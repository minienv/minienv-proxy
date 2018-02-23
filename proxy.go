package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/gorilla/websocket"
)

var (
	// DefaultUpgrader specifies the parameters for upgrading an HTTP
	// connection to a WebSocket connection.
	DefaultUpgrader = &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}
	// DefaultDialer is a dialer with all fields set to the default zero values.
	DefaultDialer = websocket.DefaultDialer
	AllowOrigin = os.Getenv("MINIENV_ALLOW_ORIGIN")
)

type ReverseProxy struct {
	ReverseHttpProxy      *httputil.ReverseProxy // http requests
	ReverseWebsocketProxy *ReverseWebsocketProxy // websocket requests
}

type ReverseWebsocketProxy struct {
	TargetHost string
	Upgrader   *websocket.Upgrader
	Dialer     *websocket.Dialer
}

// NewProxy returns a new Websocket reverse proxy that rewrites the
// URL's to the scheme, host and base path provider in target.
func NewReverseProxy(targetHost string) *ReverseProxy {
	proxy := &ReverseProxy{}
	proxy.ReverseHttpProxy = NewReverseHttpProxy(targetHost)
	proxy.ReverseWebsocketProxy = NewReverseWebsocketProxy(targetHost)
	return proxy
}

// ServeHTTP implements the http.Handler that proxies WebSocket connections.
func (p *ReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Add CORS headers
	rw.Header().Set("Access-Control-Allow-Origin", AllowOrigin)
	rw.Header().Set("Access-Control-Allow-Headers", "X-Requested-With")
	// Route to websocket or http proxy
	if isWebsocket(req) {
		p.ReverseWebsocketProxy.ServeHTTP(rw, req)
	} else {
		p.ReverseHttpProxy.ServeHTTP(rw, req)
	}
}

func isWebsocket(req *http.Request) bool {
	if strings.Join(req.Header["Upgrade"], "") == "websocket" {
		return true
	} else {
		return false
	}
}

func NewReverseHttpProxy(targetHost string) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		hostParts := strings.Split(req.Host, ".")
		if len(hostParts) < 2 {
			req.URL.Host = req.Host
		} else {
			targetPort := hostParts[0]
			req.URL.Host = targetHost + ":" + targetPort
		}
		req.URL.Scheme = "http"
		req.Host = req.URL.Host
	}
	return &httputil.ReverseProxy{Director: director, Transport: &ProxyTransport{RoundTripper: http.DefaultTransport}}

}

func NewReverseWebsocketProxy(targetHost string) *ReverseWebsocketProxy {
	return &ReverseWebsocketProxy{TargetHost: targetHost}
}

func (p *ReverseWebsocketProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// generate backend URL
	backendURL := &url.URL{}
	backendURL.Scheme = "ws"
	hostParts := strings.Split(req.Host, ".")
	if len(hostParts) < 2 {
		backendURL.Host = req.Host
	} else {
		targetPort := hostParts[0]
		backendURL.Host = p.TargetHost + ":" + targetPort
	}
	backendURL.Path = req.URL.Path
	backendURL.RawQuery = req.URL.RawQuery

	dialer := p.Dialer
	if p.Dialer == nil {
		dialer = DefaultDialer
	}

	// Pass headers from the incoming request to the dialer to forward them to
	// the final destinations.
	requestHeader := http.Header{}
	if origin := req.Header.Get("Origin"); origin != "" {
		requestHeader.Add("Origin", origin)
	}
	for _, prot := range req.Header[http.CanonicalHeaderKey("Sec-WebSocket-Protocol")] {
		requestHeader.Add("Sec-WebSocket-Protocol", prot)
	}
	for _, cookie := range req.Header[http.CanonicalHeaderKey("Cookie")] {
		requestHeader.Add("Cookie", cookie)
	}

	// Pass X-Forwarded-For headers too, code below is a part of
	// httputil.ReverseProxy. See http://en.wikipedia.org/wiki/X-Forwarded-For
	// for more information
	// TODO: use RFC7239 http://tools.ietf.org/html/rfc7239
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		// If we aren't the first proxy retain prior
		// X-Forwarded-For information as a comma+space
		// separated list and fold multiple headers into one.
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		requestHeader.Set("X-Forwarded-For", clientIP)
	}

	// Set the originating protocol of the incoming HTTP request. The SSL might
	// be terminated on our site and because we doing proxy adding this would
	// be helpful for applications on the backend.
	requestHeader.Set("X-Forwarded-Proto", "http")
	if req.TLS != nil {
		requestHeader.Set("X-Forwarded-Proto", "https")
	}

	// Enable the director to copy any additional headers it desires for
	// forwarding to the remote server.
	//if p.Director != nil {
	//	p.Director(req, requestHeader)
	//}

	// Connect to the backend URL, also pass the headers we get from the requst
	// together with the Forwarded headers we prepared above.
	// TODO: support multiplexing on the same backend connection instead of
	// opening a new TCP connection time for each request. This should be
	// optional:
	// http://tools.ietf.org/html/draft-ietf-hybi-websocket-multiplexing-01
	log.Printf("Dialing backend @ %s\n", backendURL.String())
	connBackend, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	log.Printf("Response received from backend...\n")
	if err != nil {
		log.Printf("websocketproxy: couldn't dial to remote backend url %s\n", err)
		if resp != nil {
			log.Printf("websocketproxy: resp.status = %s\n", resp.Status)
			w.WriteHeader(resp.StatusCode)
		}
		return
	}
	log.Printf("Closing backend...\n")
	defer connBackend.Close()

	log.Printf("Creating upgrader...\n")
	upgrader := p.Upgrader
	if p.Upgrader == nil {
		upgrader = DefaultUpgrader
	}

	// Only pass those headers to the upgrader.
	log.Printf("Setting upgrade headers...\n")
	upgradeHeader := http.Header{}
	if hdr := resp.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := resp.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}

	// Now upgrade the existing incoming request to a WebSocket connection.
	// Also pass the header that we gathered from the Dial handshake.
	log.Printf("Upgrading connection...\n")
	connPub, err := upgrader.Upgrade(w, req, upgradeHeader)
	if err != nil {
		log.Printf("websocketproxy: couldn't upgrade %s\n", err)
		return
	}
	defer connPub.Close()

	log.Printf("Creating channel...\n")
	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}

	// Start our proxy now, everything is ready...
	log.Printf("Starting proxy...\n")
	go cp(connBackend.UnderlyingConn(), connPub.UnderlyingConn())
	go cp(connPub.UnderlyingConn(), connBackend.UnderlyingConn())
	<-errc
}
