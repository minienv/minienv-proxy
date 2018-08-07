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
	if IsWebsocket(req) {
		p.ReverseWebsocketProxy.ServeHTTP(rw, req)
	} else {
		p.ReverseHttpProxy.ServeHTTP(rw, req)
	}
}

func IsWebsocket(req *http.Request) bool {
	if strings.Join(req.Header["Upgrade"], "") == "websocket" {
		return true
	} else {
		return false
	}
}

func CheckWebsocketOrigin(r *http.Request) bool {
	return true
}

func NewReverseHttpProxy(target string) *httputil.ReverseProxy {
	director := func(req *http.Request) {
		targetHost := target
		targetPort := ""
		targetProxyPort := ""
		if target == "" {
			// when target is empty we expect the target to be in the url/redis store
			// we expect the host to be in the form of one of the following:
			// 1. sessionId-targetPort.minienvHost - we get the target environment from the redis store using sessionId
			// 2. sessionId-targetPort-targetProxyPort.minienvHost - in this case the target is a proxy inside the environment
			// below we extract this to [sessionId,targetPort,targetProxyPort]
			hostParts := strings.Split(strings.Split(req.Host, ".")[0], "-")
			if len(hostParts) >= 2 {
				sessionId := hostParts[0]
				if sessionStore != nil {
					session, _ := sessionStore.getSession(sessionId)
					if session != nil {
						service := "env-" + session.EnvId + "-service"
						targetHost = service + ".minienv.svc.cluster.local"
						targetPort = hostParts[1]
						if len(hostParts) > 2 {
							// hostParts[2] should be "targetProxyPort.minienvHost"
							targetProxyPort = strings.Split(hostParts[2], ".")[0]
						}
					}
				}
			}
		}
		// if the targetPort is not set try and get it from the header
		if targetPort == "" {
			targetPort = req.Header.Get("Minienv-Proxy-Port")
		}
		targetPortStr := ""
		if targetPort != "" {
			targetPortStr = ":" + targetPort
		}
		req.Host = targetHost
		req.URL.Host = targetHost + targetPortStr
		req.URL.Scheme = "http"
		if targetProxyPort != "" {
			req.Header.Set("Minienv-Proxy-Port", targetProxyPort)
		}
		//log.Printf("Proxying http connection to %s\n", req.URL.String())
	}
	return &httputil.ReverseProxy{Director: director, Transport: &ProxyTransport{RoundTripper: http.DefaultTransport}}

}

func NewReverseWebsocketProxy(targetHost string) *ReverseWebsocketProxy {
	return &ReverseWebsocketProxy{TargetHost: targetHost}
}

func (p *ReverseWebsocketProxy) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	targetHost := p.TargetHost
	targetPort := ""
	targetProxyPort := ""
	targetOrigin := req.Header.Get("Origin")
	if targetHost == "" {
		// when target is empty we expect the target to be in the url/redis store
		// we expect the host to be in the form of one of the following:
		// 1. sessionId-targetPort.minienvHost - we get the target environment from the redis store using sessionId
		// 2. sessionId-targetPort-targetProxyPort.minienvHost - in this case the target is a proxy inside the environment
		// below we extract this to [sessionId,targetPort,targetProxyPort]
		urlParts := strings.SplitN(req.Host, ".", 2)
		if len(urlParts) == 2 {
			targetOrigin = AllowOrigin
			hostParts := strings.Split(urlParts[0], "-")
			if len(hostParts) >= 2 {
				sessionId := hostParts[0]
				if sessionStore != nil {
					session, _ := sessionStore.getSession(sessionId)
					if session != nil {
						service := "env-" + session.EnvId + "-service"
						targetHost = service + ".minienv.svc.cluster.local"
						targetPort = hostParts[1]
						if len(hostParts) > 2 {
							targetProxyPort = hostParts[2]
						}
					}
				}
			}
		}
	}
	// if the targetPort is not set try and get it from the header
	if targetPort == "" {
		targetPort = req.Header.Get("Minienv-Proxy-Port")
	}
	targetPortStr := ""
	if targetPort != "" {
		targetPortStr = ":" + targetPort
	}
	// generate backend URL
	backendURL := &url.URL{}
	backendURL.Host = targetHost + targetPortStr
	backendURL.Scheme = "ws"
	backendURL.Path = req.URL.Path
	backendURL.RawQuery = req.URL.RawQuery

	dialer := p.Dialer
	if p.Dialer == nil {
		dialer = DefaultDialer
	}

	// set headers
	requestHeader := http.Header{}
	if targetProxyPort != "" {
		requestHeader.Set("Minienv-Proxy-Port", targetProxyPort)
	}
	if targetOrigin != "" {
		requestHeader.Add("Origin", targetOrigin)
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

	requestHeader.Set("X-Forwarded-Proto", "https")

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
	log.Printf("Proxying websocket connection to %s\n", backendURL.String())
	connBackend, resp, err := dialer.Dial(backendURL.String(), requestHeader)
	if err != nil {
		log.Printf("websocketproxy: couldn't dial to remote backend url %s\n", err)
		if resp != nil {
			log.Printf("websocketproxy: resp.status = %s\n", resp.Status)
			w.WriteHeader(resp.StatusCode)
		}
		return
	}
	defer connBackend.Close()

	upgrader := p.Upgrader
	if p.Upgrader == nil {
		upgrader = DefaultUpgrader
	}
	upgrader.CheckOrigin = CheckWebsocketOrigin

	// Only pass those headers to the upgrader.
	upgradeHeader := http.Header{}
	if hdr := resp.Header.Get("Sec-Websocket-Protocol"); hdr != "" {
		upgradeHeader.Set("Sec-Websocket-Protocol", hdr)
	}
	if hdr := resp.Header.Get("Set-Cookie"); hdr != "" {
		upgradeHeader.Set("Set-Cookie", hdr)
	}

	// Now upgrade the existing incoming request to a WebSocket connection.
	// Also pass the header that we gathered from the Dial handshake.
	connPub, err := upgrader.Upgrade(w, req, upgradeHeader)
	if err != nil {
		log.Printf("websocketproxy: couldn't upgrade %s\n", err)
		return
	}
	defer connPub.Close()

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}

	// Start our proxy now, everything is ready...
	go cp(connBackend.UnderlyingConn(), connPub.UnderlyingConn())
	go cp(connPub.UnderlyingConn(), connBackend.UnderlyingConn())
	<-errc
}
