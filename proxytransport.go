package main

import (
	"net/http"
)

type ProxyTransport struct {
	http.RoundTripper
}

func (t *ProxyTransport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	//return t.RoundTripper.RoundTrip(req)
	resp, err = t.RoundTripper.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Header.Del("Access-Control-Allow-Origin")
	resp.Header.Del("Access-Control-Allow-Headers")
	resp.Header.Del("Content-Security-Policy")
	return resp, nil
}
