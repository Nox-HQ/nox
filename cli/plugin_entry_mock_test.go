package main

import (
	"io"
	"net/http"
	"strings"
)

// mockHTTP returns a stand-in stdHTTPGet that produces an HTTP
// response with the given status and body. Used by stamper tests.
func mockHTTP(status int, body string) func(string) (*http.Response, error) {
	return func(_ string) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
		}, nil
	}
}
