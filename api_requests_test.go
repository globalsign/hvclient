/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"io/ioutil"
	"net/http"
	"testing"
)

const (
	testURL = "http://example.com"
)

var requestTestCases = []struct {
	constructor func() apiRequest
	method      string
	endpoint    string
	body        string
	notoken     bool
}{
	{
		func() apiRequest {
			return newClaimDNSRequest("1234")
		},
		http.MethodPost,
		"/claims/domains/1234/dns",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimReassertRequest("1234")
		},
		http.MethodPost,
		"/claims/domains/1234/reassert",
		"",
		false,
	},
}

func TestRequestNewHTTPRequest(t *testing.T) {
	t.Parallel()

	for _, tc := range requestTestCases {
		var tc = tc

		t.Run(tc.method+tc.endpoint, func(t *testing.T) {
			t.Parallel()

			var err error

			var httpReq *http.Request
			if httpReq, err = tc.constructor().newHTTPRequest(testURL); err != nil {
				t.Fatalf("couldn't get HTTP request: %v", err)
			}
			defer httpReq.Body.Close()

			if got := httpReq.Method; got != tc.method {
				t.Errorf("got method %s, want %s", got, tc.method)
			}

			if got := httpReq.URL.String(); got != testURL+tc.endpoint {
				t.Errorf("got URL %s, want %s", got, testURL+tc.endpoint)
			}
		})
	}
}

func TestRequestReadBody(t *testing.T) {
	t.Parallel()

	for _, tc := range requestTestCases {
		var tc = tc

		t.Run(tc.method+tc.endpoint, func(t *testing.T) {
			t.Parallel()

			var err error

			var httpReq *http.Request
			if httpReq, err = tc.constructor().newHTTPRequest(testURL); err != nil {
				t.Fatalf("couldn't get HTTP request: %v", err)
			}
			defer httpReq.Body.Close()

			var data []byte
			if data, err = ioutil.ReadAll(httpReq.Body); err != nil {
				t.Fatalf("couldn't read HTTP request body: %v", err)
			}

			if string(data) != tc.body {
				t.Errorf("got %s, want %s", string(data), tc.body)
			}
		})
	}
}

func TestRequestNewHTTPRequestBadURL(t *testing.T) {
	t.Parallel()

	for _, tc := range requestTestCases {
		var tc = tc

		t.Run(tc.method+tc.endpoint, func(t *testing.T) {
			t.Parallel()

			if _, err := tc.constructor().newHTTPRequest("$" + testURL); err == nil {
				t.Errorf("unexpectedly got HTTP request")
			}
		})
	}
}
