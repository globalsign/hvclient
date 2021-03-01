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
	"time"
)

const (
	bodyValue     = `{"field":"value"}`
	testURL       = "http://example.com"
	tokenValue    = "tokenvalue"
	newTokenValue = "newtokenvalue"
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
			return newCertRequest(tokenValue, []byte(bodyValue))
		},
		http.MethodPost,
		"/certificates",
		bodyValue,
		false,
	},
	{
		func() apiRequest {
			return newCertRetrieveRequest(tokenValue, "1234")
		},
		http.MethodGet,
		"/certificates/1234",
		"",
		false,
	},
	{
		func() apiRequest {
			return newCertRevokeRequest(tokenValue, "1234")
		},
		http.MethodDelete,
		"/certificates/1234",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimDeleteRequest(tokenValue, "1234")
		},
		http.MethodDelete,
		"/claims/domains/1234",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimDNSRequest(tokenValue, "1234")
		},
		http.MethodPost,
		"/claims/domains/1234/dns",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimReassertRequest(tokenValue, "1234")
		},
		http.MethodPost,
		"/claims/domains/1234/reassert",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimRetrieveRequest(tokenValue, "1234")
		},
		http.MethodGet,
		"/claims/domains/1234",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimSubmitRequest(tokenValue, "donkey.com")
		},
		http.MethodPost,
		"/claims/domains/donkey.com",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimsDomainsRequest(tokenValue, 1, 20, StatusPending)
		},
		http.MethodGet,
		"/claims/domains?status=PENDING&page=1&per_page=20",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimsDomainsRequest(tokenValue, 2, 0, StatusVerified)
		},
		http.MethodGet,
		"/claims/domains?status=VERIFIED&page=2",
		"",
		false,
	},
	{
		func() apiRequest {
			return newCounterCertsIssuedRequest(tokenValue)
		},
		http.MethodGet,
		"/counters/certificates/issued",
		"",
		false,
	},
	{
		func() apiRequest {
			return newCounterCertsRevokedRequest(tokenValue)
		},
		http.MethodGet,
		"/counters/certificates/revoked",
		"",
		false,
	},
	{
		func() apiRequest {
			return newQuotaRequest(tokenValue)
		},
		http.MethodGet,
		"/quotas/issuance",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsExpiringRequest(tokenValue, 2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/expiring?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsExpiringRequest(tokenValue, 3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/expiring?page=3",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsIssuedRequest(tokenValue, 2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/issued?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsIssuedRequest(tokenValue, 3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/issued?page=3",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsRevokedRequest(tokenValue, 2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/revoked?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsRevokedRequest(tokenValue, 3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/revoked?page=3",
		"",
		false,
	},
	{
		func() apiRequest {
			return newTrustChainRequest(tokenValue)
		},
		http.MethodGet,
		"/trustchain",
		"",
		false,
	},
	{
		func() apiRequest {
			return newPolicyRequest(tokenValue)
		},
		http.MethodGet,
		"/validationpolicy",
		"",
		false,
	},
	{
		func() apiRequest {
			return newLoginRequest("the key", "the secret")
		},
		http.MethodPost,
		"/login",
		`{"api_key":"the key","api_secret":"the secret"}`,
		true,
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

func TestRequestToken(t *testing.T) {
	t.Parallel()

	for _, tc := range requestTestCases {
		var tc = tc

		if tc.notoken {
			continue
		}

		t.Run(tc.method+tc.endpoint, func(t *testing.T) {
			t.Parallel()

			var req = tc.constructor()

			checkAuthorizationHeader(t, req, tokenValue)

			req.updateToken(newTokenValue)

			checkAuthorizationHeader(t, req, newTokenValue)
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

func TestIsLoginRequest(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		req  apiRequest
		want bool
	}{
		{
			"True",
			newLoginRequest("a key", "a secret"),
			true,
		},
		{
			"False",
			newCertRetrieveRequest("some token", "some serial numer"),
			false,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := isLoginRequest(tc.req); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func checkAuthorizationHeader(t *testing.T, req apiRequest, value string) {
	t.Helper()

	var err error

	var httpReq *http.Request
	if httpReq, err = req.newHTTPRequest(testURL); err != nil {
		t.Fatalf("couldn't get HTTP request: %v", err)
	}
	defer httpReq.Body.Close()

	var expectedAuthHeader = "bearer " + value

	if len(httpReq.Header["Authorization"]) != 1 {
		t.Fatalf("got authorization header length %d, want %d", len(httpReq.Header["Authorization"]), 1)
	}

	if got := httpReq.Header["Authorization"][0]; got != expectedAuthHeader {
		t.Errorf("got authorization header value %q, want %q", got, expectedAuthHeader)
	}
}
