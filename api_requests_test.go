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
			return newClaimDeleteRequest("1234")
		},
		http.MethodDelete,
		"/claims/domains/1234",
		"",
		false,
	},
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
	{
		func() apiRequest {
			return newClaimRetrieveRequest("1234")
		},
		http.MethodGet,
		"/claims/domains/1234",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimSubmitRequest("donkey.com")
		},
		http.MethodPost,
		"/claims/domains/donkey.com",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimsDomainsRequest(1, 20, StatusPending)
		},
		http.MethodGet,
		"/claims/domains?status=PENDING&page=1&per_page=20",
		"",
		false,
	},
	{
		func() apiRequest {
			return newClaimsDomainsRequest(2, 0, StatusVerified)
		},
		http.MethodGet,
		"/claims/domains?status=VERIFIED&page=2",
		"",
		false,
	},
	{
		func() apiRequest {
			return newCounterCertsIssuedRequest()
		},
		http.MethodGet,
		"/counters/certificates/issued",
		"",
		false,
	},
	{
		func() apiRequest {
			return newCounterCertsRevokedRequest()
		},
		http.MethodGet,
		"/counters/certificates/revoked",
		"",
		false,
	},
	{
		func() apiRequest {
			return newQuotaRequest()
		},
		http.MethodGet,
		"/quotas/issuance",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsExpiringRequest(2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/expiring?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsExpiringRequest(3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/expiring?page=3",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsIssuedRequest(2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/issued?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsIssuedRequest(3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/issued?page=3",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsRevokedRequest(2, 20,
				time.Unix(1550264300, 0), time.Unix(1550374300, 0))
		},
		http.MethodGet,
		"/stats/revoked?page=2&per_page=20&from=1550264300&to=1550374300",
		"",
		false,
	},
	{
		func() apiRequest {
			return newStatsRevokedRequest(3, 0,
				time.Time{}, time.Time{})
		},
		http.MethodGet,
		"/stats/revoked?page=3",
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
