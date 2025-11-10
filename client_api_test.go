package hvclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/globalsign/hvclient/internal/testhelpers"
)

// Mock response data from GlobalSign Atlas Certificate Management API.
var mockResponse string = `{
		"constructed": [
			"admin@test.com",
			"administrator@test.com",
			"webmaster@test.com",
			"hostmaster@test.com",
			"postmaster@test.com"
		],
		"dns": {
			"SOA": {
				"emails": [
					"SOAexample@test.com"
				]
			},
			"TXT": {
				"emails": [
					"TXTexample@test.com"
				]
			},
			"CAA": {
				"emails": [
					"CAAexample@test.com"
				]
			}
		}
	}`

var mockResponseWithErrors string = `{
		"constructed": [
			"admin@test.com",
			"administrator@test.com",
			"webmaster@test.com",
			"hostmaster@test.com",
			"postmaster@test.com"
		],
		"dns": {
			"SOA": {
				"emails": [
					"SOAexample@test.com"
				],
				"errors": [
					"Sample SOA error message"
				]
			},
			"TXT": {
				"emails": [
					"TXTexample@test.com"
				],
				"errors": [
					"Sample TXT error message"
				]
			},
			"CAA": {
				"emails": [
					"CAAexample@test.com"
				],
				"errors": [
					"Sample CAA error message"
				]
			}
		}
	}`

var mockResponseTXTOnly string = `{
		"constructed": [
			"admin@test.com",
			"administrator@test.com",
			"webmaster@test.com",
			"hostmaster@test.com",
			"postmaster@test.com"
		],
		"dns": {
			"SOA": {
				"emails": []
			},
			"TXT": {
				"emails": [
					"TXTexample@test.com"
				]
			},
			"CAA": {
				"emails": []
			}
		}
	}`

func TestClaimEmailRetrieve(t *testing.T) {
	var testcases = []struct {
		name        string
		apiResponse string

		expectedResponse AuthorisedEmails
	}{
		{
			name:        "Response received containing records for SOA, TXT, CAA",
			apiResponse: mockResponse,

			expectedResponse: AuthorisedEmails{
				Constructed: []string{
					"admin@test.com",
					"administrator@test.com",
					"webmaster@test.com",
					"hostmaster@test.com",
					"postmaster@test.com",
				},
				DNS: DNSResults{
					SOA: SOAResults{
						Emails: []string{
							"SOAexample@test.com",
						},
					},
					TXT: TXTResults{
						Emails: []string{
							"TXTexample@test.com",
						},
					},
					CAA: CAAResults{
						Emails: []string{
							"CAAexample@test.com",
						},
					},
				},
			},
		},
		{
			name:        "Response received containing records for SOA, TXT, CAA with errors",
			apiResponse: mockResponseWithErrors,

			expectedResponse: AuthorisedEmails{
				Constructed: []string{
					"admin@test.com",
					"administrator@test.com",
					"webmaster@test.com",
					"hostmaster@test.com",
					"postmaster@test.com",
				},
				DNS: DNSResults{
					SOA: SOAResults{
						Emails: []string{
							"SOAexample@test.com",
						},
						Errors: []string{
							"Sample SOA error message",
						},
					},
					TXT: TXTResults{
						Emails: []string{
							"TXTexample@test.com",
						},
						Errors: []string{
							"Sample TXT error message",
						},
					},
					CAA: CAAResults{
						Emails: []string{
							"CAAexample@test.com",
						},
						Errors: []string{
							"Sample CAA error message",
						},
					},
				},
			},
		},
		{
			name:        "Response received with records for TXT only",
			apiResponse: mockResponseTXTOnly,

			expectedResponse: AuthorisedEmails{
				Constructed: []string{
					"admin@test.com",
					"administrator@test.com",
					"webmaster@test.com",
					"hostmaster@test.com",
					"postmaster@test.com",
				},
				DNS: DNSResults{
					SOA: SOAResults{
						Emails: []string{},
					},
					TXT: TXTResults{
						Emails: []string{
							"TXTexample@test.com",
						},
					},
					CAA: CAAResults{
						Emails: []string{},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(tc.apiResponse))
		}))
		defer testServer.Close()

		var ctx, cancel = context.WithCancel(context.Background())
		defer cancel()

		var conf *Config = &Config{
			URL:       testServer.URL,
			APIKey:    "1234",
			APISecret: "abcdefgh",
			TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
			TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
		}

		client, err := NewClient(ctx, conf)
		if err != nil {
			t.Errorf("error creating client: %v", err)
		}

		response, err := client.ClaimEmailRetrieve(ctx, "abcd1234")
		if !reflect.DeepEqual(*response, tc.expectedResponse) {
			t.Errorf("expected response not received, got %v, want %v", *response, tc.expectedResponse)
		}
	}
}
