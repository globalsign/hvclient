/*
Copyright (c) 2019-2021 GMO GlobalSign Pte. Ltd.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package hvclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/httputils"
	"github.com/go-chi/chi"
)

const (
	mockQuota             = 42
	sslClientSerialHeader = "X-SSL-Client-Serial"
)

// newMockServer returns an *httptest.Server which mocks the HVCA API /login
// endpoint.
func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	var r = chi.NewRouter()

	r.Route("/login", func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			var err = httputils.VerifyRequestContentType(r, httputils.ContentTypeJSON)
			if err != nil {
				writeMockError(w, http.StatusUnsupportedMediaType)
				return
			}

			// Read and parse request body.
			var data []byte
			data, err = ioutil.ReadAll(r.Body)
			if err != nil {
				writeMockError(w, http.StatusInternalServerError)
				return
			}

			var loginRequest struct {
				APIKey    string `json:"api_key"`
				APISecret string `json:"api_secret"`
			}
			err = json.Unmarshal(data, &loginRequest)
			if err != nil {
				writeMockError(w, http.StatusBadRequest)
				return
			}

			// Trivially verify the expected SSL client serial header.
			var serial = r.Header.Get(sslClientSerialHeader)
			if serial != "mock_serial" {
				writeMockError(w, http.StatusUnauthorized)
				return
			}

			// Trivially verify the expected API key.
			if loginRequest.APIKey != "mock_key" {
				writeMockError(w, http.StatusUnauthorized)
				return
			}

			// Write a mock token.
			w.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeJSON)
			_, _ = w.Write([]byte(`{"access_token":"mock_token"}`))
		})
	})

	r.Route("/quotas", func(r chi.Router) {
		r.Route("/issuance", func(r chi.Router) {
			r.Get("/", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeJSON)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"value":%d}`, mockQuota)))
			})
		})
	})

	return httptest.NewServer(r)
}

func writeMockError(w http.ResponseWriter, status int) {
	w.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeProblemJSON)
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"description":"%s"}`, http.StatusText(status))))
}

func TestClientLocalNew(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name      string
		apiKey    string
		apiSecret string
		serial    string
		status    int
	}{
		{
			name:      "OK",
			apiKey:    "mock_key",
			apiSecret: "mock_secret",
			serial:    "mock_serial",
			status:    http.StatusOK,
		},
		{
			name:      "WrongAPIKey",
			apiKey:    "wrong_key",
			apiSecret: "mock_secret",
			serial:    "mock_serial",
			status:    http.StatusUnauthorized,
		},
		{
			name:      "WrongSerial",
			apiKey:    "mock_key",
			apiSecret: "mock_secret",
			serial:    "wrong_serial",
			status:    http.StatusUnauthorized,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var testServer = newMockServer(t)
			defer testServer.Close()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			var _, err = hvclient.NewClient(ctx, &hvclient.Config{
				URL:       testServer.URL,
				APIKey:    tc.apiKey,
				APISecret: tc.apiSecret,
				ExtraHeaders: map[string]string{
					sslClientSerialHeader: tc.serial,
				},
			})
			if tc.status == http.StatusOK {
				if err != nil {
					t.Fatalf("failed to create client: %v", err)
				}
			} else {
				var apiErr hvclient.APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("failed to create client: %v", err)
				}

				if apiErr.StatusCode != tc.status {
					t.Fatalf("got status code %d, want %d", apiErr.StatusCode, tc.status)
				}
			}
		})
	}
}

func TestClientLocalQuotasIssuance(t *testing.T) {
	t.Parallel()

	var testServer = newMockServer(t)
	defer testServer.Close()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var client, err = hvclient.NewClient(ctx, &hvclient.Config{
		URL:       testServer.URL,
		APIKey:    "mock_key",
		APISecret: "mock_secret",
		ExtraHeaders: map[string]string{
			sslClientSerialHeader: "mock_serial",
		},
	})
	if err != nil {
		t.Fatalf("failed to create new client: %v", err)
	}

	var got int64
	got, err = client.QuotaIssuance(ctx)
	if err != nil {
		t.Fatalf("failed to get issuance quota: %v", err)
	}

	if got != mockQuota {
		t.Fatalf("got quota %d, want %d", got, mockQuota)
	}
}
