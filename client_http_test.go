package hvclient_test

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/globalsign/hvclient"
	"github.com/go-chi/chi"
)

// newMockServer returns an *httptest.Server which mocks the HVCA API /login
// endpoint.
func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	var r = chi.NewRouter()

	r.Route("/login", func(r chi.Router) {
		r.Post("/", func(w http.ResponseWriter, r *http.Request) {
			// Read and parse request body.
			var data, err = ioutil.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			var loginRequest struct {
				APIKey    string `json:"api_key"`
				APISecret string `json:"api_secret"`
			}
			err = json.Unmarshal(data, &loginRequest)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Trivially verify the expected API key.
			if loginRequest.APIKey != "mock_key" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}

			// Write a mock token.
			w.Write([]byte(`{"access_token":"mock_token"}`))
		})
	})

	return httptest.NewServer(r)
}

func TestClientHTTPTrivial(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name      string
		apiKey    string
		apiSecret string
		status    int
	}{
		{
			name:      "OK",
			apiKey:    "mock_key",
			apiSecret: "mock_secret",
			status:    http.StatusOK,
		},
		{
			name:      "WrongAPIKey",
			apiKey:    "wrong_key",
			apiSecret: "mock_secret",
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
			})
			if tc.status == http.StatusOK {
				if err != nil {
					t.Fatalf("failed to create client: %v", err)
				}
			} else {
				if apiErr, ok := err.(hvclient.APIError); !ok {
					t.Fatalf("failed to create client: %v", err)
				} else {
					if apiErr.StatusCode != tc.status {
						t.Fatalf("got status code %d, want %d", apiErr.StatusCode, tc.status)
					}
				}
			}
		})
	}
}
