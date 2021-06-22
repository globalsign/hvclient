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
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/httputils"
	"github.com/globalsign/hvclient/internal/pki"
	"github.com/go-chi/chi"
)

// Note: mocking up the entire HVCA API service seems a little extreme, and
// can result in unrealistic testing. However: (1) obtaining a suitable test
// HVCA account is not a trivial process, and requiring one to perform basic
// regression tests would be an onerous requirement, particularly for third
// party contributors; (2) it is not feasible to obtain some responses from
// the live HVCA service under automated test conditions (for example, an
// affirmative response that control over a domain has been successfully
// verified); and (3) it can be difficult to induce appropriate error
// conditions from the live HVCA service. Accordingly, to provide contributors
// with a way to perform regression tests in the absence of an HVCA test
// account, and to allow more code paths to be tested, we do mock up the HVCA
// service in addition to providing a suite of integration tests for use with
// the live service.

type mockCertInfo struct {
	PEM       string `json:"certificate"`
	Status    string `json:"status"`
	UpdatedAt int64  `json:"updated_at"`
}

type mockCertMeta struct {
	SerialNumber string `json:"serial_number"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
}

type mockCounter struct {
	Value int `json:"value"`
}

type mockError struct {
	Description string `json:"description"`
}

type mockLoginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

type mockLoginResponse struct {
	Token string `json:"access_token"`
}

const (
	mockAPIKey            = "mock_api_key"
	mockAPISecret         = "mock_api_secret"
	mockCertSerial        = "741DAF9EC2D5F7DC"
	mockCounterIssued     = 72
	mockCounterRevoked    = 14
	mockQuotaIssuance     = 42
	mockSSLClientSerial   = "0123456789"
	mockToken             = "mock_token"
	sslClientSerialHeader = "X-SSL-Client-Serial"
	triggerError          = "triggererror"
)

var (
	mockBigIntNotFound = big.NewInt(999999)
	mockCert           = mustReadCertFromFile("testdata/test_cert.pem")
	mockDateUpdated    = time.Date(2021, 6, 18, 16, 29, 51, 0, time.UTC)
	mockPolicy         = hvclient.Policy{
		Validity: &hvclient.ValidityPolicy{
			SecondsMin:            3600,
			SecondsMax:            7776000,
			NotBeforeNegativeSkew: 120,
			NotBeforePositiveSkew: 3600,
		},
		SubjectDN: &hvclient.SubjectDNPolicy{
			CommonName: &hvclient.StringPolicy{
				Presence: hvclient.Required,
				Format:   `^[a-zA-Z]*$`,
			},
		},
		PublicKey: &hvclient.PublicKeyPolicy{
			KeyType:        hvclient.ECDSA,
			AllowedLengths: []int{256, 384, 521},
			KeyFormat:      hvclient.PKCS10,
		},
		PublicKeySignature: hvclient.Required,
	}
	mockStatsExpiringData = []mockCertMeta{
		{
			SerialNumber: "748BDAE7199CC246",
			NotBefore:    time.Date(2021, 7, 12, 16, 29, 51, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 10, 10, 16, 29, 51, 0, time.UTC).Unix(),
		},
		{
			SerialNumber: "DEADBEEF44274823",
			NotBefore:    time.Date(2021, 7, 14, 12, 5, 37, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 10, 12, 12, 5, 37, 0, time.UTC).Unix(),
		},
		{
			SerialNumber: "AA9915DC78BB21FF",
			NotBefore:    time.Date(2021, 7, 14, 17, 59, 8, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 10, 12, 17, 59, 8, 0, time.UTC).Unix(),
		},
		{
			SerialNumber: "32897DA7B113DAB6",
			NotBefore:    time.Date(2021, 7, 14, 21, 11, 43, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 10, 12, 21, 11, 43, 0, time.UTC).Unix(),
		},
	}
	mockStatsIssuedData = []mockCertMeta{
		{
			SerialNumber: "741DAF9EC2D5F7DC",
			NotBefore:    time.Date(2021, 6, 18, 16, 29, 51, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 9, 16, 16, 29, 51, 0, time.UTC).Unix(),
		},
		{
			SerialNumber: "87BC1DC5524A2B18",
			NotBefore:    time.Date(2021, 6, 19, 12, 5, 37, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 9, 17, 12, 5, 37, 0, time.UTC).Unix(),
		},
		{
			SerialNumber: "F488BCE14A56CD2A",
			NotBefore:    time.Date(2021, 6, 19, 17, 59, 8, 0, time.UTC).Unix(),
			NotAfter:     time.Date(2021, 9, 17, 17, 59, 8, 0, time.UTC).Unix(),
		},
	}
	mockTrustChainCerts = []*x509.Certificate{
		mustReadCertFromFile("testdata/test_ica_cert.pem"),
		mustReadCertFromFile("testdata/test_root_cert.pem"),
	}
)

func newMockClient(t *testing.T) (*hvclient.Client, func()) {
	t.Helper()

	var server = newMockServer(t)

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var client, err = hvclient.NewClient(ctx, &hvclient.Config{
		URL:       server.URL,
		APIKey:    mockAPIKey,
		APISecret: mockAPISecret,
		ExtraHeaders: map[string]string{
			sslClientSerialHeader: mockSSLClientSerial,
		},
	})
	if err != nil {
		server.Close()
		t.Fatalf("failed to create new client: %v", err)
	}

	return client, server.Close
}

// newMockServer returns an *httptest.Server which mocks the HVCA API.
func newMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	var r = chi.NewRouter()

	r.Route("/certificates", func(r chi.Router) {
		r.Post("/", mockCertificatesRequest)
		r.Route("/{serial}", func(r chi.Router) {
			r.Get("/", mockCertificatesRetrieve)
			r.Delete("/", mockCertificatesRevoke)
		})
	})

	r.Route("/claims", func(r chi.Router) {
		r.Route("/domains", func(r chi.Router) {
			r.Get("/", mockNotImplemented)
			r.Post("/{domain}", mockNotImplemented)
			r.Route("/{claim}", func(r chi.Router) {
				r.Get("/", mockNotImplemented)
				r.Delete("/", mockNotImplemented)
				r.Route("/dns", func(r chi.Router) {
					r.Post("/", mockNotImplemented)
				})
				r.Route("/http", func(r chi.Router) {
					r.Post("/", mockNotImplemented)
				})
				r.Route("/email", func(r chi.Router) {
					r.Get("/", mockNotImplemented)
					r.Post("/", mockNotImplemented)
				})
				r.Route("/reassert", func(r chi.Router) {
					r.Post("/", mockNotImplemented)
				})
			})
		})
	})

	r.Route("/counters", func(r chi.Router) {
		r.Route("/certificates", func(r chi.Router) {
			r.Route("/issued", func(r chi.Router) { r.Get("/", mockCountersIssued) })
			r.Route("/revoked", func(r chi.Router) { r.Get("/", mockCountersRevoked) })
		})
	})

	r.Route("/login", func(r chi.Router) { r.Post("/", mockLogin) })

	r.Route("/quotas", func(r chi.Router) {
		r.Route("/issuance", func(r chi.Router) { r.Get("/", mockQuotasIssuance) })
	})

	r.Route("/stats", func(r chi.Router) {
		r.Route("/expiring", func(r chi.Router) { r.Get("/", mockStatsExpiring) })
		r.Route("/issued", func(r chi.Router) { r.Get("/", mockStatsIssued) })
		r.Route("/revoked", func(r chi.Router) { r.Get("/", mockStatsRevoked) })
	})

	r.Route("/trustchain", func(r chi.Router) { r.Get("/", mockTrustChain) })

	r.Route("/validationpolicy", func(r chi.Router) { r.Get("/", mockValidationPolicy) })

	return httptest.NewServer(r)
}

// mockCertificatesRequest mocks a POST /certificates operation.
func mockCertificatesRequest(w http.ResponseWriter, r *http.Request) {
	var body hvclient.Request
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		return
	}

	// Trigger 422 for specific common name.
	if body.Subject != nil && body.Subject.CommonName == triggerError {
		mockWriteError(w, http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("http://local/certificates/%X", mockCert.SerialNumber))
	mockWriteResponse(w, http.StatusCreated, nil)
}

// mockCertificatesRetrieve mocks a GET /certificates operation.
func mockCertificatesRetrieve(w http.ResponseWriter, r *http.Request) {
	// Extract serial number from URL.
	var sn, ok = big.NewInt(0).SetString(chi.URLParam(r, "serial"), 16)
	if !ok {
		mockWriteError(w, http.StatusUnprocessableEntity)
		return
	}

	// Trigger 404 for specific serial number.
	if sn.Cmp(mockBigIntNotFound) == 0 {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	mockWriteResponse(w, http.StatusOK, mockCertInfo{
		PEM:       pki.CertToPEMString(mockCert),
		Status:    "ISSUED",
		UpdatedAt: mockDateUpdated.Unix(),
	})
}

// mockCertificatesRevoke mocks a DELETE /certificates operation.
func mockCertificatesRevoke(w http.ResponseWriter, r *http.Request) {
	// Extract serial number from URL.
	var sn, ok = big.NewInt(0).SetString(chi.URLParam(r, "serial"), 16)
	if !ok {
		mockWriteError(w, http.StatusUnprocessableEntity)
		return
	}

	// Return 404 for specific serial number.
	if sn.Cmp(mockBigIntNotFound) == 0 {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	mockWriteResponse(w, http.StatusNoContent, nil)
}

// mockCountersIssued mocks a GET /counters/certificates/issued operation.
func mockCountersIssued(w http.ResponseWriter, r *http.Request) {
	mockWriteResponse(w, http.StatusOK, mockCounter{Value: mockCounterIssued})
}

// mockCountersIssued mocks a GET /counters/certificates/revoked operation.
func mockCountersRevoked(w http.ResponseWriter, r *http.Request) {
	mockWriteResponse(w, http.StatusOK, mockCounter{Value: mockCounterRevoked})
}

// mockLogin mocks a POST /login operation.
func mockLogin(w http.ResponseWriter, r *http.Request) {
	var body mockLoginRequest
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		return
	}

	// Trivially verify the expected SSL client serial header.
	var serial = r.Header.Get(sslClientSerialHeader)
	if serial != mockSSLClientSerial {
		mockWriteError(w, http.StatusUnauthorized)
		return
	}

	// Trivially verify the expected API key.
	if body.APIKey != mockAPIKey {
		mockWriteError(w, http.StatusUnauthorized)
		return
	}

	mockWriteResponse(w, http.StatusOK, mockLoginResponse{Token: mockToken})
}

// mockValidationPolicy mocks a GET /validationpolicy operation.
func mockValidationPolicy(w http.ResponseWriter, r *http.Request) {
	mockWriteResponse(w, http.StatusOK, mockPolicy)
}

// mockQuotasIssuance mocks a GET /quotas/issuance operation.
func mockQuotasIssuance(w http.ResponseWriter, r *http.Request) {
	mockWriteResponse(w, http.StatusOK, mockCounter{Value: mockQuotaIssuance})
}

// mockStatsExpiring mocks a GET /stats/expiring operation.
func mockStatsExpiring(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Total-Count", fmt.Sprintf("%d", len(mockStatsExpiringData)))
	mockWriteResponse(w, http.StatusOK, mockStatsExpiringData)
}

// mockStatsIssued mocks a GET /stats/issued operation.
func mockStatsIssued(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Total-Count", fmt.Sprintf("%d", len(mockStatsIssuedData)))
	mockWriteResponse(w, http.StatusOK, mockStatsIssuedData)
}

// mockStatsRevoked mocks a GET /stats/revoked operation.
func mockStatsRevoked(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Total-Count", fmt.Sprintf("%d", len(mockStatsIssuedData[1:])))
	mockWriteResponse(w, http.StatusOK, mockStatsIssuedData[1:])
}

// mockTrustChain mocks a GET /trustchain operation.
func mockTrustChain(w http.ResponseWriter, r *http.Request) {
	var chain = make([]string, len(mockTrustChainCerts))
	for i := range chain {
		chain[i] = pki.CertToPEMString(mockTrustChainCerts[i])
	}

	mockWriteResponse(w, http.StatusOK, chain)
}

// mockNotImplemented is a stub handler that writes a 501 not implemented
// response.
func mockNotImplemented(w http.ResponseWriter, r *http.Request) {
	mockWriteResponse(w, http.StatusNotImplemented, nil)
}

// mockUnmarshalBody unmarshals an HTTP request body, and writes an appropriate
// HTTP error response on failure.
func mockUnmarshalBody(w http.ResponseWriter, r *http.Request, out interface{}) error {
	var err = httputils.VerifyRequestContentType(r, httputils.ContentTypeJSON)
	if err != nil {
		mockWriteError(w, http.StatusUnsupportedMediaType)
		return err
	}

	// Read and parse request body.
	var data []byte
	data, err = ioutil.ReadAll(r.Body)
	if err != nil {
		mockWriteError(w, http.StatusInternalServerError)
		return err
	}

	err = json.Unmarshal(data, &out)
	if err != nil {
		mockWriteError(w, http.StatusBadRequest)
		return err
	}

	return nil
}

// mockWriteError writes an error HTTP response.
func mockWriteError(w http.ResponseWriter, status int) {
	var data, err = json.Marshal(mockError{Description: http.StatusText(status)})
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	} else {
		w.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeProblemJSON)
		w.WriteHeader(status)
		_, _ = w.Write(data)
	}
}

// mockWriteResponse writes an HTTP response. If obj is not nil, it will be
// marshalled to JSON and used as the response body.
func mockWriteResponse(w http.ResponseWriter, status int, obj interface{}) {
	if obj != nil {
		var data, err = json.Marshal(obj)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		}

		w.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeJSON)
		w.WriteHeader(status)
		_, _ = w.Write(data)
	} else {
		w.WriteHeader(status)
	}
}

func mustReadCertFromFile(filename string) *x509.Certificate {
	var cert, err = pki.CertFromFile(filename)
	if err != nil {
		panic(fmt.Sprintf("failed to open certificate at path %s: %v", filename, err))
	}

	return cert
}
