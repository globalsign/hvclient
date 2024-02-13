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

	"github.com/go-chi/chi"
	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/httputils"
	"github.com/globalsign/hvclient/internal/pki"
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

type mockClaim struct {
	ID        string              `json:"id"`
	Status    string              `json:"status"`
	Domain    string              `json:"domain"`
	CreatedAt int64               `json:"created_at"`
	ExpiresAt int64               `json:"expires_at"`
	AssertBy  int64               `json:"assert_by"`
	Log       []mockClaimLogEntry `json:"log"`
}

type mockClaimAssertionInfo struct {
	Token    string `json:"token"`
	AssertBy int64  `json:"assert_by"`
	ID       string `json:"id"`
}

type mockClaimLogEntry struct {
	Status      string `json:"status"`
	Description string `json:"description"`
	TimeStamp   int64  `json:"timestamp"`
}

type mockCounter struct {
	Value int `json:"value"`
}

type mockDNSRequest struct {
	AuthorizationDomain string `json:"authorization_domain"`
}

type mockHTTPRequest struct {
	AuthorizationDomain string `json:"authorization_domain,omitempty"`
	Scheme              string `json:"scheme"`
}

type mockEmailRequest struct {
	Email string `json:"email_address"`
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

type mockAuthorisedEmails struct {
	Constructed []string       `json:"constructed"`
	DNS         mockDNSResults `json:"DNS"`
}

type mockDNSResults struct {
	SOA mockSOAResults `json:"SOA"`
}

type mockSOAResults struct {
	Emails []string `json:"emails,omitempty"`
}

type mockRevocationBody struct {
	RevocationReason string `json:"revocation_reason"`
	RevocationTime   int64  `json:"revocation_time"`
}

const (
	mockAPIKey              = "mock_api_key"
	mockAPISecret           = "mock_api_secret"
	mockCertSerial          = "741DAF9EC2D5F7DC"
	mockCertSerialLocation  = "http://local/certificates/741DAF9EC2D5F7DC"
	mockCounterIssued       = 72
	mockCounterRevoked      = 14
	mockClaimDomainVerified = "verified.com."
	mockClaimEmail          = "spock@enterprise.org"
	mockClaimID             = "113FED08"
	mockClaimToken          = "mock_claim_token"
	mockQuotaIssuance       = 42
	mockSSLClientSerial     = "0123456789"
	mockToken               = "mock_token"
	sslClientSerialHeader   = "X-SSL-Client-Serial"
	triggerError            = "triggererror"
)

var (
	mockBigIntNotFound = big.NewInt(999999)
	mockCert           = mustReadCertFromFile("testdata/test_cert.pem")
	mockClaimAssert    = mockClaimAssertionInfo{
		Token:    mockClaimToken,
		AssertBy: mockDateAssertBy.Unix(),
		ID:       mockClaimID,
	}
	mockClaimsEntries = []mockClaim{
		{
			ID:        mockClaimID,
			Status:    "VERIFIED",
			Domain:    "fake.com.",
			CreatedAt: mockDateCreated.Unix(),
			ExpiresAt: mockDateExpiresAt.Unix(),
			AssertBy:  mockDateAssertBy.Unix(),
			Log: []mockClaimLogEntry{
				{
					Status:      "SUCCESS",
					Description: "domain claim verified",
					TimeStamp:   mockDateUpdated.Unix(),
				},
			},
		},
		{
			ID:        "pending1",
			Status:    "PENDING",
			Domain:    "pending1.com.",
			CreatedAt: mockDateCreated.Unix(),
			ExpiresAt: mockDateExpiresAt.Unix(),
			AssertBy:  mockDateAssertBy.Unix(),
			Log: []mockClaimLogEntry{
				{
					Status:      "ERROR",
					Description: "error verifying domain claim",
					TimeStamp:   mockDateUpdated.Unix(),
				},
				{
					Status:      "ERROR",
					Description: "error verifying domain claim",
					TimeStamp:   mockDateUpdated.Add(time.Hour).Unix(),
				},
			},
		},
		{
			ID:        "pending2",
			Status:    "PENDING",
			Domain:    "pending2.com.",
			CreatedAt: mockDateCreated.Unix(),
			ExpiresAt: mockDateExpiresAt.Unix(),
			AssertBy:  mockDateAssertBy.Unix(),
			Log: []mockClaimLogEntry{
				{
					Status:      "ERROR",
					Description: "error verifying domain claim",
					TimeStamp:   mockDateUpdated.Unix(),
				},
			},
		},
	}
	mockDateCreated   = time.Date(2021, 6, 16, 4, 19, 25, 0, time.UTC)
	mockDateExpiresAt = time.Date(2021, 6, 17, 22, 7, 4, 0, time.UTC)
	mockDateUpdated   = time.Date(2021, 6, 18, 16, 29, 51, 0, time.UTC)
	mockDateAssertBy  = time.Date(2021, 6, 19, 13, 5, 31, 0, time.UTC)
	mockPolicy        = hvclient.Policy{
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
			r.Patch("/", mockCertificatesRevoke)
		})
	})

	r.Route("/claims", func(r chi.Router) {
		r.Route("/domains", func(r chi.Router) {
			r.Get("/", mockClaimsDomains)
			r.Route("/{arg}", func(r chi.Router) {
				r.Post("/", mockClaimsSubmit)
				r.Get("/", mockClaimsRetrieve)
				r.Delete("/", mockClaimsDelete)
				r.Route("/dns", func(r chi.Router) {
					r.Post("/", mockClaimsDNS)
				})
				r.Route("/http", func(r chi.Router) {
					r.Post("/", mockClaimsHTTP)
				})
				r.Route("/email", func(r chi.Router) {
					r.Get("/", mockClaimsEmailRetrieve)
					r.Post("/", mockClaimsEmail)
				})
				r.Route("/reassert", func(r chi.Router) {
					r.Post("/", mockClaimsReassert)
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

	// Unmarshal body.
	var body mockRevocationBody
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		fmt.Printf("%s\n", err)
		return
	}

	// Return 404 for specific serial number.
	if sn.Cmp(mockBigIntNotFound) == 0 {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	mockWriteResponse(w, http.StatusNoContent, nil)
}

// mockClaimsDelete mocks a DELETE /claims/domains/{id} operation.
func mockClaimsDelete(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	mockWriteResponse(w, http.StatusNoContent, nil)
}

// mockClaimsDNS mocks a POST /claims/domains/{id}/dns operation.
func mockClaimsDNS(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	// Unmarshal body.
	var body mockDNSRequest
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		return
	}

	if body.AuthorizationDomain == mockClaimDomainVerified {
		mockWriteResponse(w, http.StatusNoContent, nil)
		return
	}

	mockWriteResponse(w, http.StatusCreated, nil)
}

// mockClaimsEmail mocks a POST /claims/domains/{id}/email operation.
func mockClaimsEmail(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	// Unmarshal body.
	var body mockEmailRequest
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		return
	}

	if body.Email == mockClaimEmail {
		mockWriteResponse(w, http.StatusNoContent, nil)
		return
	}

	mockWriteResponse(w, http.StatusCreated, nil)
}

// mockClaimsEmailRetrieve mocks a GET /claims/domains/{id}/email operation.
func mockClaimsEmailRetrieve(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	var mockResponse = mockAuthorisedEmails{
		Constructed: []string{
			"admin@test.com",
			"administrator@test.com",
			"webmaster@test.com",
			"hostmaster@test.com",
			"postmaster@test.com",
		},
		DNS: mockDNSResults{
			SOA: mockSOAResults{
				Emails: []string{
					"example@test.com",
				},
			},
		},
	}

	mockWriteResponse(w, http.StatusOK, &mockResponse)
}

// mockClaimsHTTP mocks a POST /claims/domains/{id}/http operation.
func mockClaimsHTTP(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	// Unmarshal body.
	var body mockHTTPRequest
	var err = mockUnmarshalBody(w, r, &body)
	if err != nil {
		return
	}

	if body.AuthorizationDomain == mockClaimDomainVerified {
		mockWriteResponse(w, http.StatusNoContent, nil)
		return
	}

	mockWriteResponse(w, http.StatusCreated, nil)
}

// mockClaimsDomains mocks a GET /claims/domains operation.
func mockClaimsDomains(w http.ResponseWriter, r *http.Request) {
	var status string
	if vals := r.URL.Query()["status"]; len(vals) > 0 {
		status = vals[0]
	}

	var entries []mockClaim
	for _, entry := range mockClaimsEntries {
		if (entry.Status == "VERIFIED") == (status == "VERIFIED") {
			entries = append(entries, entry)
		}
	}

	w.Header().Set("Total-Count", fmt.Sprintf("%d", len(entries)))
	mockWriteResponse(w, http.StatusOK, entries)
}

// mockClaimsSubmit mocks a POST /claims/domains/{domain} operation.
func mockClaimsSubmit(w http.ResponseWriter, r *http.Request) {
	var domain = chi.URLParam(r, "arg")

	// Trigger 422 for specific domain
	if domain == triggerError {
		mockWriteError(w, http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("http://local/claims/domains/%s", mockClaimAssert.ID))
	mockWriteResponse(w, http.StatusCreated, mockClaimAssert)
}

// mockClaimsReassert mocks a POST /claims/domains/{id}/reassert operation.
func mockClaimsReassert(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 422 for specific domain
	if id == triggerError {
		mockWriteError(w, http.StatusUnprocessableEntity)
		return
	}

	w.Header().Set("Location", fmt.Sprintf("http://local/claims/domains/%s", mockClaimAssert.ID))
	mockWriteResponse(w, http.StatusOK, mockClaimAssert)
}

// mockClaimsRetrieve mocks a GET /claims/domains/{id} operation.
func mockClaimsRetrieve(w http.ResponseWriter, r *http.Request) {
	var id = chi.URLParam(r, "arg")

	// Trigger 404 for specific ID
	if id == triggerError {
		mockWriteError(w, http.StatusNotFound)
		return
	}

	mockWriteResponse(w, http.StatusOK, mockClaimsEntries[0])
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
