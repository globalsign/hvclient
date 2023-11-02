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
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/pki"
	"github.com/google/go-cmp/cmp"
)

func TestClientMockNew(t *testing.T) {
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
			apiKey:    mockAPIKey,
			apiSecret: mockAPISecret,
			serial:    mockSSLClientSerial,
			status:    http.StatusOK,
		},
		{
			name:      "WrongAPIKey",
			apiKey:    "wrong_key",
			apiSecret: mockAPISecret,
			serial:    mockSSLClientSerial,
			status:    http.StatusUnauthorized,
		},
		{
			name:      "WrongSerial",
			apiKey:    mockAPIKey,
			apiSecret: mockAPISecret,
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
				if err == nil {
					t.Fatal("unexpectedly created client")
				}

				var apiErr hvclient.APIError
				if !errors.As(err, &apiErr) {
					t.Fatalf("unexpected error: %v", err)
				}

				if apiErr.StatusCode != tc.status {
					t.Fatalf("got status code %d, want %d", apiErr.StatusCode, tc.status)
				}
			}
		})
	}
}

func TestClientMockCertificatesRequest(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		cn   string
		want *big.Int
		err  error
	}{
		{
			name: "OK",
			cn:   "John Doe",
			want: mustParseBigInt(t, mockCertSerial, 16),
		},
		{
			name: "TriggeredError",
			cn:   triggerError,
			err:  hvclient.APIError{StatusCode: http.StatusUnprocessableEntity},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var csr, err = pki.CSRFromFile("testdata/test_csr.pem")
			if err != nil {
				t.Fatalf("failed to read CSR: %v", err)
			}

			var got *string
			got, err = client.CertificateRequest(
				ctx,
				&hvclient.Request{
					Validity: &hvclient.Validity{
						NotBefore: time.Now(),
						NotAfter:  time.Unix(0, 0),
					},
					Subject: &hvclient.DN{CommonName: tc.cn},
					CSR:     csr,
				},
			)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if fmt.Sprintf("%X", got) != mockCertSerial {
				t.Fatalf("got %X, want %s", got, mockCertSerial)
			}
		})
	}
}

func TestClientMockCertificatesRetrieve(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		serial *big.Int
		want   hvclient.CertInfo
		err    error
	}{
		{
			name:   "OK",
			serial: big.NewInt(0x741daf9ec2d5f7dc),
			want: hvclient.CertInfo{
				PEM:       pki.CertToPEMString(mockCert),
				X509:      mockCert,
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Date(2021, 6, 18, 16, 29, 51, 0, time.UTC),
			},
		},
		{
			name:   "NotFound",
			serial: mockBigIntNotFound,
			err:    hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.CertificateRetrieve(ctx, tc.serial)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if !got.Equal(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockCertificatesRevoke(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		serial *big.Int
		err    error
	}{
		{
			name:   "OK",
			serial: big.NewInt(0x741daf9ec2d5f7dc),
		},
		{
			name:   "NotFound",
			serial: mockBigIntNotFound,
			err:    hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var err = client.CertificateRevoke(ctx, tc.serial)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}
		})
	}
}

func TestClientMockCertificatesRevokeWithReason(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name                     string
		serial                   *big.Int
		reason                   hvclient.RevocationReason
		time                     int64
		keyCompromiseAttestation string
		err                      error
	}{
		{
			name:                     "OK",
			serial:                   big.NewInt(0x741daf9ec2d5f7dc),
			reason:                   hvclient.RevocationReasonUnspecified,
			time:                     0,
			keyCompromiseAttestation: "",
		},
		{
			name:   "NotFound",
			serial: mockBigIntNotFound,
			err:    hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var err = client.CertificateRevokeWithReason(ctx, tc.serial, tc.reason, tc.time, tc.keyCompromiseAttestation)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}
		})
	}
}

func TestClientMockClaimsDomains(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		status        hvclient.ClaimStatus
		page, perPage int
		want          []hvclient.Claim
	}{
		{
			name:   "Verified",
			status: hvclient.StatusVerified,
			want: []hvclient.Claim{
				{
					ID:        mockClaimID,
					Status:    hvclient.StatusVerified,
					Domain:    "fake.com.",
					CreatedAt: mockDateCreated,
					ExpiresAt: mockDateExpiresAt,
					AssertBy:  mockDateAssertBy,
					Log: []hvclient.ClaimLogEntry{
						{
							Status:      hvclient.VerificationSuccess,
							Description: "domain claim verified",
							TimeStamp:   mockDateUpdated,
						},
					},
				},
			},
		},
		{
			name:   "Pending",
			status: hvclient.StatusPending,
			want: []hvclient.Claim{
				{
					ID:        "pending1",
					Status:    hvclient.StatusPending,
					Domain:    "pending1.com.",
					CreatedAt: mockDateCreated,
					ExpiresAt: mockDateExpiresAt,
					AssertBy:  mockDateAssertBy,
					Log: []hvclient.ClaimLogEntry{
						{
							Status:      hvclient.VerificationError,
							Description: "error verifying domain claim",
							TimeStamp:   mockDateUpdated,
						},
						{
							Status:      hvclient.VerificationError,
							Description: "error verifying domain claim",
							TimeStamp:   mockDateUpdated.Add(time.Hour),
						},
					},
				},
				{
					ID:        "pending2",
					Status:    hvclient.StatusPending,
					Domain:    "pending2.com.",
					CreatedAt: mockDateCreated,
					ExpiresAt: mockDateExpiresAt,
					AssertBy:  mockDateAssertBy,
					Log: []hvclient.ClaimLogEntry{
						{
							Status:      hvclient.VerificationError,
							Description: "error verifying domain claim",
							TimeStamp:   mockDateUpdated,
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			var got, count, err = client.ClaimsDomains(ctx, tc.page, tc.perPage, tc.status)
			if err != nil {
				t.Fatalf("failed to get stats expiring: %v", err)
			}

			if count != int64(len(tc.want)) {
				t.Fatalf("got count %d, want %d", count, len(tc.want))
			}

			if !cmp.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimDelete(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		err  error
	}{
		{
			name: "OK",
			id:   mockClaimID,
		},
		{
			name: "TriggerError",
			id:   triggerError,
			err:  hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var err = client.ClaimDelete(ctx, tc.id)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}
		})
	}
}

func TestClientMockClaimDNS(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		id     string
		domain string

		want bool
		err  error
	}{
		{
			name:   "ok - DNS Pending",
			id:     mockClaimID,
			domain: "fake.com",

			want: false,
			err:  nil,
		},
		{
			name:   "ok - DNS Verified",
			id:     mockClaimID,
			domain: mockClaimDomainVerified,

			want: true,
			err:  nil,
		},
		{
			name:   "error - DNS triggerError",
			id:     triggerError,
			domain: "",

			want: false,
			err:  hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimDNS(ctx, tc.id, tc.domain)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimHTTP(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		id     string
		domain string

		want bool
		err  error
	}{
		{
			name:   "ok - HTTP Pending",
			id:     mockClaimID,
			domain: "fake.com",

			want: false,
			err:  nil,
		},
		{
			name:   "ok - HTTP Verified",
			id:     mockClaimID,
			domain: mockClaimDomainVerified,

			want: true,
			err:  nil,
		},
		{
			name:   "error - HTTP triggerError",
			id:     triggerError,
			domain: "",

			want: false,
			err:  hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimHTTP(ctx, tc.id, tc.domain, "HTTP")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimEmail(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		id    string
		email string

		want bool
		err  error
	}{
		{
			name:  "ok - Email Pending",
			id:    mockClaimID,
			email: "khan@earth.com",

			want: false,
			err:  nil,
		},
		{
			name:  "ok - Email Verified",
			id:    mockClaimID,
			email: mockClaimEmail,

			want: true,
			err:  nil,
		},
		{
			name:  "error - Email triggerError",
			id:    triggerError,
			email: "",

			want: false,
			err:  hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimEmail(ctx, tc.id, tc.email)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimEmailRetrieve(t *testing.T) {
	t.Parallel()

	var want = hvclient.AuthorisedEmails{
		Constructed: []string{
			"admin@test.com",
			"administrator@test.com",
			"webmaster@test.com",
			"hostmaster@test.com",
			"postmaster@test.com",
		},
		DNS: hvclient.DNSResults{
			SOA: hvclient.SOAResults{
				Emails: []string{
					"example@test.com",
				},
			},
		},
	}

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	var got, err = client.ClaimEmailRetrieve(ctx, mockClaimID)
	if err != nil {
		t.Fatalf("got error %v, want %v", err, nil)
	}

	if cmp.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestClientMockClaimSubmit(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		domain string
		want   hvclient.ClaimAssertionInfo
		err    error
	}{
		{
			name:   "OK",
			domain: "fake.com.",
			want: hvclient.ClaimAssertionInfo{
				Token:    mockClaimToken,
				AssertBy: mockDateAssertBy,
				ID:       mockClaimID,
			},
		},
		{
			name:   "TriggerError",
			domain: triggerError,
			err:    hvclient.APIError{StatusCode: http.StatusUnprocessableEntity},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimSubmit(ctx, tc.domain)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if !cmp.Equal(got, &tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimReassert(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		want hvclient.ClaimAssertionInfo
		err  error
	}{
		{
			name: "OK",
			id:   mockClaimID,
			want: hvclient.ClaimAssertionInfo{
				Token:    mockClaimToken,
				AssertBy: mockDateAssertBy,
				ID:       mockClaimID,
			},
		},
		{
			name: "TriggerError",
			id:   triggerError,
			err:  hvclient.APIError{StatusCode: http.StatusUnprocessableEntity},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimReassert(ctx, tc.id)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if !cmp.Equal(got, &tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockClaimRetrieve(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		want hvclient.Claim
		err  error
	}{
		{
			name: "OK",
			id:   mockClaimID,
			want: hvclient.Claim{
				ID:        mockClaimID,
				Status:    hvclient.StatusVerified,
				Domain:    "fake.com.",
				CreatedAt: mockDateCreated,
				ExpiresAt: mockDateExpiresAt,
				AssertBy:  mockDateAssertBy,
				Log: []hvclient.ClaimLogEntry{
					{
						Status:      hvclient.VerificationSuccess,
						Description: "domain claim verified",
						TimeStamp:   mockDateUpdated,
					},
				},
			},
		},
		{
			name: "TriggerError",
			id:   triggerError,
			err:  hvclient.APIError{StatusCode: http.StatusNotFound},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			var got, err = client.ClaimRetrieve(ctx, tc.id)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				verifyAPIError(t, err, tc.err)
				return
			}

			if !cmp.Equal(got, &tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockCounterCertsIssued(t *testing.T) {
	t.Parallel()

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var got, err = client.CounterCertsIssued(ctx)
	if err != nil {
		t.Fatalf("failed to get count of certificates issued: %v", err)
	}

	if got != mockCounterIssued {
		t.Fatalf("got %d, want %d", got, mockCounterIssued)
	}
}

func TestClientMockCounterCertsRevoked(t *testing.T) {
	t.Parallel()

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var got, err = client.CounterCertsRevoked(ctx)
	if err != nil {
		t.Fatalf("failed to get count of certificates revoked: %v", err)
	}

	if got != mockCounterRevoked {
		t.Fatalf("got %d, want %d", got, mockCounterRevoked)
	}
}

func TestClientMockQuotasIssuance(t *testing.T) {
	t.Parallel()

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var got, err = client.QuotaIssuance(ctx)
	if err != nil {
		t.Fatalf("failed to get issuance quota: %v", err)
	}

	if got != mockQuotaIssuance {
		t.Fatalf("got %d, want %d", got, mockQuotaIssuance)
	}
}

func TestClientMockStatsExpiring(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		page, perPage int
		from, to      time.Time
		want          []hvclient.CertMeta
	}{
		{
			name: "ok",
			want: []hvclient.CertMeta{
				{
					SerialNumber: mustParseBigInt(t, "748BDAE7199CC246", 16),
					NotBefore:    time.Date(2021, 7, 12, 16, 29, 51, 0, time.UTC),
					NotAfter:     time.Date(2021, 10, 10, 16, 29, 51, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "DEADBEEF44274823", 16),
					NotBefore:    time.Date(2021, 7, 14, 12, 5, 37, 0, time.UTC),
					NotAfter:     time.Date(2021, 10, 12, 12, 5, 37, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "AA9915DC78BB21FF", 16),
					NotBefore:    time.Date(2021, 7, 14, 17, 59, 8, 0, time.UTC),
					NotAfter:     time.Date(2021, 10, 12, 17, 59, 8, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "32897DA7B113DAB6", 16),
					NotBefore:    time.Date(2021, 7, 14, 21, 11, 43, 0, time.UTC),
					NotAfter:     time.Date(2021, 10, 12, 21, 11, 43, 0, time.UTC),
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			var got, count, err = client.StatsExpiring(ctx, tc.page, tc.perPage, tc.from, tc.to)
			if err != nil {
				t.Fatalf("failed to get stats expiring: %v", err)
			}

			if count != int64(len(tc.want)) {
				t.Fatalf("got count %d, want %d", count, len(tc.want))
			}

			if !cmp.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockStatsIssued(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		page, perPage int
		from, to      time.Time
		want          []hvclient.CertMeta
	}{
		{
			name: "ok",
			want: []hvclient.CertMeta{
				{
					SerialNumber: mustParseBigInt(t, "741DAF9EC2D5F7DC", 16),
					NotBefore:    time.Date(2021, 6, 18, 16, 29, 51, 0, time.UTC),
					NotAfter:     time.Date(2021, 9, 16, 16, 29, 51, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "87BC1DC5524A2B18", 16),
					NotBefore:    time.Date(2021, 6, 19, 12, 5, 37, 0, time.UTC),
					NotAfter:     time.Date(2021, 9, 17, 12, 5, 37, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "F488BCE14A56CD2A", 16),
					NotBefore:    time.Date(2021, 6, 19, 17, 59, 8, 0, time.UTC),
					NotAfter:     time.Date(2021, 9, 17, 17, 59, 8, 0, time.UTC),
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			var got, count, err = client.StatsIssued(ctx, tc.page, tc.perPage, tc.from, tc.to)
			if err != nil {
				t.Fatalf("failed to get stats issued: %v", err)
			}

			if count != int64(len(tc.want)) {
				t.Fatalf("got count %d, want %d", count, len(tc.want))
			}

			if !cmp.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockStatsRevoked(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		page, perPage int
		from, to      time.Time
		want          []hvclient.CertMeta
	}{
		{
			name: "ok",
			want: []hvclient.CertMeta{
				{
					SerialNumber: mustParseBigInt(t, "87BC1DC5524A2B18", 16),
					NotBefore:    time.Date(2021, 6, 19, 12, 5, 37, 0, time.UTC),
					NotAfter:     time.Date(2021, 9, 17, 12, 5, 37, 0, time.UTC),
				},
				{
					SerialNumber: mustParseBigInt(t, "F488BCE14A56CD2A", 16),
					NotBefore:    time.Date(2021, 6, 19, 17, 59, 8, 0, time.UTC),
					NotAfter:     time.Date(2021, 9, 17, 17, 59, 8, 0, time.UTC),
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			var client, closefunc = newMockClient(t)
			defer closefunc()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			var got, count, err = client.StatsRevoked(ctx, tc.page, tc.perPage, tc.from, tc.to)
			if err != nil {
				t.Fatalf("failed to get stats revoked: %v", err)
			}

			if count != int64(len(tc.want)) {
				t.Fatalf("got count %d, want %d", count, len(tc.want))
			}

			if !cmp.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClientMockTrustChain(t *testing.T) {
	t.Parallel()

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var got, err = client.TrustChain(ctx)
	if err != nil {
		t.Fatalf("failed to get issuance quota: %v", err)
	}

	if !cmp.Equal(got, mockTrustChainCerts) {
		t.Fatalf("got %v, want %v", got, mockTrustChainCerts)
	}
}

func TestClientMockValidationPolicy(t *testing.T) {
	t.Parallel()

	var client, closefunc = newMockClient(t)
	defer closefunc()

	var ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	var got, err = client.Policy(ctx)
	if err != nil {
		t.Fatalf("failed to get validation policy: %v", err)
	}

	if !cmp.Equal(got, &mockPolicy) {
		t.Fatalf("got %v, want %v", got, mockPolicy)
	}
}

func verifyAPIError(t *testing.T, got, want error) {
	t.Helper()

	var gotAPIErr, wantAPIErr hvclient.APIError

	if !errors.As(got, &gotAPIErr) {
		t.Fatalf("got error type %T, want %T", got, gotAPIErr)
	}

	if !errors.As(want, &wantAPIErr) {
		t.Fatalf("want error type should be %T, but is %T", want, wantAPIErr)
	}

	if gotAPIErr.StatusCode != wantAPIErr.StatusCode {
		t.Fatalf("got error status %d, want %d", gotAPIErr.StatusCode, wantAPIErr.StatusCode)
	}
}

func mustParseBigInt(t *testing.T, s string, base int) *big.Int {
	t.Helper()

	var n, ok = big.NewInt(0).SetString(s, base)
	if !ok {
		t.Fatalf("invalid big integer: %s", s)
	}

	return n
}
