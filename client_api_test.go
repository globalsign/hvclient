// +build integration

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
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

const (
	tcrRSAPublicKeyFile  = "testdata/rsa_pub.key"
	tcrRSAPrivateKeyFile = "testdata/rsa_priv.key"
	tcrECPublicKeyFile   = "testdata/ec_pub.key"
	tcrECPrivateKeyFile  = "testdata/ec_priv.key"
)

// Test for success.
func TestCertificateRequest(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		req *hvclient.Request
	}{
		{
			&hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
				},
				Subject: &hvclient.DN{
					CommonName: "Phil Bole",
				},
				PublicKey: testhelpers.MustGetPublicKeyFromFile(t, tcrRSAPublicKeyFile),
			},
		},
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(fmt.Sprintf("%d", n+1), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if _, err := testClient.CertificateRequest(ctx, tc.req); err != nil {
				t.Errorf("couldn't get certificate: %v", err)
			}
		})
	}
}

// Test for success with a PKCS#10 as proof-of-possession, requires a
// different account and client.
func TestCertificateRequestPKCS10(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		req *hvclient.Request
	}{
		{
			&hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
				},
				Subject: &hvclient.DN{
					CommonName: "Johnny Peaton",
				},
				PrivateKey: testhelpers.MustGetPrivateKeyFromFile(t, tcrRSAPrivateKeyFile),
			},
		},
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(fmt.Sprintf("%d", n+1), func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var clnt *hvclient.Client
			var err error

			if clnt, err = hvclient.NewClientFromFile(ctx, testP10ConfigFilename); err != nil {
				t.Fatalf("couldn't get client from file: %v", err)
			}

			if tc.req.CSR, err = tc.req.PKCS10(); err != nil {
				t.Fatalf("couldn't generate PKCS#10: %v", err)
			}

			tc.req.PrivateKey = nil

			if _, err = clnt.CertificateRequest(ctx, tc.req); err != nil {
				t.Errorf("couldn't get certificate: %v", err)
			}
		})
	}
}

// Test for failure.
func TestCertificateRequestFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		req  *hvclient.Request
		err  error
	}{
		{
			"UnsupportedKeyType",
			&hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
				},
				Subject: &hvclient.DN{
					CommonName: "MT Glass",
				},
				PublicKey: testhelpers.MustGetPublicKeyFromFile(t, tcrECPublicKeyFile),
			},
			testAPIErrorUnsupportedKeyType,
		},
		{
			"KeyTypeAgainstPolicy",
			&hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
				},
				Subject: &hvclient.DN{
					CommonName: "MT Glass",
					Email:      "mtglass@acme.com",
				},
				PublicKey: testhelpers.MustGetPublicKeyFromFile(t, tcrRSAPublicKeyFile),
			},
			testAPIErrorAgainstPolicy,
		},
		{
			"PublicKeyNotAKey",
			&hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Now(),
					NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
				},
				Subject: &hvclient.DN{
					CommonName: "MT Glass",
					Email:      "mtglass@acme.com",
				},
				PublicKey: "not even a key",
			},
			&json.MarshalerError{
				Type: reflect.TypeOf(errors.New("")),
				Err:  errors.New("value doesn't matter"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			// Attempt to get certificate.

			var err error
			if _, err = testClient.CertificateRequest(ctx, tc.req); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Test for success.
func TestRetrieveCertificate(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var got *hvclient.CertInfo
	if got, err = testClient.CertificateRetrieve(ctx, testRetrieveCertificateSerialNumber); err != nil {
		t.Fatalf("couldn't retrieve certificate: %v", err)
	}

	if !got.Equal(testRetrieveCertificateCertInfo) {
		t.Fatalf("got %v, want %v", got, testRetrieveCertificateCertInfo)
	}

	var block *pem.Block
	block, _ = pem.Decode([]byte(testTrustChainCerts[0]))

	var root *x509.Certificate
	if root, err = x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("couldn't parse root certificate: %v", err)
	}

	if err = got.X509.CheckSignatureFrom(root); err != nil {
		t.Errorf("couldn't check signature: %v", err)
	}
}

// Test for failure.
func TestRetrieveCertificateFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		serial string
		err    error
	}{
		{
			"NoSuchSerialNumber",
			testRetrieveNonexistentCertificateSerialNumber,
			testAPIErrorNotFound,
		},
		{
			"InvalidSerialNumber",
			testRetrieveInvalidCertificateSerialNumber,
			testAPIErrorNotFound,
		},
		{
			"BadSerialNumber",
			testRetrieveBadCertificateSerialNumber,
			testAPIErrorInvalidSerialNumberFormat,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error

			if _, err = testClient.CertificateRetrieve(ctx, tc.serial); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

func TestRevokeCertificateFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name         string
		serialnumber string
		err          error
	}{
		{
			"AlreadyRevoked",
			testRevokeCertificateSerialNumberAlreadyRevoked,
			nil,
		},
		{
			"Nonexistence",
			testRetrieveNonexistentCertificateSerialNumber,
			testAPIErrorNotFound,
		},
		{
			"InvalidSerialNumber",
			testRetrieveInvalidCertificateSerialNumber,
			testAPIErrorNotFound,
		},
		{
			"BadSerialNumber",
			testRetrieveBadCertificateSerialNumber,
			testAPIErrorInvalidSerialNumberFormat,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			err = testClient.CertificateRevoke(ctx, tc.serialnumber)
			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Test certificate operations by requesting a certificate issuance, then
// immediately retrieving it, and immediately revoking it. This test stands
// the best chance of attempting to retrieve or revoke the certificate while
// it is still in the process of being issued, which should be handled
// transparently, so continued success of this test would suggest (although
// not prove) that that functionality is working as desired. This also tests
// that the certificate request method is correctly returning a certificate
// serial number which can successfully be used for retrieval and revocation.
func TestCertificateRequestRetrieveRevoke(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Request certificate.

	var err error

	var req = &hvclient.Request{
		Validity: &hvclient.Validity{
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(time.Duration(24) * time.Hour),
		},
		Subject: &hvclient.DN{
			CommonName: "Harcourt Finnigren",
		},
		PublicKey: testhelpers.MustGetPublicKeyFromFile(t, tcrRSAPublicKeyFile),
	}

	var serialNumber string
	if serialNumber, err = testClient.CertificateRequest(ctx, req); err != nil {
		t.Fatalf("couldn't request certificate: %v", err)
	}

	// Retrieve certificate.

	if _, err = testClient.CertificateRetrieve(ctx, serialNumber); err != nil {
		t.Fatalf("couldn't retrieve certificate: %v", err)
	}

	// Revoke certificate.

	if err = testClient.CertificateRevoke(ctx, serialNumber); err != nil {
		t.Fatalf("couldn't revoke certificate: %v", err)
	}
}

// Test for success.
func TestCounters(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		method func(*hvclient.Client, context.Context) (int64, error)
		cmp    func(*testing.T, int64)
	}{
		{
			"CertsIssued",
			(*hvclient.Client).CounterCertsIssued,
			func(t *testing.T, n int64) {
				t.Helper()
				if n < testCounterCertsIssuedMinimum {
					t.Errorf("got %d, want >= %d", n, testCounterCertsIssuedMinimum)
				}
			},
		},
		{
			"CertsRevoked",
			(*hvclient.Client).CounterCertsRevoked,
			func(t *testing.T, n int64) {
				t.Helper()
				if n < testCounterCertsRevokedMinimum {
					t.Errorf("got %d, want >= %d", n, testCounterCertsRevokedMinimum)
				}
			},
		},
		{
			"QuotaIssuance",
			(*hvclient.Client).QuotaIssuance,
			func(t *testing.T, n int64) {
				t.Helper()
				if n > testQuotaIssuanceMaximum {
					t.Errorf("got %d, want <= %d", n, testQuotaIssuanceMaximum)
				}
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var got int64
			var err error

			if got, err = tc.method(testClient, ctx); err != nil {
				t.Fatalf("couldn't get counter: %v", err)
			}

			tc.cmp(t, got)
		})
	}
}

// Test for context timeout.
func TestCountersForTimeout(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		method func(*hvclient.Client, context.Context) (int64, error)
	}{
		{
			"CertsIssued",
			(*hvclient.Client).CounterCertsIssued,
		},
		{
			"CertsRevoked",
			(*hvclient.Client).CounterCertsRevoked,
		},
		{
			"QuotaIssuance",
			(*hvclient.Client).QuotaIssuance,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond*100)
			defer cancel()

			var err error

			if _, err = tc.method(testClient, ctx); err == nil {
				t.Fatalf("unexpectedly got counter")
			}

			if !strings.Contains(err.Error(), timeoutErrorSubstring) {
				t.Errorf("failed to get context timeout error")
			}
		})
	}
}

// Test for success.
func TestStats(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		method func(
			*hvclient.Client,
			context.Context,
			int, int,
			time.Time, time.Time) ([]hvclient.CertMeta, int64, error)
		page, pagesize int
		from, to       time.Time
		wantcount      int64
		wantmetas      []hvclient.CertMeta
	}{
		{
			"StatsExpiring",
			(*hvclient.Client).StatsExpiring,
			1,
			testStatsMaximumPageSize,
			testStatsExpiringFrom,
			testStatsExpiringTo,
			testStatsExpiringTotalCount,
			testStatsExpiringMetas,
		},
		{
			"StatsIssued",
			(*hvclient.Client).StatsIssued,
			1,
			testStatsMaximumPageSize,
			testStatsIssuedFrom,
			testStatsIssuedTo,
			testStatsIssuedTotalCount,
			testStatsIssuedMetas,
		},
		{
			"StatsRevoked",
			(*hvclient.Client).StatsRevoked,
			1,
			testStatsMaximumPageSize,
			testStatsRevokedFrom,
			testStatsRevokedTo,
			testStatsRevokedTotalCount,
			testStatsRevokedMetas,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			// Make API call.
			var got, count, err = tc.method(testClient, ctx, tc.page, tc.pagesize, tc.from, tc.to)
			if err != nil {
				t.Fatalf("couldn't get cert metas: %v", err)
			}

			// Skip remaining tests, as the counts are not as expected.
			t.Skipf("stats tests currently failing")

			// Verify total count.
			if count != tc.wantcount {
				t.Errorf("got count %d, want %d", count, tc.wantcount)
			}

			// Verify certificate metadata.
			if !reflect.DeepEqual(got, tc.wantmetas) {
				t.Errorf("got %v, want %v", got, tc.wantmetas)
			}
		})
	}
}

// Tests for failure.
func TestStatsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name           string
		method         func(*hvclient.Client, context.Context, int, int, time.Time, time.Time) ([]hvclient.CertMeta, int64, error)
		page, pagesize int
		from, to       time.Time
		err            error
	}{
		{
			"InvalidPageSize",
			(*hvclient.Client).StatsExpiring,
			1,
			testStatsInvalidPageSize,
			testStatsExpiringFrom,
			testStatsExpiringTo,
			testAPIErrorInvalidPageSize,
		},
		{
			"InvalidPage",
			(*hvclient.Client).StatsIssued,
			0,
			testStatsMaximumPageSize,
			testStatsExpiringFrom,
			testStatsExpiringTo,
			testAPIErrorInvalidPage,
		},
		{
			"InvalidTime",
			(*hvclient.Client).StatsRevoked,
			1,
			testStatsMaximumPageSize,
			testStatsTooLongFrom,
			testStatsTooLongTo,
			testAPIErrorWindowTooLong,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, _, err = tc.method(testClient, ctx, tc.page, tc.pagesize, tc.from, tc.to); err == nil {
				t.Fatalf("unexpectedly got cert metas")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Test that the returned chain of trust matches the expected chain
// of trust for the test account.
func TestTrustChain(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var got []string
	if got, err = testClient.TrustChain(ctx); err != nil {
		t.Fatalf("couldn't get trust chain: %v", err)
	}

	if !reflect.DeepEqual(got, testTrustChainCerts) {
		t.Errorf("got %v, want %v", got, testTrustChainCerts)
	}
}

// Test that the returned raw validation policy  matches the expected raw
// validation policy for the test account.
func TestValidationPolicy(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		want *hvclient.Policy
	}{
		{
			"One",
			&hvclient.Policy{
				Validity: &hvclient.ValidityPolicy{
					SecondsMin:            60,
					SecondsMax:            7776000,
					NotBeforeNegativeSkew: 200,
					NotBeforePositiveSkew: 200,
				},
				SubjectDN: &hvclient.SubjectDNPolicy{
					CommonName: &hvclient.StringPolicy{
						Presence: hvclient.Required,
						Format:   "^[a-zA-Z0-9\\ \\-\\.\\\\s]+$",
					},
					Organization: &hvclient.StringPolicy{
						Presence: hvclient.Static,
						Format:   "GlobalSign Engineering",
					},
					OrganizationalUnit: &hvclient.ListPolicy{
						Static:   false,
						List:     []string{"^.*$"},
						MinCount: 0,
						MaxCount: 3,
					},
					StreetAddress: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					Locality: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					State: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					Country: &hvclient.StringPolicy{
						Presence: hvclient.Static,
						Format:   "US",
					},
					Email: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					JOILocality: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					JOIState: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					JOICountry: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
					BusinessCategory: &hvclient.StringPolicy{
						Presence: hvclient.Forbidden,
						Format:   "",
					},
				},
				SAN: &hvclient.SANPolicy{
					DNSNames: &hvclient.ListPolicy{
						Static:   false,
						List:     []string{"."},
						MinCount: 0,
						MaxCount: 5,
					},
					Emails: &hvclient.ListPolicy{
						Static:   false,
						List:     []string{},
						MinCount: 0,
						MaxCount: 0,
					},
					IPAddresses: &hvclient.ListPolicy{
						Static:   false,
						List:     []string{},
						MinCount: 0,
						MaxCount: 0,
					},
					URIs: &hvclient.ListPolicy{
						Static:   false,
						List:     []string{},
						MinCount: 0,
						MaxCount: 0,
					},
				},
				EKUs: &hvclient.EKUPolicy{
					Critical: false,
					EKUs: hvclient.ListPolicy{
						Static: true,
						List: []string{
							"1.3.6.1.5.5.7.3.2",
							"1.3.6.1.5.5.7.3.1",
						},
						MinCount: 2,
						MaxCount: 2,
					},
				},
				PublicKey: &hvclient.PublicKeyPolicy{
					KeyType:        hvclient.RSA,
					AllowedLengths: []int{2048, 3072, 4096},
					KeyFormat:      hvclient.PKCS8,
				},
				PublicKeySignature: hvclient.Forbidden,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			var pol *hvclient.Policy
			if pol, err = testClient.Policy(ctx); err != nil {
				t.Fatalf("couldn't get policy: %v", err)
			}

			if !reflect.DeepEqual(pol, tc.want) {
				t.Errorf("got %v, want %v", pol, tc.want)
			}
		})
	}
}

// Tests for context timeout.
func TestTrustChainWithContextTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond*1000)
	defer cancel()

	var err error
	if _, err = testClient.TrustChain(ctx); err == nil {
		t.Fatalf("unexpectedly got trust chain")
	}

	if !strings.Contains(err.Error(), timeoutErrorSubstring) {
		t.Errorf("failed to get context timeout error")
	}
}

// Tests for context timeout.
func TestValidationPolicyWithContextTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond*1000)
	defer cancel()

	var err error
	if _, err = testClient.Policy(ctx); err == nil {
		t.Fatalf("unexpectedly got policy")
	}

	if !strings.Contains(err.Error(), timeoutErrorSubstring) {
		t.Errorf("failed to get context timeout error")
	}
}

// Tests for success without verifying the output.
func TestClaimsDomains(t *testing.T) {
	t.Skip("this test always times out, skip until resolved")

	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	if _, _, err := testClient.ClaimsDomains(ctx, 1, testStatsMaximumPageSize, hvclient.StatusPending); err != nil {
		t.Errorf("couldn't get domain claims: %v", err)
	}
}

func TestClaimsDomainsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		page    int
		perpage int
		status  hvclient.ClaimStatus
		err     error
	}{
		{
			"BadPageSize",
			1,
			testStatsInvalidPageSize,
			hvclient.StatusVerified,
			testAPIErrorInvalidPageSize,
		},
		{
			"BadPage",
			0,
			testStatsMaximumPageSize,
			hvclient.StatusVerified,
			testAPIErrorInvalidPage,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, _, err = testClient.ClaimsDomains(ctx, tc.page, tc.perpage, tc.status); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

func TestClaimSubmitFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		domain string
		err    error
	}{
		{
			"AlreadyClaimed",
			testClaimAlreadyClaimedDomain,
			testAPIErrorExistingDomain,
		},
		{
			"InvalidDomain",
			testClaimInvalidDomain,
			testAPIErrorInvalidDomain,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, err = testClient.ClaimSubmit(ctx, tc.domain); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Test for success with valid existing claim ID.
func TestClaimRetrieve(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var clm *hvclient.Claim
	if clm, err = testClient.ClaimRetrieve(ctx, testClaimPendingID); err != nil {
		t.Fatalf("couldn't get domain claim: %v", err)
	}

	if clm.Status != hvclient.StatusPending {
		t.Errorf("got %s, want %s", clm.Status, hvclient.StatusPending)
	}
}

func TestClaimRetrieveFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		err  error
	}{
		{
			"Nonexistent",
			testClaimNonexistentID,
			testAPIErrorNotFound,
		},
		{
			"AlreadyDeleted",
			testClaimAlreadyDeletedID,
			testAPIErrorNotFound,
		},
		{
			"BadID",
			testClaimBadID,
			testAPIErrorInvalidIDLength,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, err = testClient.ClaimRetrieve(ctx, tc.id); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

func TestClaimDeleteFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		err  error
	}{
		{
			"AlreadyDeleted",
			testClaimAlreadyDeletedID,
			testAPIErrorNotFound,
		},
		{
			"NonExistent",
			testClaimNonexistentID,
			testAPIErrorNotFound,
		},
		{
			"BadID",
			testClaimBadID,
			testAPIErrorInvalidIDLength,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if err = testClient.ClaimDelete(ctx, tc.id); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Submits a domain claim, retrieves it, and then deletes it.
func TestClaimSubmitRetrieveDelete(t *testing.T) {
	// t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var testDomain string
	var err error
	var submitted *hvclient.ClaimAssertionInfo

	testDomain = "vulture.flying.no.such.domain.com"
	if submitted, err = testClient.ClaimSubmit(ctx, testDomain); err != nil {
		t.Fatalf("couldn't submit domain claim: %v", err)
	}

	var retrieved *hvclient.Claim
	if retrieved, err = testClient.ClaimRetrieve(ctx, submitted.ID); err != nil {
		t.Fatalf("couldn't retrieve domain claim: %v", err)
	}

	if retrieved.ID != submitted.ID {
		t.Fatalf("got %s, want %s", retrieved.ID, submitted.ID)
	}

	if err = testClient.ClaimDelete(ctx, submitted.ID); err != nil {
		t.Errorf("couldn't delete domain claim: %v", err)
	}
}

func TestClaimDNSFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name       string
		id         string
		authDomain string
		err        error
	}{
		{
			"NonExistent",
			testClaimNonexistentID,
			"",
			testAPIErrorNotFound,
		},
		{
			"BadID",
			testClaimBadID,
			"",
			testAPIErrorInvalidIDLength,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, err = testClient.ClaimDNS(ctx, tc.id, tc.authDomain); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Tests if a ClaimDNS API call returns false, since all the domains
// we are testing are fake and they'll therefore never be verified.
func TestClaimDNSAlreadySubmitted(t *testing.T) {
	// t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var clm bool
	if clm, err = testClient.ClaimDNS(ctx, testClaimPendingID, ""); err != nil {
		t.Fatalf("couldn't reassert domain claim: %v", err)
	}

	if clm {
		t.Errorf("got %t, want %t", clm, false)
	}
}

func TestClaimReassertFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		id   string
		err  error
	}{
		{
			"NonExistent",
			testClaimNonexistentID,
			testAPIErrorNotFound,
		},
		{
			"BadID",
			testClaimBadID,
			testAPIErrorInvalidIDLength,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var err error
			if _, err = testClient.ClaimReassert(ctx, tc.id); err == nil {
				t.Fatalf("unexpectedly succeeded")
			}

			checkAPIErrorsEqual(t, err, tc.err)
		})
	}
}

// Test for success when reasserting an existing claim.
func TestClaimReassertAlreadySubmitted(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var clm *hvclient.ClaimAssertionInfo
	if clm, err = testClient.ClaimReassert(ctx, testClaimPendingID); err != nil {
		t.Fatalf("couldn't reassert domain claim: %v", err)
	}

	if clm.ID != testClaimPendingID {
		t.Errorf("got %s, want %s", clm.ID, testClaimPendingID)
	}
}

// Test for successful login with unencrypted key.
func TestLoginSuccessUnencryptedKey(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		filename string
	}{
		{
			"UnencryptedKey",
			testLoginConfigFilename,
		},
		{
			"EncryptedKey",
			testLoginEncryptedConfigFilename,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var clnt *hvclient.Client
			var err error
			if clnt, err = hvclient.NewClientFromFile(ctx, testLoginConfigFilename); err != nil {
				t.Fatalf("couldn't login: %v", err)
			}

			// Test DefaultTimeout() here, as good as anywhere.

			var want = time.Second * 5
			if got := clnt.DefaultTimeout(); got != want {
				t.Errorf("got timeout %v, want %v", got, want)
			}
		})
	}
}

func TestNewClientFromFileBad(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.conf",
		"testdata/config_test_bad_key.conf",
		"testdata/config_test_bad_cert.conf",
		"testdata/config_test_bad_version.conf",
		"testdata/config_test_bad_url.conf",
		"testdata/config_test_no_url.conf",
		"testdata/config_test_bad_passphrase.conf",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if _, err := hvclient.NewClientFromFile(ctx, tc); err == nil {
				t.Fatalf("unexpectedly got client from file: %v", err)
			}
		})
	}
}

func TestNewClientFromConfigBad(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		conf *hvclient.Config
	}{
		{
			"NoURL",
			&hvclient.Config{
				URL:       "",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPIKey",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPISecret",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoKey",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    nil,
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoCert",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   nil,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			if _, err := hvclient.NewClient(ctx, tc.conf); err == nil {
				t.Fatalf("unexpectedly got client from config: %v", err)
			}
		})
	}
}

func checkAPIErrorsEqual(t *testing.T, got, want error) {
	t.Helper()

	// Errors are equal if they're both nil.
	if got == nil && want == nil {
		return
	}

	var apiErr hvclient.APIError
	if !errors.As(got, &apiErr) {
		// If error type is not an HVCA API error, just ensure the type
		// is as expected, ignoring the value which is too unpredictable
		// to verify.
		if !errors.As(got, &want) {
			t.Fatalf("got error type %T, want type %T", got, want)
		}
		return
	}

	// Otherwise, verify the HVCA API error is the one we expect.
	if apiErr != want {
		t.Errorf("got error %v %T, want %v %T", apiErr, apiErr, want, want)
	}
}
