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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

const (
	testConfigsEnvVar = "HVCLIENT_TEST_CONFIGS"
	testTimeout       = time.Second * 30
)

// In general, it is not feasible to test all functionality with live HVCA
// accounts, because it is neither reasonable nor efficient to expect all
// users to have available a set of test accounts that covers all possible
// configurations, and because some functionality (e.g. asserting control
// of a live, public domain) is simply not feasible to attempt in general
// purpose automated tests. Therefore, the objective of these integration
// tests is to provide at least one successful path through each client
// method, without attempting to exhaust all the possibilities.
//
// The environment variable HVCLIENT_TEST_CONFIGS should contain a list of
// test configuration files separated by semicolon (';') characters.

// TestCertificates requests a set of new certificates and revokes one of
// them, and then verifies that other certificate-related requests such as
// counters and statistics return consistent results. An ephemeral private
// key will be generated according to the requirements of the validation
// policy. Each test account must be capable of successfully handling a
// certificate request containing just a common name of "testsubject".
func TestCertificates(t *testing.T) {
	t.Parallel()

	const commonName = "testsubject"
	const numCerts = 2

	for _, cfg := range getTestConfigs(t) {
		var cfg = cfg

		t.Run(filepath.Base(cfg), func(t *testing.T) {
			t.Parallel()

			var ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var client, err = hvclient.NewClientFromFile(ctx, cfg)
			if err != nil {
				t.Fatalf("failed to create new client from file: %v", err)
			}

			// Retrieve issuance quota, and test it by verifying it's adequate
			// for the proposed tests.
			var quota int64
			quota, err = client.QuotaIssuance(ctx)
			if err != nil {
				t.Fatalf("failed to retrieve issuance quota: %v", err)
			}

			if quota < numCerts {
				t.Fatalf("remaining issuance quota of %d certificate insufficient for test", quota)
			}

			// Retrieve the trust chain certificates and use them to build a set
			// of verify options, so we can verify the certificates we receive.
			var trustChain []*x509.Certificate
			trustChain, err = client.TrustChain(ctx)
			if err != nil {
				t.Fatalf("failed to retrieve trust chain: %v", err)
			}

			var opts = x509.VerifyOptions{
				Intermediates: x509.NewCertPool(),
				Roots:         x509.NewCertPool(),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			}

			for _, cert := range trustChain {
				if !cert.IsCA {
					continue
				}

				if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
					opts.Roots.AddCert(cert)
				} else {
					opts.Intermediates.AddCert(cert)
				}
			}

			// Retrieve validation policy, and generate an ephemeral private
			// key of the appropriate type and length that we'll use for making
			// the certificate requests.
			var pol *hvclient.Policy
			pol, err = client.Policy(ctx)
			if err != nil {
				t.Fatalf("failed to retrieve validation policy: %v", err)
			}

			var key, pub = generateTestKey(t, pol)

			// Generate a certificate request object.
			var req = &hvclient.Request{
				Validity: &hvclient.Validity{
					NotAfter: time.Unix(0, 0),
				},
				Subject: &hvclient.DN{CommonName: "testsubject"},
			}

			// Add a public key, a private key, or a CSR to the request,
			// depending on what the validation policy requires.
			switch pol.PublicKey.KeyFormat {
			case hvclient.PKCS8:
				switch pol.PublicKeySignature {
				case hvclient.Optional, hvclient.Required:
					req.PrivateKey = key

				case hvclient.Forbidden:
					req.PublicKey = pub
				}

			case hvclient.PKCS10:
				req.CSR = generateCSR(t, key, commonName)
			}

			var startTime = time.Now()

			// Request and retrieve some certificates.
			var certs = make([]*x509.Certificate, numCerts)
			for i := range certs {
				req.Validity.NotBefore = time.Now()

				// Request certificate.
				var serialNumber *big.Int
				serialNumber, err = client.CertificateRequest(ctx, req)
				if err != nil {
					t.Fatalf("failed to request certificate: %v", err)
				}

				// Retrieve it.
				var info *hvclient.CertInfo
				info, err = client.CertificateRetrieve(ctx, serialNumber)
				if err != nil {
					t.Fatalf("failed to retrieve certificate: %v", err)
				}

				// Verify the serial number in the certificate we received
				// is indeed the one we were expecting.
				if serialNumber.Cmp(info.X509.SerialNumber) != 0 {
					t.Fatalf("got serial number %x, want %x", serialNumber, info.X509.SerialNumber)
				}

				// Verify status and updated at time.
				if info.Status != hvclient.StatusIssued {
					t.Fatalf("got status %v, want %v", info.Status, hvclient.StatusIssued)
				}

				if info.UpdatedAt.Sub(startTime) < time.Second*-1 {
					t.Fatalf("unexpected claim created at time: %v", info.UpdatedAt)
				}

				// Verify the certificate against the trust chain we retrieved
				// earlier.
				_, err = info.X509.Verify(opts)
				if err != nil {
					t.Fatalf("failed to verify certificate against trust chain: %v", err)
				}

				certs[i] = info.X509
			}

			// Revoke the first certificate we requested.
			err = client.CertificateRevoke(ctx, certs[0].SerialNumber)
			if err != nil {
				t.Fatalf("failed to revoke certificate: %v", err)
			}

			// Check the counters are at least great enough to reflect the
			// operations we just performed. Since the counters are cumulative
			// values specific to each individual HVCA account, this is the best
			// we can realistically do.
			var count int64
			count, err = client.CounterCertsIssued(ctx)
			if err != nil {
				t.Fatalf("failed to get counter of certificates issued: %v", err)
			}

			if count < numCerts {
				t.Fatalf("got issued count %d, want >= %d", count, numCerts)
			}

			count, err = client.CounterCertsRevoked(ctx)
			if err != nil {
				t.Fatalf("failed to get counter of certificates revoked: %v", err)
			}

			if count < 1 {
				t.Fatalf("got issued count %d, want >= %d", count, 1)
			}

			// Wait a few seconds for the statistics to be recorded, and then
			// verify that the operations we just performed can be retrieved.
			// From observation, a delay of 5 seconds appears to be reliably
			// sufficient. Anything shorts seems to sometimes result in errors.
			time.Sleep(time.Second * 5)

			// Verify the statistics for certificates issued include all the
			// certificates we just issued.
			var from = certs[0].NotBefore.Add(time.Second * -1)
			var to = certs[numCerts-1].NotBefore.Add(time.Second)
			var stats []hvclient.CertMeta
			stats, count, err = client.StatsIssued(ctx, 1, 100, from, to)
			if err != nil {
				t.Fatalf("failed to get statistics for certificates issued: %v", err)
			}
			verifyCertsInStats(t, certs, stats)

			if count < numCerts {
				t.Fatalf("got count %d, want >= %d", count, numCerts)
			}

			// Verify statistics for certificates revoked include the certificate
			// we just revoked.
			stats, count, err = client.StatsRevoked(ctx, 1, 100, from, time.Now())
			if err != nil {
				t.Fatalf("failed to get statistics for certificates revoked: %v", err)
			}
			verifyCertsInStats(t, certs[0:1], stats)

			if count < 1 {
				t.Fatalf("got count %d, want >= %d", count, 1)
			}

			// Verify statistics for certificates expiring include all the
			// certificates we just issued.
			from = certs[0].NotAfter.Add(time.Second * -1)
			to = certs[numCerts-1].NotAfter.Add(time.Second)
			stats, count, err = client.StatsExpiring(ctx, 1, 100, from, to)
			if err != nil {
				t.Fatalf("failed to get statistics for certificates expiring: %v", err)
			}
			verifyCertsInStats(t, certs, stats)

			if count < numCerts {
				t.Fatalf("got count %d, want >= %d", count, numCerts)
			}
		})
	}
}

// TestClaims submits a domain claim for a randomly generated domain,
// retrieves it, reasserts it, asserts (falsely) ownership of the domain
// via DNS, and finally deletes the claim.
func TestClaims(t *testing.T) {
	t.Parallel()

	var startTime = time.Now()

	for _, cfg := range getTestConfigs(t) {
		var cfg = cfg

		t.Run(filepath.Base(cfg), func(t *testing.T) {
			t.Parallel()

			var ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
			defer cancel()

			var client, err = hvclient.NewClientFromFile(ctx, cfg)
			if err != nil {
				t.Fatalf("failed to create new client from file: %v", err)
			}

			var testDomain = strings.ToLower(testhelpers.MustMakeRandomIdentifier(t, 8)) + ".com."

			// Submit new claim and verify the response contents.
			var info *hvclient.ClaimAssertionInfo
			info, err = client.ClaimSubmit(ctx, testDomain)
			if err != nil {
				t.Fatalf("failed to submit domain claim: %v", err)
			}
			defer func() {
				// Defer deletion of claim, to try to ensure we clean
				// up after ourselves. Use a different context in case the
				// original one has expired.
				var ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
				defer cancel()

				var err = client.ClaimDelete(ctx, info.ID)
				if err != nil {
					t.Fatalf("failed to submit domain claim: %v", err)
				}
			}()

			if info.ID == "" {
				t.Fatal("unexpectedly received empty ID")
			}

			if info.Token == "" {
				t.Fatal("unexpectedly received empty token")
			}

			if info.AssertBy.Sub(startTime) < time.Second*-1 {
				t.Fatalf("unexpected claim assert by time: %v", info.AssertBy)
			}

			// Retrieve the claim and verify the contents.
			var claim *hvclient.Claim
			claim, err = client.ClaimRetrieve(ctx, info.ID)
			if err != nil {
				t.Fatalf("failed to retrieve claim: %v", err)
			}

			if claim.ID != info.ID {
				t.Fatalf("got ID %s, want %s", claim.ID, info.ID)
			}

			if claim.Status != hvclient.StatusPending {
				t.Fatalf("got status %s, want %s", claim.Status, hvclient.StatusPending)
			}

			if claim.Domain != testDomain {
				t.Fatalf("got domain %s, want %s", claim.Domain, testDomain)
			}

			if claim.CreatedAt.Sub(startTime) < time.Second*-1 {
				t.Fatalf("unexpected claim created at time: %v", claim.CreatedAt)
			}

			// Expires at time can be zero.
			if !claim.ExpiresAt.Equal(time.Unix(0, 0)) && claim.ExpiresAt.Sub(startTime) < time.Second*-1 {
				t.Fatalf("unexpected claim expires at time: %v", claim.ExpiresAt)
			}

			if claim.AssertBy.Sub(startTime) < time.Second*-1 {
				t.Fatalf("unexpected claim assert by time: %v", claim.AssertBy)
			}

			// Retrieve claim domains and look for the one we just added. We
			// apply a maximum limit of 1,000 domains to avoid the test taking
			// too much time.
			var found bool
		outerLoop:
			for i := 1; i <= 10; i++ {
				var claims, count, err = client.ClaimsDomains(ctx, i, 100, hvclient.StatusPending)
				if err != nil {
					t.Fatalf("failed to retrieve claims domains: %v", err)
				}

				if count == 0 {
					t.Fatal("claims domains count unexpectedly zero")
				}

				// Break if there are no more domains to examine.
				if len(claims) == 0 {
					break
				}

				// Look for our claim.
				for _, element := range claims {
					if element.ID == claim.ID {
						found = true
						break outerLoop
					}
				}
			}

			if !found {
				t.Fatalf("failed to find claim with ID %s in claims domains", claim.ID)
			}

			// Reassert the claim and verify the response contents.
			var reinfo *hvclient.ClaimAssertionInfo
			reinfo, err = client.ClaimReassert(ctx, claim.ID)
			if err != nil {
				t.Fatalf("failed to reassert claim with ID %s", claim.ID)
			}

			if reinfo.ID != claim.ID {
				t.Fatalf("got ID %s, want %s", reinfo.ID, claim.ID)
			}

			if info.Token == "" {
				t.Fatal("unexpectedly received empty token")
			}

			if info.AssertBy.Sub(startTime) < time.Second*-1 {
				t.Fatalf("unexpected claim assert by time: %v", info.AssertBy)
			}

			// Assert (falsely) ownership with DNS method.
			var verified bool
			verified, err = client.ClaimDNS(ctx, claim.ID, testDomain)
			if err != nil {
				t.Fatalf("failed to assert ownership: %v", err)
			}

			if verified {
				t.Fatal("ownership unexpectedly verified")
			}
		})
	}
}

// verifyCertsInStats verifies that all the certificates in certs have a
// corresponding entry (by serial number) in stats.
func verifyCertsInStats(t *testing.T, certs []*x509.Certificate, stats []hvclient.CertMeta) {
	t.Helper()

	for _, cert := range certs {
		var found = false

		for _, stat := range stats {
			if cert.SerialNumber.Cmp(stat.SerialNumber) == 0 {
				found = true
				break
			}
		}

		if !found {
			t.Fatalf("failed to find certificate with serial number %X in statistics", cert.SerialNumber)
		}
	}
}

// generateCSR generates a CSR containing just a common name with the provided
// key,
func generateCSR(
	t *testing.T,
	key interface{},
	commonName string,
) *x509.CertificateRequest {
	t.Helper()

	var der, err = x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}},
		key,
	)
	if err != nil {
		t.Fatalf("failed to create certificate request: %v", err)
	}

	var csr *x509.CertificateRequest
	csr, err = x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("failed to parse certificate request: %v", err)
	}

	return csr
}

// generateTestKey generates a random private key of the appropriate type and
// of the smallest allowed length specified by a validation policy. The public
// component is also returned.
func generateTestKey(t *testing.T, pol *hvclient.Policy) (interface{}, interface{}) {
	t.Helper()

	var keypol = pol.PublicKey

	if keypol == nil {
		t.Fatal("no public key policy in validation policy")
	}

	if len(keypol.AllowedLengths) == 0 {
		t.Fatal("no allowed public key lengths in validation policy")
	}

	// Sort allowed key lengths so we can select the smallest one for efficiency.
	sort.Sort(sort.IntSlice(keypol.AllowedLengths))

	switch keypol.KeyType {
	case hvclient.RSA:
		var key, err = rsa.GenerateKey(rand.Reader, keypol.AllowedLengths[0])
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		return key, key.Public()

	case hvclient.ECDSA:
		// Find the smallest allowed key length for which we have a
		// supported curve.
		var curve elliptic.Curve
		for _, length := range keypol.AllowedLengths {
			switch length {
			case 224:
				curve = elliptic.P224()
			case 256:
				curve = elliptic.P256()
			case 384:
				curve = elliptic.P384()
			case 521:
				curve = elliptic.P521()
			}

			// Break out of the loop if we found a supported key length.
			if curve != nil {
				break
			}
		}

		if curve == nil {
			t.Fatalf("no supported ECDSA allowed key lengths: %v", keypol.AllowedLengths)
		}

		var key, err = ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate ECDSA key: %v", err)
		}

		return key, key.Public()

	default:
		t.Fatalf("unsupported public key type in validation policy: %d", keypol.KeyType)
	}

	panic("something went unexpectedly wrong")
}

// getTestConfig retrieves a list of HV client configuration files specified
// in an environment variable.
func getTestConfigs(t *testing.T) []string {
	t.Helper()

	var v, ok = os.LookupEnv(testConfigsEnvVar)
	if !ok {
		t.Skipf("environment variable %s not set", testConfigsEnvVar)
	}

	return strings.Split(v, ";")
}
