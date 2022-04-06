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

package hvclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"time"
)

// counter is a reponse body from any HVCA request which returns a
// single count.
type counter struct {
	Value int64 `json:"value"`
}

// claimsDNSRequest represents the body used for an HVCA request to assert domain control through DNS validation method
type claimsDNSRequest struct {
	AuthorizationDomain string `json:"authorization_domain,omitempty"`
}

// claimsHTTPRequest represents the body used for an HVCA request to assert domain control through HTTP validation method
type claimsHTTPRequest struct {
	AuthorizationDomain string `json:"authorization_domain,omitempty"`
	Scheme              string `json:"scheme"`
}

// claimsEmailRequest represents the body used for an HVCA request to assert domain control through Email validation method
type claimsEmailRequest struct {
	EmailAddress string `json:"email_address"`
}

const (
	// certSNHeaderName is the name of the HTTP header in which the
	// URL of a certificate can be found.
	certSNHeaderName = "Location"

	// claimLocationHeaderName is the name of the HTTP header in which the
	// URL of a claim can be found.
	claimLocationHeaderName = "Location"

	// totalCountHeaderName is the name of the HTTP header in which a total
	// count field can be found.
	totalCountHeaderName = "Total-Count"
)

// HVCA API endpoints.
const (
	endpointCertificates                = "/certificates"
	endpointClaimsDomains               = "/claims/domains"
	endpointCountersCertificatesIssued  = "/counters/certificates/issued"
	endpointCountersCertificatesRevoked = "/counters/certificates/revoked"
	endpointQuotasIssuance              = "/quotas/issuance"
	endpointStatsExpiring               = "/stats/expiring"
	endpointStatsIssued                 = "/stats/issued"
	endpointStatsRevoked                = "/stats/revoked"
	endpointTrustChain                  = "/trustchain"
	endpointPolicy                      = "/validationpolicy"
	pathReassert                        = "/reassert"
	pathDNS                             = "/dns"
	pathHTTP                            = "/http"
	pathEmail                           = "/email"
)

// CertificateRequest requests a new certificate based. The HVCA API is
// asynchronous, and on success this method returns the serial number of
// the new certificate. After a short delay, the certificate itself may be
// retrieved via the CertificateRetrieve method.
func (c *Client) CertificateRequest(
	ctx context.Context,
	req *Request,
) (*big.Int, error) {
	var r, err = c.makeRequest(
		ctx,
		endpointCertificates,
		http.MethodPost,
		req,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var snString string
	snString, err = basePathHeaderFromResponse(r, certSNHeaderName)
	if err != nil {
		return nil, err
	}

	var sn, ok = big.NewInt(0).SetString(snString, 16)
	if !ok {
		return nil, fmt.Errorf("invalid serial number returned: %s", snString)
	}

	return sn, nil
}

// CertificateRetrieve retrieves a certificate.
func (c *Client) CertificateRetrieve(
	ctx context.Context,
	serial *big.Int,
) (*CertInfo, error) {
	var r CertInfo
	var _, err = c.makeRequest(
		ctx,
		endpointCertificates+"/"+url.QueryEscape(fmt.Sprintf("%X", serial)),
		http.MethodGet,
		nil,
		&r,
	)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// CertificateRevoke revokes a certificate.
func (c *Client) CertificateRevoke(
	ctx context.Context,
	serial *big.Int,
) error {
	var _, err = c.makeRequest(
		ctx,
		endpointCertificates+"/"+url.QueryEscape(fmt.Sprintf("%X", serial)),
		http.MethodDelete,
		nil,
		nil,
	)
	return err
}

// TrustChain returns the chain of trust for the certificates issued
// by the calling account.
func (c *Client) TrustChain(ctx context.Context) ([]*x509.Certificate, error) {
	var chain []string
	var _, err = c.makeRequest(
		ctx,
		endpointTrustChain,
		http.MethodGet,
		nil,
		&chain,
	)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, enc := range chain {
		var block, rest = pem.Decode([]byte(enc))
		if block == nil {
			return nil, errors.New("invalid PEM in response")
		} else if len(rest) > 0 {
			return nil, errors.New("trailing data after PEM block in response")
		}

		var cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate in response: %w", err)
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

// Policy returns the calling account's validation policy.
func (c *Client) Policy(ctx context.Context) (*Policy, error) {
	var pol Policy
	var _, err = c.makeRequest(
		ctx,
		endpointPolicy,
		http.MethodGet,
		nil,
		&pol,
	)
	if err != nil {
		return nil, err
	}

	return &pol, nil
}

// CounterCertsIssued returns the number of certificates issued
// by the calling account.
func (c *Client) CounterCertsIssued(ctx context.Context) (int64, error) {
	return c.countersCommon(ctx, endpointCountersCertificatesIssued)
}

// CounterCertsRevoked returns the number of certificates revoked
// by the calling account.
func (c *Client) CounterCertsRevoked(ctx context.Context) (int64, error) {
	return c.countersCommon(ctx, endpointCountersCertificatesRevoked)
}

// QuotaIssuance returns the remaining quota of certificate
// issuances for the calling account.
func (c *Client) QuotaIssuance(ctx context.Context) (int64, error) {
	return c.countersCommon(ctx, endpointQuotasIssuance)
}

// countersCommon is the common method for all /counters and /quotas endpoints.
func (c *Client) countersCommon(
	ctx context.Context,
	path string,
) (int64, error) {
	var count counter
	var _, err = c.makeRequest(ctx, path, http.MethodGet, nil, &count)
	if err != nil {
		return 0, err
	}

	return count.Value, nil
}

// StatsExpiring returns a slice of the certificates which expired or which
// will expire during the specified time window, along with the total count
// of those certificates. The total count may be higher than the number of
// certificates in the slice if the total count is higher than the specified
// number of certificates per page. The HVCA API enforces a maximum number of
// certificates per page. If the total count is higher than the number of
// certificates in the slice, the remaining certificates may be retrieved
// by incrementing the page number in subsequent calls of this method.
func (c *Client) StatsExpiring(
	ctx context.Context,
	page, perPage int,
	from, to time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsExpiring, page, perPage, from, to)
}

// StatsIssued returns a slice of the certificates which were issued during
// the specified time window, along with the total count of those certificates.
// The total count may be higher than the number of certificates in the slice if
// the total count is higher than the specified number of certificates per
// page. The HVCA API enforces a maximum number of certificates per page. If
// the total count is higher than the number of certificates in the slice, the
// remaining certificates may be retrieved by incrementing the page number in
// subsequent calls of this method.
func (c *Client) StatsIssued(
	ctx context.Context,
	page, perPage int,
	from, to time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsIssued, page, perPage, from, to)
}

// StatsRevoked returns a slice of the certificates which were revoked during
// the specified time window, along with the total count of those certificates.
// The total count may be higher than the number of certificates in the slice if
// the total count is higher than the specified number of certificates per
// page. The HVCA API enforces a maximum number of certificates per page. If
// the total count is higher than the number of certificates in the slice, the
// remaining certificates may be retrieved by incrementing the page number in
// subsequent calls of this method.
func (c *Client) StatsRevoked(
	ctx context.Context,
	page, perPage int,
	from, to time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsRevoked, page, perPage, from, to)
}

// statsCommon is the common method for all /stats endpoints.
func (c *Client) statsCommon(
	ctx context.Context,
	path string,
	page, perPage int,
	from, to time.Time,
) ([]CertMeta, int64, error) {
	var stats []CertMeta
	var r, err = c.makeRequest(
		ctx,
		path+paginationString(page, perPage, from, to),
		http.MethodGet,
		nil,
		&stats,
	)
	if err != nil {
		return nil, 0, err
	}

	var count int64
	count, err = intHeaderFromResponse(r, totalCountHeaderName)
	if err != nil {
		return nil, 0, err
	}

	return stats, count, nil
}

// ClaimsDomains returns a slice of either pending or verified domain claims
// along with the total count of domain claims in either category. The total
// count may be higher than the number of claims in the slice if the total
// count is higher than the specified number of claims per page. The HVCA API
// enforces a maximum number of claims per page. If the total count is higher
// than the number of claims in the slice, the remaining claims may be
// retrieved by incrementing the page number in subsequent calls of this
// method.
func (c *Client) ClaimsDomains(
	ctx context.Context,
	page, perPage int,
	status ClaimStatus,
) ([]Claim, int64, error) {
	var claims []Claim
	var r, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+
			paginationString(page, perPage, time.Time{}, time.Time{})+
			fmt.Sprintf("&status=%s", status),
		http.MethodGet,
		nil,
		&claims,
	)
	if err != nil {
		return nil, 0, err
	}

	var count int64
	count, err = intHeaderFromResponse(r, totalCountHeaderName)
	if err != nil {
		return nil, 0, err
	}

	return claims, count, nil
}

// ClaimSubmit submits a new domain claim and returns the token value that
// should be used to verify control of that domain.
func (c *Client) ClaimSubmit(ctx context.Context, domain string) (*ClaimAssertionInfo, error) {
	var info ClaimAssertionInfo
	var r, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+"/"+url.QueryEscape(domain),
		http.MethodPost,
		nil,
		&info,
	)
	if err != nil {
		return nil, err
	}

	var location string
	location, err = basePathHeaderFromResponse(r, claimLocationHeaderName)
	if err != nil {
		return nil, err
	}

	info.ID = location

	return &info, nil
}

// ClaimRetrieve returns a domain claim.
func (c *Client) ClaimRetrieve(ctx context.Context, id string) (*Claim, error) {
	var claim Claim
	var _, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+"/"+url.QueryEscape(id),
		http.MethodGet,
		nil,
		&claim,
	)
	if err != nil {
		return nil, err
	}

	return &claim, nil
}

// ClaimDelete deletes a domain claim.
func (c *Client) ClaimDelete(ctx context.Context, id string) error {
	var _, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+"/"+url.QueryEscape(id),
		http.MethodDelete,
		nil,
		nil,
	)
	return err
}

// ClaimDNS requests assertion of domain control using DNS once the appropriate
// token has been placed in the relevant DNS records. A return value of false
// indicates that the assertion request was created. A return value of true
// indicates that domain control was verified.
func (c *Client) ClaimDNS(ctx context.Context, id, authDomain string) (bool, error) {
	var body interface{}
	// The HVCA API documentation indicates that the request body is
	// required, but practice suggests that it is not. The request does
	// definitely fail if the empty string is provided as the authorization
	// domain, however, so we'll only include the body in the request if
	// an authorization domain was provided.
	//
	if authDomain != "" {
		body = claimsDNSRequest{AuthorizationDomain: authDomain}
	}

	return c.claimAssert(ctx, body, id, pathDNS)
}

// ClaimHTTP requests assEmailertion of domain control using HTTP once the appropriate
// token has been placed at the expected path. A return value of false
// indicates that the assertion request was created. A return value of true
// indicates that domain control was verified.
func (c *Client) ClaimHTTP(ctx context.Context, id, authDomain, scheme string) (bool, error) {
	var body = claimsHTTPRequest{
		AuthorizationDomain: authDomain,
		Scheme:              scheme,
	}

	return c.claimAssert(ctx, body, id, pathHTTP)
}

// ClaimEmail requests assertion of domain control using Email once the appropriate
// token has been placed at the expected path. A return value of false
// indicates that the assertion request was created. A return value of true
// indicates that domain control was verified.
func (c *Client) ClaimEmail(ctx context.Context, id, emailAddress string) (bool, error) {
	var body = claimsEmailRequest{
		EmailAddress: emailAddress,
	}

	return c.claimAssert(ctx, body, id, pathEmail)
}

// ClaimReassert reasserts an existing domain claim, for example if the
// assert-by time of a previous assertion request has expired.
func (c *Client) ClaimReassert(ctx context.Context, id string) (*ClaimAssertionInfo, error) {
	var info ClaimAssertionInfo
	var r, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+"/"+url.QueryEscape(id)+pathReassert,
		http.MethodPost,
		nil,
		&info,
	)
	if err != nil {
		return nil, err
	}

	var location string
	location, err = basePathHeaderFromResponse(r, claimLocationHeaderName)
	if err != nil {
		return nil, err
	}

	info.ID = location

	return &info, err
}

func (c *Client) claimAssert(ctx context.Context, body interface{}, id, path string) (bool, error) {
	var response, err = c.makeRequest(
		ctx,
		endpointClaimsDomains+"/"+url.QueryEscape(id)+path,
		http.MethodPost,
		body,
		nil,
	)
	if err != nil {
		return false, err
	}

	switch response.StatusCode {
	case http.StatusCreated:
		return false, nil
	case http.StatusNoContent:
		return true, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", response.StatusCode)
}
