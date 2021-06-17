/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/globalsign/hvclient/internal/httputils"
)

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
	endpointCertificates = "/certificates"
	endpointClaims       = "/claims/domains"
	endpointCounters     = "/counters/certificates"
	endpointQuota        = "/quotas/issuance"
	endpointStats        = "/stats"
	endpointTrustChain   = "/trustchain"
	endpointPolicy       = "/validationpolicy"
)

// CertificateRequest requests a new certificate based on a Request object.
// The HVCA HTTP API is asynchronous, and on success this method returns the
// serial number of the certificate to be issued. After a short delay, the
// certificate itself may be retrieved via the CertificateRetrieve method.
func (c *Client) CertificateRequest(ctx context.Context, hvcareq *Request) (string, error) {
	var r, err = c.makeRequest(
		ctx,
		nil,
		endpointCertificates,
		http.MethodPost,
		hvcareq,
		nil,
	)
	if err != nil {
		return "", err
	}

	return basePathHeaderFromResponse(r, certSNHeaderName)
}

// CertificateRetrieve retrieves the certificate with the specified serial number.
func (c *Client) CertificateRetrieve(ctx context.Context, serialNumber string) (*CertInfo, error) {
	var r CertInfo
	var _, err = c.makeRequest(
		ctx,
		nil,
		endpointCertificates+"/"+serialNumber,
		http.MethodGet,
		nil,
		&r,
	)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// CertificateRevoke revokes the certificate with the specified serial number.
func (c *Client) CertificateRevoke(ctx context.Context, serialNumber string) error {
	var _, err = c.makeRequest(
		ctx,
		nil,
		endpointCertificates+"/"+serialNumber,
		http.MethodDelete,
		nil,
		nil,
	)
	return err
}

// TrustChain returns the chain of trust for the
// certificates issued by the calling account.
func (c *Client) TrustChain(ctx context.Context) ([]string, error) {
	var chain []string
	var _, err = c.makeRequest(
		ctx,
		nil,
		endpointTrustChain,
		http.MethodGet,
		nil,
		&chain,
	)
	if err != nil {
		return nil, err
	}

	return chain, nil
}

// Policy returns the calling account's validation policy.
func (c *Client) Policy(ctx context.Context) (*Policy, error) {
	var pol Policy
	var _, err = c.makeRequest(
		ctx,
		nil,
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
	return c.counter(ctx, newCounterCertsIssuedRequest())
}

// CounterCertsRevoked returns the number of certificates revoked
// by the calling account.
func (c *Client) CounterCertsRevoked(ctx context.Context) (int64, error) {
	return c.counter(ctx, newCounterCertsRevokedRequest())
}

// QuotaIssuance returns the remaining quota of certificate
// issuances for the calling account.
func (c *Client) QuotaIssuance(ctx context.Context) (int64, error) {
	return c.counter(ctx, newQuotaRequest())
}

func (c *Client) counter(ctx context.Context, r apiRequest) (int64, error) {
	var response, err = c.makeRequest(ctx, r, "", "", nil, nil)
	if err != nil {
		return 0, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return counterFromResponse(response)
}

// StatsExpiring returns a slice of the certificates which expired or which
// will expire during the specified time window, along with the total count
// of those certificates. The total count may be higher than the number of
// certificate in the slice if the total count is higher than the specified
// number of certificates per page. The HVCA API enforces a maximum number of
// certificates per page. If the total count is higher than the number of
// certificates in the slice, the remaining certificates may be retrieved
// by incrementing the page number in subsequent calls of this method.
func (c *Client) StatsExpiring(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.certsMeta(ctx, newStatsExpiringRequest(page, perPage, notBefore, notAfter))
}

// StatsIssued returns a slice of the certificates which were issued during
// the specified time window, along with the total count of those certificates.
// The total count may be higher than the number of certificate in the slice if
// the total count is higher than the specified number of certificates per
// page. The HVCA API enforces a maximum number of certificates per page. If
// the total count is higher than the number of certificates in the slice, the
// remaining certificates may be retrieved by incrementing the page number in
// subsequent calls of this method.
func (c *Client) StatsIssued(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.certsMeta(ctx, newStatsIssuedRequest(page, perPage, notBefore, notAfter))
}

// StatsRevoked returns a slice of the certificates which were revoked during
// the specified time window, along with the total count of those certificates.
// The total count may be higher than the number of certificate in the slice if
// the total count is higher than the specified number of certificates per
// page. The HVCA API enforces a maximum number of certificates per page. If
// the total count is higher than the number of certificates in the slice, the
// remaining certificates may be retrieved by incrementing the page number in
// subsequent calls of this method.
func (c *Client) StatsRevoked(
	ctx context.Context,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.certsMeta(ctx, newStatsRevokedRequest(page, perPage, notBefore, notAfter))
}

func (c *Client) certsMeta(ctx context.Context, r apiRequest) ([]CertMeta, int64, error) {
	var response, err = c.makeRequest(ctx, r, "", "", nil, nil)
	if err != nil {
		return nil, 0, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return certMetasFromResponse(response)
}

// ClaimsDomains returns a slice of either pending or verified domain claims
// along with the total count of domain claims in either category. The total
// count may be higher than the number of claims in the slice if the total
// count is higher than the specified number of claims per page. The HVCA API
// enforces a maximum number of claims per page. If the total count is higher
// than the number of claims in the slice, the remaining claims may be
// retrieved by incrementing the page number in subsequent calls of this
// method.
func (c *Client) ClaimsDomains(ctx context.Context, page, perPage int, status ClaimStatus) ([]Claim, int64, error) {
	var response, err = c.makeRequest(
		ctx,
		newClaimsDomainsRequest(page, perPage, status),
		"", "", nil,
		nil,
	)
	if err != nil {
		return nil, 0, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return claimsFromResponse(response)
}

// ClaimSubmit submits a new domain claim and returns the token value that
// should be used to verify control of that domain.
func (c *Client) ClaimSubmit(ctx context.Context, domain string) (*ClaimAssertionInfo, error) {
	var response, err = c.makeRequest(
		ctx,
		newClaimSubmitRequest(domain),
		"", "", nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return claimAssertionInfoFromResponse(response)
}

// ClaimRetrieve returns the domain claim with the specified ID.
func (c *Client) ClaimRetrieve(ctx context.Context, id string) (*Claim, error) {
	var response, err = c.makeRequest(
		ctx,
		newClaimRetrieveRequest(id),
		"", "", nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return claimFromResponse(response)
}

// ClaimDelete deletes the domain claim with the specified ID.
func (c *Client) ClaimDelete(ctx context.Context, id string) error {
	var response, err = c.makeRequest(
		ctx,
		newClaimDeleteRequest(id),
		"", "", nil,
		nil,
	)
	if err != nil {
		return err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return nil
}

// ClaimDNS requests assertion of domain control using DNS once the appropriate
// token has been placed in the relevant DNS records. A return value of false
// indicates that the assertion request was created. A return value of true
// indicates that domain control was verified.
func (c *Client) ClaimDNS(ctx context.Context, id string) (bool, error) {
	var response, err = c.makeRequest(
		ctx,
		newClaimDNSRequest(id),
		"", "", nil,
		nil,
	)
	if err != nil {
		return false, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	switch response.StatusCode {
	case http.StatusCreated:
		return false, nil
	case http.StatusNoContent:
		return true, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", response.StatusCode)
}

// ClaimReassert reasserts an existing domain claim, for example if the
// assert-by time of a previous assertion request has expired.
func (c *Client) ClaimReassert(ctx context.Context, id string) (*ClaimAssertionInfo, error) {
	var response, err = c.makeRequest(
		ctx,
		newClaimReassertRequest(id),
		"", "", nil,
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer httputils.ConsumeAndCloseResponseBody(response)

	return claimAssertionInfoFromResponse(response)
}
