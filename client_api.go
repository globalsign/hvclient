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
	"net/url"
	"strings"
	"time"

	"github.com/globalsign/hvclient/internal/httputils"
)

// counter is a reponse body from any HVCA request which returns a
// single count.
type counter struct {
	Value int64 `json:"value"`
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
	endpointClaims                      = "/claims/domains"
	endpointClaimsDomains               = "/claims/domains"
	endpointCountersCertificatesIssued  = "/counters/certificates/issued"
	endpointCountersCertificatesRevoked = "/counters/certificates/revoked"
	endpointQuotasIssuance              = "/quotas/issuance"
	endpointStatsExpiring               = "/stats/expiring"
	endpointStatsIssued                 = "/stats/issued"
	endpointStatsRevoked                = "/stats/revoked"
	endpointTrustChain                  = "/trustchain"
	endpointPolicy                      = "/validationpolicy"
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
		endpointCertificates+"/"+url.QueryEscape(serialNumber),
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
		endpointCertificates+"/"+url.QueryEscape(serialNumber),
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
	var _, err = c.makeRequest(ctx, nil, path, http.MethodGet, nil, &count)
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
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsExpiring, page, perPage, notBefore, notAfter)
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
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsIssued, page, perPage, notBefore, notAfter)
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
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	return c.statsCommon(ctx, endpointStatsRevoked, page, perPage, notBefore, notAfter)
}

// statsCommon is the common method for all /stats endpoints.
func (c *Client) statsCommon(
	ctx context.Context,
	path string,
	page, perPage int,
	notBefore, notAfter time.Time,
) ([]CertMeta, int64, error) {
	var stats []CertMeta
	var r, err = c.makeRequest(
		ctx,
		nil,
		path+paginationString(page, perPage, notBefore, notAfter),
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

// paginationString builds a query string for paginated API requests.
func paginationString(
	page, perPage int,
	from, to time.Time,
) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("?page=%d", page))

	if perPage > 0 {
		builder.WriteString(fmt.Sprintf("&per_page=%d", perPage))
	}

	if !from.IsZero() {
		builder.WriteString(fmt.Sprintf("&from=%d", from.Unix()))
	}

	if !to.IsZero() {
		builder.WriteString(fmt.Sprintf("&to=%d", to.Unix()))
	}

	return builder.String()
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
		nil,
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
		nil,
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

// ClaimRetrieve returns the domain claim with the specified ID.
func (c *Client) ClaimRetrieve(ctx context.Context, id string) (*Claim, error) {
	var claim Claim
	var _, err = c.makeRequest(
		ctx,
		nil,
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

// ClaimDelete deletes the domain claim with the specified ID.
func (c *Client) ClaimDelete(ctx context.Context, id string) error {
	var _, err = c.makeRequest(
		ctx,
		nil,
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
