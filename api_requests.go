/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"
)

// apiRequest represents an HVCA API call request generator. The exported
// API functions create a new API request object for each API call and pass it
// to Client.makeRequest. API request objects represent a single individual API
// call, and are not normally intended to be reused.
type apiRequest interface {
	// newHTTPRequest creates a new HTTP request for the particular API call.
	// Normally this method should only be called by Client.makeRequest.
	newHTTPRequest(url string) (*http.Request, error)
}

// certRequest represents an HVCA POST /certificates API call.
type certRequest struct {
	token string
	body  []byte
}

// certRetrieveRequest represents an HVCA GET /certificates/{certificate} API call.
type certRetrieveRequest struct {
	token        string
	serialNumber string
}

// certRevokeRequest represents an HVCA DELETE /certificates/{certificate} API call.
type certRevokeRequest struct {
	token        string
	serialNumber string
}

// counterCertsIssuedRequest represents an HVCA GET /counters/certificates/issued API call.
type counterCertsIssuedRequest struct {
	token string
}

// counterCertsRevokedRequest represents an HVCA GET /counters/certificates/revoked API call.
type counterCertsRevokedRequest struct {
	token string
}

// statsExpiringRequest represents an HVCA GET /stats/expiring API call.
type statsExpiringRequest struct {
	token   string
	page    int
	perPage int
	from    time.Time
	to      time.Time
}

// statsIssuedRequest represents an HVCA GET /stats/issued API call.
type statsIssuedRequest struct {
	token   string
	page    int
	perPage int
	from    time.Time
	to      time.Time
}

// statsRevokedRequest represents an HVCA GET /stats/revoked API call.
type statsRevokedRequest struct {
	token   string
	page    int
	perPage int
	from    time.Time
	to      time.Time
}

// quotaRequest represents an HVCA GET /quotas/issuance API call.
type quotaRequest struct {
	token string
}

// trustChainRequest represents an HVCA GET /trustchain API call.
type trustChainRequest struct {
	token string
}

// policyRequest represents an HVCA GET /validationpolicy API call.
type policyRequest struct {
	token string
}

// claimsDomainsRequest represents an HVCA GET /claims/domains API call.
type claimsDomainsRequest struct {
	token   string
	page    int
	perPage int
	status  ClaimStatus
}

// claimSubmitRequest represents an HVCA POST /claims/domains/{domain} API call.
type claimSubmitRequest struct {
	token  string
	domain string
}

// claimRetrieveRequest represents an HVCA GET claims/domains/{claimID} API call.
type claimRetrieveRequest struct {
	token string
	id    string
}

// claimDeleteRequest represents an HVCA DELETE /claims/domains/{claimID} API call.
type claimDeleteRequest struct {
	token string
	id    string
}

// claimDNSRequest represents an HVCA POST /claims/domains/{domain}/dns API call.
type claimDNSRequest struct {
	token string
	id    string
}

// claimReassertRequest represents an HVCA POST /claims/domains/{domain}/reassert API call.
type claimReassertRequest struct {
	token string
	id    string
}

// loginRequest represents an HVCA POST /login API call.
type loginRequest struct {
	body []byte
}

const (
	// HVCA API endpoints.
	endpointCertificates = "/certificates"
	endpointClaims       = "/claims/domains"
	endpointCounters     = "/counters/certificates"
	endpointLogin        = "/login"
	endpointQuota        = "/quotas/issuance"
	endpointStats        = "/stats"
	endpointTrustChain   = "/trustchain"
	endpointPolicy       = "/validationpolicy"
)

// newHTTPRequest creates an HTTP request for an HVCA POST /certificates API call.
func (r *certRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodPost,
		url+endpointCertificates,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /certificates/{certificate} API call.
func (r *certRetrieveRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointCertificates+"/"+r.serialNumber,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA DELETE /certificates/{certificate} API call.
func (r *certRevokeRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodDelete,
		url+endpointCertificates+"/"+r.serialNumber,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /counters/certificates/issued API call.
func (r *counterCertsIssuedRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointCounters+"/issued",
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /counters/certificates/revoked API call.
func (r *counterCertsRevokedRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointCounters+"/revoked",
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /stats/expiring API call.
func (r *statsExpiringRequest) newHTTPRequest(url string) (*http.Request, error) {
	url = fmt.Sprintf("%s%s/expiring?page=%d", url, endpointStats, r.page)

	if r.perPage > 0 {
		url += fmt.Sprintf("&per_page=%d", r.perPage)
	}

	if !r.from.IsZero() {
		url += fmt.Sprintf("&from=%d", r.from.Unix())
	}

	if !r.to.IsZero() {
		url += fmt.Sprintf("&to=%d", r.to.Unix())
	}

	return newHTTPRequest(
		http.MethodGet,
		url,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /stats/issued API call.
func (r *statsIssuedRequest) newHTTPRequest(url string) (*http.Request, error) {
	url = fmt.Sprintf("%s%s/issued?page=%d", url, endpointStats, r.page)

	if r.perPage > 0 {
		url += fmt.Sprintf("&per_page=%d", r.perPage)
	}

	if !r.from.IsZero() {
		url += fmt.Sprintf("&from=%d", r.from.Unix())
	}

	if !r.to.IsZero() {
		url += fmt.Sprintf("&to=%d", r.to.Unix())
	}

	return newHTTPRequest(
		http.MethodGet,
		url,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /stats/revoked API call.
func (r *statsRevokedRequest) newHTTPRequest(url string) (*http.Request, error) {
	url = fmt.Sprintf("%s%s/revoked?page=%d", url, endpointStats, r.page)

	if r.perPage > 0 {
		url += fmt.Sprintf("&per_page=%d", r.perPage)
	}

	if !r.from.IsZero() {
		url += fmt.Sprintf("&from=%d", r.from.Unix())
	}

	if !r.to.IsZero() {
		url += fmt.Sprintf("&to=%d", r.to.Unix())
	}

	return newHTTPRequest(
		http.MethodGet,
		url,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /quotas/issuance API call.
func (r *quotaRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointQuota,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /trustchain API call.
func (r *trustChainRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointTrustChain,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /validationpolicy API call.
func (r *policyRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointPolicy,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA GET /claims/domains API call.
func (r *claimsDomainsRequest) newHTTPRequest(url string) (*http.Request, error) {
	url = fmt.Sprintf("%s/claims/domains?status=%s&page=%d", url, r.status, r.page)

	if r.perPage > 0 {
		url += fmt.Sprintf("&per_page=%d", r.perPage)
	}

	return newHTTPRequest(
		http.MethodGet,
		url,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA POST /claims/domains/{domain} API call.
func (r *claimSubmitRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodPost,
		url+endpointClaims+"/"+r.domain,
		r,
	)
}

// newHTTPRequest creates an HTTP request for a GET HVCA claims/domains/{claimID} API call.
func (r *claimRetrieveRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodGet,
		url+endpointClaims+"/"+r.id,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA DELETE /claims/domains/{claimID} API call.
func (r *claimDeleteRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodDelete,
		url+endpointClaims+"/"+r.id,
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA POST /claims/domains/{domain}/dns API call.
func (r *claimDNSRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodPost,
		url+endpointClaims+"/"+r.id+"/dns",
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA POST /claims/domains/{domain}/reassert API call.
func (r *claimReassertRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodPost,
		url+endpointClaims+"/"+r.id+"/reassert",
		r,
	)
}

// newHTTPRequest creates an HTTP request for an HVCA POST /login API call.
func (r *loginRequest) newHTTPRequest(url string) (*http.Request, error) {
	return newHTTPRequest(
		http.MethodPost,
		url+endpointLogin,
		r,
	)
}

// newHTTPRequest encapsulates common functionality for creating HTTP requests for
// concrete request types. The method paramater should be one of GET, DELETE or POST.
// the url parameter should be the URL for the API call, excluding any required query
// string. The b parameter should be one of the Request objects provided by this package
// for each individual HVCA API call.
func newHTTPRequest(method, url string, b apiRequest) (*http.Request, error) {
	// Create an io.Reader containing the body of the request, if the request
	// contains a "body" field. If it doesn't create an io.Reader containing
	// the empty string.
	var body io.Reader
	if v := reflect.ValueOf(b).Elem().FieldByName("body"); v.IsValid() {
		body = bytes.NewReader(v.Bytes())
	} else {
		body = bytes.NewReader([]byte{})
	}

	// Create an http.Request object.
	var request, err = http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}

	return request, nil
}

// newCertRequest creates a new HVCA POST /certificates API call.
func newCertRequest(token string, body []byte) *certRequest {
	return &certRequest{
		token: token,
		body:  body,
	}
}

// newCertRetrieveRequest creates a new HVCA GET /certificates/{certificate} API call.
func newCertRetrieveRequest(token, serialNumber string) *certRetrieveRequest {
	return &certRetrieveRequest{token: token, serialNumber: serialNumber}
}

// newCertRevokeRequest creates a new HVCA DELETE /certificates/{certificate} API call.
func newCertRevokeRequest(token, serialNumber string) *certRevokeRequest {
	return &certRevokeRequest{
		token:        token,
		serialNumber: serialNumber,
	}
}

// newCounterCertsIssuedRequest creates a new HVCA GET /counters/certificates/issued API call.
func newCounterCertsIssuedRequest(token string) *counterCertsIssuedRequest {
	return &counterCertsIssuedRequest{
		token: token,
	}
}

// newCounterCertsRevokedRequest creates a new HVCA GET /counters/certificates/revoked API call.
func newCounterCertsRevokedRequest(token string) *counterCertsRevokedRequest {
	return &counterCertsRevokedRequest{
		token: token,
	}
}

// newStatsExpiringRequest creates a new HVCA GET /stats/expiring API call.
func newStatsExpiringRequest(token string, page, perPage int, from, to time.Time) *statsExpiringRequest {
	return &statsExpiringRequest{
		token:   token,
		page:    page,
		perPage: perPage,
		from:    from,
		to:      to,
	}
}

// newStatsIssuedRequest creates a new HVCA GET /stats/issued API call.
func newStatsIssuedRequest(token string, page, perPage int, from, to time.Time) *statsIssuedRequest {
	return &statsIssuedRequest{
		token:   token,
		page:    page,
		perPage: perPage,
		from:    from,
		to:      to,
	}
}

// newStatsRevokedRequest creates a new HVCA GET /stats/revoked API call.
func newStatsRevokedRequest(token string, page, perPage int, from, to time.Time) *statsRevokedRequest {
	return &statsRevokedRequest{
		token:   token,
		page:    page,
		perPage: perPage,
		from:    from,
		to:      to,
	}
}

// newQuotaRequest creates a new HVCA GET /quotas/issuance API call.
func newQuotaRequest(token string) *quotaRequest {
	return &quotaRequest{
		token: token,
	}
}

// newTrustChainRequest creates a new HVCA GET /trustchain API call.
func newTrustChainRequest(token string) *trustChainRequest {
	return &trustChainRequest{
		token: token,
	}
}

// newPolicyRequest creates a new HVCA GET /validationpolicy API call.
func newPolicyRequest(token string) *policyRequest {
	return &policyRequest{
		token: token,
	}
}

// newClaimsDomainsRequest creates a new HVCA GET /claims/domains API call.
func newClaimsDomainsRequest(token string, page, perPage int, status ClaimStatus) *claimsDomainsRequest {
	return &claimsDomainsRequest{
		token:   token,
		page:    page,
		perPage: perPage,
		status:  status,
	}
}

// newClaimSubmitRequest creates a new HVCA POST /claims/domains/{domain} API call.
func newClaimSubmitRequest(token, domain string) *claimSubmitRequest {
	return &claimSubmitRequest{
		token:  token,
		domain: domain,
	}
}

// newClaimRetrieveRequest creates a new HVCA claims/domains/{claimID} API call.
func newClaimRetrieveRequest(token, id string) *claimRetrieveRequest {
	return &claimRetrieveRequest{
		token: token,
		id:    id,
	}
}

// newClaimDeleteRequest creates a new HVCA DELETE /claims/domains/{claimID} API call.
func newClaimDeleteRequest(token, id string) *claimDeleteRequest {
	return &claimDeleteRequest{
		token: token,
		id:    id,
	}
}

// newClaimDNSRequest creates a new HVCA POST /claims/domains/{domain}/dns API call.
func newClaimDNSRequest(token, id string) *claimDNSRequest {
	return &claimDNSRequest{
		token: token,
		id:    id,
	}
}

// newClaimReassertRequest creates a new HVCA POST /claims/domains/{domain}/reassert API call.
func newClaimReassertRequest(token, id string) *claimReassertRequest {
	return &claimReassertRequest{
		token: token,
		id:    id,
	}
}

// newLoginRequest creates a new HVCA POST /login API call.
func newLoginRequest(key, secret string) *loginRequest {
	return &loginRequest{
		body: []byte(fmt.Sprintf(`{"api_key":"%s","api_secret":"%s"}`, key, secret)),
	}
}

// isLoginRequest checks if the provided request is a login request.
func isLoginRequest(req apiRequest) bool {
	if _, ok := req.(*loginRequest); !ok {
		return false
	}

	return true
}
