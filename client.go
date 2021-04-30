/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Client is a fully-featured client through which HVCA API calls can be made.
//
// A client is created from either a configuration object or a configuration
// file containing the account and other information. Once a client is
// created, it can then be used to make HVCA API calls.
//
// The user does not need to explicitly login. The client object will log the
// user in automatically, and refresh their login if the authentication token
// expires. In the event of a HTTP 503 service unavailable response, or a
// response indicating that a request has been accepted but the corresponding
// resource is not yet available, the client will automatically wait and retry
// the call a predetermined number of times. The maximum wait time for this
// process may be controlled through the context passed to each API call.
//
// It is safe to make concurrent API calls from a single client object.
type Client struct {
	config       *Config
	url          *url.URL
	loginRequest *loginRequest
	httpClient   *http.Client
	token        string
	lastLoggedIn time.Time
	loginMutex   sync.RWMutex
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

	// numberOfRetries is the number of times to retry a request.
	numberOfRetries = 5
)

var (

	// priorLoginDelay is the amount of time for which we can assume a prior
	// login is still valid. If a token expires and another login attempt is
	// made, and we check the last login time and find that it was less than
	// this time interval in the past, then we assume that another routine
	// logged in again between the time we discovered our token was expired,
	// and the time we attempted our login, and so we abandon our new login
	// attempt as unnecessary.
	priorLoginDelay = time.Minute

	// Initial time to wait before retrying. Subsequent retries will be more
	// widely spacesd
	retryWaitDuration = time.Second
)

// retryErrors is a list of errors upon receiving which we should retry a
// request.
var retryErrors = [...]APIError{
	APIError{StatusCode: 503, Description: "Service busy, please retry later"},
	APIError{StatusCode: 202, Description: "Operation in Progress"},
}

// CertificateRequest requests a new certificate based on a Request object.
// The HVCA HTTP API is asynchronous, and on success this method returns the
// serial number of the certificate to be issued. After a short delay, the
// certificate itself may be retrieved via the CertificateRetrieve method.
func (c *Client) CertificateRequest(ctx context.Context, hvcareq *Request) (string, error) {
	var err error

	// Marshal certificate request.

	var body []byte
	if body, err = json.Marshal(hvcareq); err != nil {
		return "", err
	}

	// Make API call.

	var response *http.Response
	if response, err = c.makeRequest(
		ctx,
		newCertRequest(c.readLoginToken(), body),
	); err != nil {
		return "", err
	}
	defer response.Body.Close()

	// Return base path from HTTP header in response.

	return basePathHeaderFromResponse(response, certSNHeaderName)
}

// CertificateRetrieve retrieves the certificate with the specified serial number.
func (c *Client) CertificateRetrieve(ctx context.Context, serialNumber string) (*CertInfo, error) {
	var response *http.Response
	var err error

	// Make API call.

	if response, err = c.makeRequest(
		ctx,
		newCertRetrieveRequest(c.readLoginToken(), serialNumber),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	// Return certificate and additional information.

	return certInfoFromResponse(response)
}

// CertificateRevoke revokes the certificate with the specified serial number.
func (c *Client) CertificateRevoke(ctx context.Context, serialNumber string) error {
	var response *http.Response
	var err error

	// Make API call.

	if response, err = c.makeRequest(
		ctx,
		newCertRevokeRequest(c.readLoginToken(), serialNumber),
	); err != nil {
		return err
	}
	response.Body.Close()

	// No return value for this API call.

	return nil
}

// TrustChain returns the chain of trust for the
// certificates issued by the calling account.
func (c *Client) TrustChain(ctx context.Context) ([]string, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newTrustChainRequest(c.readLoginToken()),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return stringSliceFromResponse(response)
}

// Policy returns the calling account's validation policy.
func (c *Client) Policy(ctx context.Context) (*Policy, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newPolicyRequest(c.readLoginToken()),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return policyFromResponse(response)
}

// CounterCertsIssued returns the number of certificates issued
// by the calling account.
func (c *Client) CounterCertsIssued(ctx context.Context) (int64, error) {
	return c.counter(ctx, newCounterCertsIssuedRequest(c.readLoginToken()))
}

// CounterCertsRevoked returns the number of certificates revoked
// by the calling account.
func (c *Client) CounterCertsRevoked(ctx context.Context) (int64, error) {
	return c.counter(ctx, newCounterCertsRevokedRequest(c.readLoginToken()))
}

// QuotaIssuance returns the remaining quota of certificate
// issuances for the calling account.
func (c *Client) QuotaIssuance(ctx context.Context) (int64, error) {
	return c.counter(ctx, newQuotaRequest(c.readLoginToken()))
}

func (c *Client) counter(ctx context.Context, r apiRequest) (int64, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(ctx, r); err != nil {
		return 0, err
	}
	defer response.Body.Close()

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
	return c.certsMeta(ctx, newStatsExpiringRequest(c.readLoginToken(), page, perPage, notBefore, notAfter))
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
	return c.certsMeta(ctx, newStatsIssuedRequest(c.readLoginToken(), page, perPage, notBefore, notAfter))
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
	return c.certsMeta(ctx, newStatsRevokedRequest(c.readLoginToken(), page, perPage, notBefore, notAfter))
}

func (c *Client) certsMeta(ctx context.Context, r apiRequest) ([]CertMeta, int64, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(ctx, r); err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

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
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimsDomainsRequest(c.readLoginToken(), page, perPage, status),
	); err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	return claimsFromResponse(response)
}

// ClaimSubmit submits a new domain claim and returns the token value that
// should be used to verify control of that domain.
func (c *Client) ClaimSubmit(ctx context.Context, domain string) (*ClaimAssertionInfo, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimSubmitRequest(c.readLoginToken(), domain),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return claimAssertionInfoFromResponse(response)
}

// ClaimRetrieve returns the domain claim with the specified ID.
func (c *Client) ClaimRetrieve(ctx context.Context, id string) (*Claim, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimRetrieveRequest(c.readLoginToken(), id),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return claimFromResponse(response)
}

// ClaimDelete deletes the domain claim with the specified ID.
func (c *Client) ClaimDelete(ctx context.Context, id string) error {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimDeleteRequest(c.readLoginToken(), id),
	); err != nil {
		return err
	}
	response.Body.Close()

	return nil
}

// ClaimDNS requests assertion of domain control using DNS once the appropriate
// token has been placed in the relevant DNS records. A return value of false
// indicates that the assertion request was created. A return value of true
// indicates that domain control was verified.
func (c *Client) ClaimDNS(ctx context.Context, id string) (bool, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimDNSRequest(c.readLoginToken(), id),
	); err != nil {
		return false, err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case 201:
		return false, nil
	case 204:
		return true, nil
	}

	return false, fmt.Errorf("unexpected status code: %d", response.StatusCode)
}

// ClaimReassert reasserts an existing domain claim, for example if the
// assert-by time of a previous assertion request has expired.
func (c *Client) ClaimReassert(ctx context.Context, id string) (*ClaimAssertionInfo, error) {
	var response *http.Response
	var err error

	if response, err = c.makeRequest(
		ctx,
		newClaimReassertRequest(c.readLoginToken(), id),
	); err != nil {
		return nil, err
	}
	defer response.Body.Close()

	return claimAssertionInfoFromResponse(response)
}

/*
login logs into the HVCA server.

The HVCA system requires an account to login with an API key and API secret, and returns a
token. All subsequent API calls must provide a valid token from a previous login.

Because each login generates a new token, it is not possible to login for every API call,
because in the time between generating the HTTP request including the token and the HVCA
system processing the request, another request for the same account may have logged in and
invalidated the first token.

Since logging in also takes some time, it is undesirable, as well as not possible, to login
for every API call.

It is therefore desirable to login once, retrieve the login token, and then use that token
for all subsequent API calls. This creates two problems to solve:

1. The token expires after a period of time, so subsequent logins may be required; and

2. We would like to be able to make concurrent API calls using the same login, so we need
to efficiently synchronize access to the login token.

Because of familiar TOCTTOU problems, it is not feasible to check if we are logged in before
making an API call, because the token may expire after we check but before we make the API call.
Therefore our strategy is to let the API call fail, login again, and try the call a second time.
This strategy is transparent to the user of the library.

Again, because of TOCTTOU problems, it is possible that between the time an API call fails and its
login attempt, another concurrent call may also have failed and logged in again, retrieving a new but
different authentication token. Therefore we store the time of the last login, and check it whenever
we attempt to login. If the previous request was made within the last minute (the token will not expire
during such a short time period) then we refrain from logging in, and simply return to retry the API call.

To solve the second problem, we synchonize access to the login token (and to the last logged-in time)
with a read-write lock. Checking the last logged-in time and retrieving the value of the current
login token are done by acquiring a read lock, and a write lock is acquired only when we actually
need to login.

Note that only the login token and the last login time need to be synchronized. All the other members
of the Client struct are read-only, and an *http.Client is safe to use concurrently according to the
documentation.
*/
func (c *Client) login(ctx context.Context) error {
	// Check if the last login was later then a predetermined duration ago.
	// If it was, then assume the token from that login is still valid and
	// return without doing anything. A read lock is adequate for this.

	c.loginMutex.RLock()
	if time.Now().Sub(c.lastLoggedIn) < priorLoginDelay {
		c.loginMutex.RUnlock()
		return nil
	}
	c.loginMutex.RUnlock()

	// Last login was earlier than a predetermnined duration ago, so we need
	// to log in again, for which we need a write lock.

	c.loginMutex.Lock()
	defer c.loginMutex.Unlock()

	// It's possible another thread grabbed the write lock after we released the
	// read lock, and logged us in, so we need to check the last login time again.

	if time.Now().Sub(c.lastLoggedIn) < priorLoginDelay {
		return nil
	}

	// Login to HVCA.

	var err error
	var response *http.Response

	if response, err = c.makeRequest(ctx, c.loginRequest); err != nil {

		// Zero-out the token and last login time in case of error.

		c.token = ""
		c.lastLoggedIn = time.Time{}

		return err
	}
	defer response.Body.Close()

	if c.token, err = tokenFromResponse(response); err != nil {

		// Zero-out the token and last login time in case of error.

		c.token = ""
		c.lastLoggedIn = time.Time{}

		return err
	}

	c.lastLoggedIn = time.Now()

	return nil
}

// readLoginToken performs a synchronized read of the login token.
func (c *Client) readLoginToken() string {
	c.loginMutex.RLock()
	defer c.loginMutex.RUnlock()

	return c.token
}

// makeRequest sends an API request to the HVCA server.
func (c *Client) makeRequest(ctx context.Context, req apiRequest) (*http.Response, error) {
	var err error
	var retriesRemaining = numberOfRetries

	var response *http.Response

	for {
		var request *http.Request

		if request, err = req.newHTTPRequest(c.url.String()); err != nil {
			return nil, err
		}

		request = request.WithContext(ctx)

		if response, err = c.httpClient.Do(request); err != nil {
			return nil, err
		}

		// HVCA doesn't return any 3XX HTTP status codes, so treat everything outside
		// of the 2XX range as an error.

		if response.StatusCode < 200 || response.StatusCode > 299 || response.StatusCode == 202 {
			var apiErr = newAPIError(response)

			if isExpiredTokenError(apiErr) {

				// Token from previous login has expired, so login again, update the
				// request with the new login token, and try again.

				if isLoginRequest(req) {
					// The /login endpoint shouldn't return either of the
					// errors that would cause this path to execute, but we
					// have no guarantee of that, so guard against the deadlock
					// that would occur if a login request failed with one of
					// these errors and c.login was called recursively.

					return nil, errors.New("recursive login request")
				}

				c.login(ctx)
				req.updateToken(c.readLoginToken())

				continue
			} else if shouldRetry(apiErr) && retriesRemaining > 0 {

				// Service is (hopefully temporarily) unavailable, or response is otherwise temporarily
				// delayed, so pause for a predetermined amount of time, decrement the number of remaining
				// retries, and try again, progressively increasing the wait time.

				retriesRemaining--
				time.Sleep(retryWaitDuration * time.Duration((numberOfRetries - retriesRemaining)))

				continue
			}
			response.Body.Close()

			return nil, apiErr
		}

		// No errors, so break from the loop.

		break
	}

	return response, nil
}

// DefaultTimeout returns the timeout specified in the configuration object or
// file used to create the client, or the default timeout provided if no value
// was specified. This is useful for honoring the timeout requested by the
// configuration when creating the context to pass to an API method if the
// original configuration information is no longer available.
func (c *Client) DefaultTimeout() time.Duration {
	return c.config.Timeout
}

// shouldRetry returns true if we should retry the request after an error or
// other condition.
func shouldRetry(err APIError) bool {
	for _, retryError := range retryErrors {
		if err == retryError {
			return true
		}
	}

	return false
}

// NewClient creates a new HVCA client from a configuration object. An initial
// login is made, and the returned client is immediately ready to make API
// calls.
func NewClient(ctx context.Context, conf *Config) (*Client, error) {
	// Validate configuration object before continuing.

	var err error
	if err = conf.Validate(); err != nil {
		return nil, err
	}

	// Build the new HVCA client. Note the last logged in time is at its
	// default zero value, which is a time early enough that it won't prevent
	// our initial login. See documentation for the login method for more
	// information on our login strategy.

	// Build a TLS transport only if an HTTPS URL was specified.
	var tnspt http.RoundTripper

	if conf.url.Scheme == "https" {
		// Populate TLS client certificates only if one was provided.
		var tlsCerts []tls.Certificate
		if conf.TLSCert != nil {
			tlsCerts = []tls.Certificate{
				tls.Certificate{
					Certificate: [][]byte{conf.TLSCert.Raw},
					PrivateKey:  conf.TLSKey,
					Leaf:        conf.TLSCert,
				},
			}
		}

		tnspt = &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            conf.TLSRoots,
				Certificates:       tlsCerts,
				InsecureSkipVerify: conf.InsecureSkipVerify,
			},
		}
	}

	var newClient = Client{
		config:       conf,
		url:          conf.url,
		httpClient:   &http.Client{Transport: tnspt},
		loginRequest: newLoginRequest(conf.APIKey, conf.APISecret),
	}

	// Perform the initial login and return the new client.
	if err = newClient.login(ctx); err != nil {
		return nil, err
	}

	return &newClient, nil
}

// NewClientFromFile returns a new HVCA client from a configuration file. An
// initial login is made, and the returned client is immediately ready to make
// API calls.
//
// Refer to the documentation for the Config object for the format of the
// configuration file.
func NewClientFromFile(ctx context.Context, filename string) (*Client, error) {
	var conf *Config
	var err error

	if conf, err = NewConfigFromFile(filename); err != nil {
		return nil, err
	}

	return NewClient(ctx, conf)
}
