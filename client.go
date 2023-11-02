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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"

	// "errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/globalsign/hvclient/internal/httputils"
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
	BaseURL       *url.URL
	HTTPClient    *http.Client
	Config        *Config
	Token         string
	LastLogin     time.Time
	TokenMtx      sync.RWMutex
	LoginMtx      sync.Mutex
	ClientProfile *ClientProfile
}

const (
	// numberOfRetries is the number of times to retry a request.
	numberOfRetries = 5

	// Initial time to wait before retrying. Subsequent retries will be more
	// widely spaced
	retryWaitDuration = time.Second
)

// makeRequest sends an API request to the HVCA server. If out is non-nil,
// the HTTP response body will be unmarshalled into it. In all code paths,
// the response body will be fully consumed and closed before returning.
func (c *Client) makeRequest(
	ctx context.Context,
	path string,
	method string,
	in interface{},
	out interface{},
) (*http.Response, error) {
	var retriesRemaining = numberOfRetries
	var response *http.Response

	// Loop so we can retry requests if necessary.
	for {
		var body io.Reader
		if in != nil {
			var data, err = json.Marshal(in)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal request body: %w", err)
			}

			body = bytes.NewReader(data)
		}

		var request, err = http.NewRequestWithContext(ctx, method, c.BaseURL.String()+path, body)
		if err != nil {
			return nil, fmt.Errorf("failed to create new HTTP request: %w", err)
		}

		// Add a content type header when we have a request body. Note that
		// HVCA specifically requires a UTF-8 charset parameter with the
		// media type.
		if in != nil {
			request.Header.Set(httputils.ContentTypeHeader, httputils.ContentTypeJSONUTF8)
		}

		// Add any extra headers to the request first, so they can't override
		// any headers we add ourselves.
		for key, value := range c.Config.ExtraHeaders {
			request.Header.Add(key, value)
		}

		// Perform specific processing for non-login requests.
		if !strings.HasPrefix(path, endpointLogin) {
			// Since this is not a login request, preemptively login again if
			// the stored authentication token is believed to be expired.
			err = c.loginIfTokenHasExpired(ctx)
			if err != nil {
				return nil, err
			}

			// Add the authentication token to all requests except login requests.
			request.Header.Set(httputils.AuthorizationHeader, "Bearer "+c.GetToken())
		}

		// Execute the request.
		if response, err = c.HTTPClient.Do(request); err != nil {
			return nil, fmt.Errorf("failed to execute HTTP request: %w", err)
		}
		defer httputils.ConsumeAndCloseResponseBody(response)

		// HVCA doesn't return any 3XX HTTP status codes, so treat everything outside
		// of the 2XX range as an error. Also treat 202 status codes as "errors",
		// because we want to retry in that event.
		if response.StatusCode < 200 || response.StatusCode > 299 || response.StatusCode == http.StatusAccepted {
			var apiErr = NewAPIError(response)

			// Depending on the status code, we may want to retry the request.
			switch apiErr.StatusCode {
			case http.StatusUnauthorized:
				// If we get an unauthorized status from a login request
				// then we just have bad login credentials. This is a
				// fatal error, so just stop and return it.
				if strings.HasPrefix(path, endpointLogin) {
					return nil, apiErr
				}

				// Otherwise, the token may have expired, so attempt to login
				// again, and retry the original request on success. Note that
				// this should be unusual, since we checked whether the token
				// had expired before executing this request. However, since
				// HVCA doesn't return information about the actual lifetime
				// of the token, we're having to assume that the currently
				// documented token lifetime will remain the same. If the
				// lifetime ever is shortened, this will act as a safeguard
				// and prevent otherwise fatal failures that a reactive
				// re-login could easily resolve.
				var err = c.login(ctx)
				if err != nil {
					return nil, err
				}

			case http.StatusServiceUnavailable, http.StatusAccepted:
				// Return the error if we're out of retries.
				if retriesRemaining <= 0 {
					return nil, apiErr
				}

				// Otherwise we want to retry, so decrement the number of
				// remaining retries and pause for a progressively increasing
				// period of time.
				retriesRemaining--
				time.Sleep(retryWaitDuration * time.Duration((numberOfRetries - retriesRemaining)))

			default:
				// Return the error on any other status code.
				return nil, apiErr
			}

			// Continue around the loop to retry the request.
			continue
		}

		// No errors, so break from the loop.
		break
	}

	// Return early if we're not expecting a response body.
	if out == nil {
		return response, nil
	}

	// All response bodies from successful HVCA requests have a JSON content
	// type, so verify that's what we have before reading the body.
	var err = httputils.VerifyResponseContentType(response, httputils.ContentTypeJSON)
	if err != nil {
		return nil, err
	}

	// Read and unmarshal the response body.
	var data []byte
	data, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	err = json.Unmarshal(data, out)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal HTTP response body: %w", err)
	}

	return response, nil
}

// DefaultTimeout returns the timeout specified in the configuration object or
// file used to create the client, or the default timeout provided if no value
// was specified. This is useful for honoring the timeout requested by the
// configuration when creating the context to pass to an API method if the
// original configuration information is no longer available.
func (c *Client) DefaultTimeout() time.Duration {
	return c.Config.Timeout
}

// NewThinClient creates a new client with no initial login client and a custom
// http client to facilitate re-use between hvclients.
func NewThinClient(profile *ClientProfile, httpClient *http.Client) (*Client, error) {

	// Build an HTTP transport using any proxy settings from the environment.
	// Experimentation suggests that the other values seem to reasonably
	// maximally encourage the sharing of TCP connections.
	var tnspt = &http.Transport{
		MaxIdleConnsPerHost: 1024,
		MaxIdleConns:        1024,
		MaxConnsPerHost:     1024,
		Proxy:               http.ProxyFromEnvironment,
	}

	profile.Config.url, _ = url.Parse(profile.Config.URL)

	if profile.Config.url.Scheme == "https" {
		// Populate TLS client certificates only if one was provided.
		var tlsCerts []tls.Certificate
		if profile.Config.TLSCert != nil {
			tlsCerts = []tls.Certificate{
				{
					Certificate: [][]byte{profile.Config.TLSCert.Raw},
					PrivateKey:  profile.Config.TLSKey,
					Leaf:        profile.Config.TLSCert,
				},
			}
		}

		tnspt.TLSClientConfig = &tls.Config{
			RootCAs:            profile.Config.TLSRoots,
			Certificates:       tlsCerts,
			InsecureSkipVerify: profile.Config.InsecureSkipVerify,
		}
	}

	// Build a new client.
	var newClient = Client{
		Config:        profile.Config,
		Token:         profile.Token,
		BaseURL:       profile.Config.url,
		HTTPClient:    &http.Client{Transport: tnspt},
		ClientProfile: profile,
		// }
	}

	return &newClient, nil
}

// NewClient creates a new HVCA client from a configuration object. An initial
// login is made, and the returned client is immediately ready to make API
// calls.
func NewClient(ctx context.Context, conf *Config) (*Client, error) {
	// Validate configuration object before continuing.
	var err = conf.Validate()
	if err != nil {
		return nil, err
	}

	// Build an HTTP transport using any proxy settings from the environment.
	// Experimentation suggests that the other values seem to reasonably
	// maximally encourage the sharing of TCP connections.
	var tnspt = &http.Transport{
		MaxIdleConnsPerHost: 1024,
		MaxIdleConns:        1024,
		MaxConnsPerHost:     1024,
		Proxy:               http.ProxyFromEnvironment,
	}

	if conf.url.Scheme == "https" {
		// Populate TLS client certificates only if one was provided.
		var tlsCerts []tls.Certificate
		if conf.TLSCert != nil {
			tlsCerts = []tls.Certificate{
				{
					Certificate: [][]byte{conf.TLSCert.Raw},
					PrivateKey:  conf.TLSKey,
					Leaf:        conf.TLSCert,
				},
			}
		}

		tnspt.TLSClientConfig = &tls.Config{
			RootCAs:            conf.TLSRoots,
			Certificates:       tlsCerts,
			InsecureSkipVerify: conf.InsecureSkipVerify,
		}
	}

	// Build a new client.
	var newClient = Client{
		Config:     conf,
		BaseURL:    conf.url,
		HTTPClient: &http.Client{Transport: tnspt},
	}

	// Perform the initial login and return the new client.
	err = newClient.login(ctx)
	if err != nil {
		return nil, err
	}

	return &newClient, nil
}

// NewClientFromFile returns a new HVCA client from a configuration file. An
// initial login is made, and the returned client is immediately ready to make
// API calls.
func NewClientFromFile(ctx context.Context, filename string) (*Client, error) {
	var conf, err = NewConfigFromFile(filename)
	if err != nil {
		return nil, err
	}

	return NewClient(ctx, conf)
}
