/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"bytes"
	"io"
	"net/http"
	"reflect"
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

// claimDNSRequest represents an HVCA POST /claims/domains/{domain}/dns API call.
type claimDNSRequest struct {
	id string
}

// claimReassertRequest represents an HVCA POST /claims/domains/{domain}/reassert API call.
type claimReassertRequest struct {
	id string
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

// newClaimDNSRequest creates a new HVCA POST /claims/domains/{domain}/dns API call.
func newClaimDNSRequest(id string) *claimDNSRequest {
	return &claimDNSRequest{
		id: id,
	}
}

// newClaimReassertRequest creates a new HVCA POST /claims/domains/{domain}/reassert API call.
func newClaimReassertRequest(id string) *claimReassertRequest {
	return &claimReassertRequest{
		id: id,
	}
}
