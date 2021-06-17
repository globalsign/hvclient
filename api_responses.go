/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strconv"
)

// headerFromResponse retrieves the value of a header from an HTTP response. If there
// is more than one header value, only the first is returned.
func headerFromResponse(r *http.Response, name string) (string, error) {
	if len(r.Header[name]) == 0 {
		return "", fmt.Errorf("no values in response for header %q", name)
	}

	return r.Header[name][0], nil
}

// basePathHeaderFromResponse retrieves the base part of the path value contained in a
// header in an HTTP response. If there is more than one header value, only
// the first is returned.
func basePathHeaderFromResponse(r *http.Response, name string) (string, error) {
	var location, err = headerFromResponse(r, name)
	if err != nil {
		return "", err
	}

	return filepath.Base(location), nil
}

// intHeaderFromResponse retrieves the integer value of a header from an HTTP
// response. If there is more than one header value, only the first is
// returned.
func intHeaderFromResponse(r *http.Response, name string) (int64, error) {
	var s, err = headerFromResponse(r, name)
	if err != nil {
		return 0, err
	}

	var n int64
	n, err = strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, err
	}

	return n, nil
}

// counterFromResponse retrieves a counter value from an HTTP response.
func counterFromResponse(r *http.Response) (int64, error) {
	var data *struct {
		Count int64 `json:"value"`
	}

	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		return 0, err
	}

	return data.Count, nil
}

// stringSliceFromResponse retrieves a slice of strings from an HTTP response body.
func stringSliceFromResponse(r *http.Response) ([]string, error) {
	var s []string

	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		return nil, err
	}

	return s, nil
}

// certMetasFromResponse extracts a slice of certificate metadata from an HTTP response.
func certMetasFromResponse(r *http.Response) ([]CertMeta, int64, error) {
	var metas []CertMeta

	var err = json.NewDecoder(r.Body).Decode(&metas)
	if err != nil {
		return nil, 0, err
	}

	var count int64
	count, err = intHeaderFromResponse(r, totalCountHeaderName)
	if err != nil {
		return nil, 0, err
	}

	return metas, count, nil
}

// policyFromResponse extracts a validation policy from an HTTP response.
func policyFromResponse(r *http.Response) (*Policy, error) {
	var pol *Policy

	// We need to read the HTTP response body twice - once to unmarshal the
	// JSON data, and again to read the raw JSON into the Policy object - so
	// we create a TeeReader to allow us to do this.

	var buf bytes.Buffer
	var tee = io.TeeReader(r.Body, &buf)

	if err := json.NewDecoder(tee).Decode(&pol); err != nil {
		return nil, err
	}

	return pol, nil
}

// claimsFromResponse returns a list and total count of domain claims from
// an HTTP response.
func claimsFromResponse(r *http.Response) ([]Claim, int64, error) {
	// Parse HTTP response body.

	var clms []Claim

	var err = json.NewDecoder(r.Body).Decode(&clms)
	if err != nil {
		return nil, 0, err
	}

	// Parse total count from HTTP header.

	var totalCount int64
	totalCount, err = intHeaderFromResponse(r, totalCountHeaderName)
	if err != nil {
		return nil, 0, err
	}

	return clms, totalCount, nil
}

// claimAssertionInfoFromResponse extracts claim assertion information from
// an HTTP response.
func claimAssertionInfoFromResponse(r *http.Response) (*ClaimAssertionInfo, error) {
	// Parse HTTP response body.

	var clm *ClaimAssertionInfo

	var err = json.NewDecoder(r.Body).Decode(&clm)
	if err != nil {
		return nil, err
	}

	// Get claim location from HTTP header.

	var location string
	location, err = basePathHeaderFromResponse(r, claimLocationHeaderName)
	if err != nil {
		return nil, err
	}

	clm.ID = location

	// Return claim assertion information.

	return clm, nil
}

// claimFromResponse extracts a domain claim from an HTTP response.
func claimFromResponse(r *http.Response) (*Claim, error) {
	var clm *Claim

	if err := json.NewDecoder(r.Body).Decode(&clm); err != nil {
		return nil, err
	}

	return clm, nil
}

// tokenFromResponse creates a new HVCA login API call response object.
func tokenFromResponse(httpResp *http.Response) (string, error) {
	var data *struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(httpResp.Body).Decode(&data); err != nil {
		return "", err
	}

	return data.AccessToken, nil
}
