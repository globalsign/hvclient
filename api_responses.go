/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"encoding/json"
	"fmt"
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
