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
	"io/ioutil"
	"net/http"

	"github.com/globalsign/hvclient/internal/httputils"
)

// APIError is an error returned by the HVCA HTTP API
type APIError struct {
	StatusCode  int
	Description string
}

// hvcaError is the format of an HVCA error HTTP response body.
type hvcaError struct {
	Description string `json:"description"`
}

// Error returns a string representation of the error.
func (e APIError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Description)
}

// newAPIError creates a new APIError object from an HTTP response.
func newAPIError(r *http.Response) APIError {
	// All HVCA error response bodies have a problem+json content type, so
	// return a generic error if that's not the content type we have.
	var err = httputils.VerifyResponseContentType(r, httputils.ContentTypeProblemJSON)
	if err != nil {
		return APIError{StatusCode: r.StatusCode, Description: "unknown API error"}
	}

	// Read and unmarshal the response body. Return a generic error on
	// any failure.
	var data []byte
	data, err = ioutil.ReadAll(r.Body)
	if err != nil {
		return APIError{StatusCode: r.StatusCode, Description: "unknown API error"}
	}

	var hvErr hvcaError
	err = json.Unmarshal(data, &hvErr)
	if err != nil {
		return APIError{StatusCode: r.StatusCode, Description: "unknown API error"}
	}

	return APIError{StatusCode: r.StatusCode, Description: hvErr.Description}
}
