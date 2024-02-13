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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/globalsign/hvclient/internal/httputils"
)

// APIError is an error returned by the HVCA HTTP API.
type APIError 	struct {
	StatusCode  int
	Description string
	Errors      map[string]string // Additional error details
}

// hvcaError is the format of an HVCA error HTTP response body.
type hvcaError struct {
	Description string 		 		`json:"description"`
	Errors 		map[string]string 	`json:"errors,omitempty"`
}

// Error returns a string representation of the error.
func (e APIError) Error() string {
	return fmt.Sprintf("%d: %s %s", e.StatusCode, e.Description, e.Errors)
}

// NewAPIError creates a new APIError object from an HTTP response.
func NewAPIError(r *http.Response) APIError {
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

	return APIError{StatusCode: r.StatusCode, Description: hvErr.Description, Errors: hvErr.Errors}
}
