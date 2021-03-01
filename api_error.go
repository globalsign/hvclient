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
)

// APIError is an error returned by the HVCA HTTP API
type APIError struct {
	StatusCode  int    // HTTP status code returned by HVCA
	Description string // Description of the error
}

var (
	// loginExpiredError indicates an expired login token.
	loginExpiredError = APIError{StatusCode: 401, Description: "Token is expired"}

	// signatureInvalidError also indicates an expired login token.
	signatureInvalidError = APIError{StatusCode: 401, Description: "Signature is invalid"}
)

// Error returns a string representation of the error.
func (e APIError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Description)
}

// newAPIError creates a new APIError object.
func newAPIError(response *http.Response) APIError {
	var data *struct {
		Description string `json:"description"`
	}

	if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
		return APIError{
			StatusCode:  response.StatusCode,
			Description: "unknown API error",
		}
	}

	return APIError{
		StatusCode:  response.StatusCode,
		Description: data.Description,
	}
}

// isExpiredLoginError checks if an API error results from an expired login
// token.
func isExpiredTokenError(err APIError) bool {
	return err == loginExpiredError || err == signatureInvalidError
}
