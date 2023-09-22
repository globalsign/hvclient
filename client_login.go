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
	"context"
	"fmt"
	"net/http"
	"time"
)

// loginRequest is an HVCA POST /login request body.
type loginRequest struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// loginResponse is an HVCA POST /login response body.
type loginResponse struct {
	AccessToken string `json:"access_token"`
}

const (
	// tokenLifetime is the assumed lifetime of an HVCA authentication token.
	// The HVCA API appears to not return any information confirming the
	// lifetime of the token, but at the time of writing the API documentation
	// states it to be 10 minutes. We here set it to nine minutes just to
	// leave some headroom.
	tokenLifetime = time.Minute * 9
)

// HVCA API endpoints.
const (
	endpointLogin = "/login"
)

// login logs into the HVCA server and stores the authentication token.
func (c *Client) login(ctx context.Context) error {
	var req = loginRequest{
		APIKey:    c.Config.APIKey,
		APISecret: c.Config.APISecret,
	}

	var resp loginResponse
	var _, err = c.makeRequest(
		ctx,
		endpointLogin,
		http.MethodPost,
		req,
		&resp,
	)
	if err != nil {
		c.tokenReset()

		return fmt.Errorf("failed to login: %w", err)
	}

	c.SetToken(resp.AccessToken)

	return nil
}

// loginIfTokenHasExpired logs in if the stored authentication token has
// expired, or if there is no stored authentication token. To avoid
// unnecessary simultaneous re-logins, this method ensures only one goroutine
// at a time can perform a re-login operation via this method.
func (c *Client) loginIfTokenHasExpired(ctx context.Context) error {
	// Do nothing if the token is not yet believed to be expired.
	if !c.tokenHasExpired() {
		return nil
	}

	// Token is believed to be expired, so lock the login mutex to ensure only
	// one goroutine at a time can relogin. Note that it is perfectly safe for
	// one goroutine to call login (which doesn't acquire the login mutex) while
	// another calls this method (which does acquire it) - it's just somewhat
	// inefficient. Also note that access to the token is sychronized using
	// a different mutex, so attempting to acquire that mutex while holding
	// this one won't cause a deadlock.
	c.LoginMtx.Lock()
	defer c.LoginMtx.Unlock()

	// Check again if the token is believed to be expired, as another
	// goroutine may have acquired the login mutex before we did.
	if !c.tokenHasExpired() {
		return nil
	}

	return c.login(ctx)
}

// tokenHasExpired returns true if the stored authentication token is believed
// to be expired (or if there is no stored authentication token), indicating
// that another login is required.
func (c *Client) tokenHasExpired() bool {
	c.TokenMtx.RLock()
	defer c.TokenMtx.RUnlock()

	return time.Since(c.LastLogin) > tokenLifetime
}

// tokenReset clears the stored authentication token and the last login time.
func (c *Client) tokenReset() {
	c.TokenMtx.Lock()
	defer c.TokenMtx.Unlock()

	c.Token = ""
	c.LastLogin = time.Time{}
}

// SetToken sets the stored authentication token and sets the last login time
// to the current time.
func (c *Client) SetToken(token string) {
	c.TokenMtx.Lock()
	defer c.TokenMtx.Unlock()

	c.Token = token
	c.LastLogin = time.Now()
}

// GetToken performs a synchronized read of the stored authentication token.
func (c *Client) GetToken() string {
	c.TokenMtx.RLock()
	defer c.TokenMtx.RUnlock()

	return c.Token
}

//
