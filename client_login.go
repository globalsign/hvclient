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
)

// login logs into the HVCA server and stores the authentication token.
func (c *Client) login(ctx context.Context) error {
	return c.Authorizer.Login(ctx)
}

// loginIfTokenHasExpired logs in if the stored authentication token has
// expired, or if there is no stored authentication token. To avoid
// unnecessary simultaneous re-logins, this method ensures only one goroutine
// at a time can perform a re-login operation via this method.
func (c *Client) loginIfTokenHasExpired(ctx context.Context) error {
	// Do nothing if the token is not yet believed to be expired.
	if !c.Authorizer.HasExpired(ctx) {
		return nil
	}

	// Token is believed to be expired, so lock the login mutex to ensure only
	// one goroutine at a time can relogin. Note that it is perfectly safe for
	// one goroutine to call login (which doesn't acquire the login mutex) while
	// another calls this method (which does acquire it) - it's just somewhat
	// inefficient. Also note that access to the token is sychronized using
	// a different mutex, so attempting to acquire that mutex while holding
	// this one won't cause a deadlock.
	c.loginMtx.Lock()
	defer c.loginMtx.Unlock()

	// Check again if the token is believed to be expired, as another
	// goroutine may have acquired the login mutex before we did.
	if !c.Authorizer.HasExpired(ctx) {
		return nil
	}

	return c.login(ctx)
}
