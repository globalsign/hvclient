// +build integration

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
	"os"
	"strings"
	"testing"
	"time"
)

const (
	expiredToken = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0..HB9UFeY_7WnncGJX.mi276xhKF0gqWh-K3npzLJTEiOAZmwIJnmsz1f_IsSWIlKBrbtgLf_PG-odz80hTLjjElrLWIL5bsWDMi-tu8nC2a7l_iyc3iPQlQ6WgtrH8X4fuVKZvMYLgu-GDi518ByWbmadhLksoeBY3rxdCerfq-hgBaD3EeKitaloekSWvrzwUmvWWFKgTDmbq9sGDRZWgBZsjjlU22MqmaATlCYT9dmGSmxFgw5b7uiZOqR8gpWqxY96himjGZRXG9rqObBHmp0Lz6VT4EexnLngLZIN-vXZYm2VRuM8qmRyse7xB_CExxOnatFMmyEGk8dKHz3rZIfjTR9ZXD-0Y88i8fhBRFLvbM6H8q9_8cyoirNtH9jTUEioOcTEzzUk_MmtuV0oe0gLQR4MXVZaw_Xr-oZC_Mo-VlqbrK3hmAAWeRkDfsB-A-gElOE6eaFhLWrN9pENG7u2YtaoMB1FA6hRbeYpwp6YS_wTt9U5aAxXBPVm_LI73z7a_xUUb96j3xtYeH5fCiYEnXMjMboM3r7keUVLt0njGZJX3o0Vq-Bdj7sJhJeGVIzXd1zIgx5Op_ckAvMcElZLPjEVzOhfY4K6Hn1gDHJGAPfYe9G3-EXKJEra5mjSERb5LAeY9EVEQDUs9k5VRLxYX8D5qCepBBNAbdY_5U94P600WMKC3qijmQXL7yvCMQI4CRY4Pc2TYqbts8eWszmbK2L-nz4clrfcLhdCzdxryGM1Gj0V9qDlZP4yUhrL-LzLo4I-Bskzvp_wzuq3-LmQ8O-BUlwaoWV62tD-en4vzKaC23fZXWgQHBFP8CWNvEK5zC6rNTsMB7v7YJxqOHb7kmdekNNCiB368zrDxF___h6eYfQE1EyFooqAQk_3_b3OzQ4TT-N80CGM0k0jWEnqhCh7m1AEvSbWxNHeIN_hOVF7y_CGkccmxjLklHb2tjvi8Aabj-KjzODXA17De51tJXlWQYqQe_5We4agalNnA_zApok72zaY8t8Oc07_i8u8SNLw1zvs.cLPsf5Q-aJe0qCCAzjkjMg"
)

var (
	testConfigsEnvVar = "HVCLIENT_TEST_CONFIGS"
	testTimeout       = time.Second * 30
)

// TestRelogin tests the ability of an API call to detect an expired token,
// relogin, and remake itself by making a successful call, then deliberately
// setting the token to an expired value, and then making a second call. If
// the test is successful, the second call will fail due to the expired token,
// but will log in again and successfully complete on its second attempt.
// Test needs to belong to the client package, rather than the client_test
// package, because we need access to set the login token.
func TestRelogin(t *testing.T) {
	t.Parallel()

	// Get configuration files from the environment.
	var v, ok = os.LookupEnv(testConfigsEnvVar)
	if !ok {
		t.Skipf("environment variable %s not set", testConfigsEnvVar)
	}

	// We only need to run this test with one configuration file, and any
	// one will do, so we'll just use the first.
	var cfg = strings.Split(v, ";")[0]

	var ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var clnt, err = NewClientFromFile(ctx, cfg)
	if err != nil {
		t.Fatalf("failed to create new client from file: %v", err)
	}

	var oldToken = clnt.tokenRead()

	if _, err = clnt.Policy(ctx); err != nil {
		t.Fatalf("couldn't get response: %v", err)
	}

	// Reset the token, and verify that a new token is automatically
	// obtained.
	clnt.tokenReset()

	if _, err = clnt.Policy(ctx); err != nil {
		t.Fatalf("couldn't get response: %v", err)
	}

	var newToken = clnt.tokenRead()

	if oldToken == newToken {
		t.Errorf("old and new tokens unexpectedly compare equal")
	}

	// Deliberately set the token to an expired but otherwise valid
	// token, and verify that when the request is declined as unauthenticated,
	// a new token is automatically obtained.
	oldToken = newToken

	clnt.tokenSet(expiredToken)

	if _, err = clnt.Policy(ctx); err != nil {
		t.Fatalf("couldn't get response: %v", err)
	}

	newToken = clnt.tokenRead()

	if oldToken == newToken {
		t.Errorf("old and new tokens unexpectedly compare equal")
	}
}
