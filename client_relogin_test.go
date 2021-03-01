// +build integration

/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"context"
	"testing"
	"time"

	"github.com/globalsign/hvclient/internal/testhelpers"
)

const (
	expiredToken = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4R0NNIiwiemlwIjoiREVGIn0..HB9UFeY_7WnncGJX.mi276xhKF0gqWh-K3npzLJTEiOAZmwIJnmsz1f_IsSWIlKBrbtgLf_PG-odz80hTLjjElrLWIL5bsWDMi-tu8nC2a7l_iyc3iPQlQ6WgtrH8X4fuVKZvMYLgu-GDi518ByWbmadhLksoeBY3rxdCerfq-hgBaD3EeKitaloekSWvrzwUmvWWFKgTDmbq9sGDRZWgBZsjjlU22MqmaATlCYT9dmGSmxFgw5b7uiZOqR8gpWqxY96himjGZRXG9rqObBHmp0Lz6VT4EexnLngLZIN-vXZYm2VRuM8qmRyse7xB_CExxOnatFMmyEGk8dKHz3rZIfjTR9ZXD-0Y88i8fhBRFLvbM6H8q9_8cyoirNtH9jTUEioOcTEzzUk_MmtuV0oe0gLQR4MXVZaw_Xr-oZC_Mo-VlqbrK3hmAAWeRkDfsB-A-gElOE6eaFhLWrN9pENG7u2YtaoMB1FA6hRbeYpwp6YS_wTt9U5aAxXBPVm_LI73z7a_xUUb96j3xtYeH5fCiYEnXMjMboM3r7keUVLt0njGZJX3o0Vq-Bdj7sJhJeGVIzXd1zIgx5Op_ckAvMcElZLPjEVzOhfY4K6Hn1gDHJGAPfYe9G3-EXKJEra5mjSERb5LAeY9EVEQDUs9k5VRLxYX8D5qCepBBNAbdY_5U94P600WMKC3qijmQXL7yvCMQI4CRY4Pc2TYqbts8eWszmbK2L-nz4clrfcLhdCzdxryGM1Gj0V9qDlZP4yUhrL-LzLo4I-Bskzvp_wzuq3-LmQ8O-BUlwaoWV62tD-en4vzKaC23fZXWgQHBFP8CWNvEK5zC6rNTsMB7v7YJxqOHb7kmdekNNCiB368zrDxF___h6eYfQE1EyFooqAQk_3_b3OzQ4TT-N80CGM0k0jWEnqhCh7m1AEvSbWxNHeIN_hOVF7y_CGkccmxjLklHb2tjvi8Aabj-KjzODXA17De51tJXlWQYqQe_5We4agalNnA_zApok72zaY8t8Oc07_i8u8SNLw1zvs.cLPsf5Q-aJe0qCCAzjkjMg"
)

var (
	testReloginConfigFilename = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_PKCS8")
	testTimeout               = time.Second * 5
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

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	var err error
	var clnt *Client

	if clnt, err = NewClientFromFile(ctx, testReloginConfigFilename); err != nil {
		t.Fatalf("couldn't get client: %v", err)
	}

	var oldToken = clnt.readLoginToken()

	if _, err = clnt.Policy(ctx); err != nil {
		t.Fatalf("couldn't get response: %v", err)
	}

	clnt.token = expiredToken
	clnt.lastLoggedIn = time.Time{}

	if _, err = clnt.Policy(ctx); err != nil {
		t.Fatalf("couldn't get response: %v", err)
	}

	var newToken = clnt.readLoginToken()

	if oldToken == newToken {
		t.Errorf("old and new tokens unexpectedly compare equal")
	}
}
