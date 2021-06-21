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

package hvclient_test

import (
	"context"
	"testing"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestNewClientFromFileError(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.conf",
		"testdata/config_test_bad_key.conf",
		"testdata/config_test_bad_cert.conf",
		"testdata/config_test_bad_version.conf",
		"testdata/config_test_bad_url.conf",
		"testdata/config_test_no_url.conf",
		"testdata/config_test_bad_passphrase.conf",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			if _, err := hvclient.NewClientFromFile(ctx, tc); err == nil {
				t.Fatalf("unexpectedly got client from file: %v", err)
			}
		})
	}
}

func TestNewClientFromConfigError(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		conf *hvclient.Config
	}{
		{
			"NoURL",
			&hvclient.Config{
				URL:       "",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPIKey",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPISecret",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoKey",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    nil,
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoCert",
			&hvclient.Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   nil,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var ctx, cancel = context.WithCancel(context.Background())
			defer cancel()

			if _, err := hvclient.NewClient(ctx, tc.conf); err == nil {
				t.Fatalf("unexpectedly got client from config: %v", err)
			}
		})
	}
}
