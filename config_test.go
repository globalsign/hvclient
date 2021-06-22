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
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io/ioutil"
	"reflect"
	"testing"
	"time"

	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestConfigNewFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		want     Config
		keyType  reflect.Type
		err      error
	}{
		{
			filename: "testdata/config_test.conf",
			want: Config{
				URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
				version:   2,
				APIKey:    "1234",
				APISecret: "abcdefgh",
				Timeout:   time.Second * 60,
			},
			keyType: reflect.TypeOf((*rsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/config_test_with_timeout.conf",
			want: Config{
				URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
				version:   2,
				APIKey:    "5678",
				APISecret: "stuvwxyz",
				Timeout:   time.Second * 5,
			},
			keyType: reflect.TypeOf((*rsa.PrivateKey)(nil)),
		},
		{
			filename: "testdata/config_test_no_version.conf",
			want: Config{
				URL:       "http://127.0.0.1:5500",
				version:   2,
				APIKey:    "1234",
				APISecret: "abcdefgh",
				Timeout:   time.Second * 60,
			},
		},
		{
			filename: "testdata/no_such_file.conf",
			err:      errors.New("no such file"),
		},
		{
			filename: "testdata/config_test_bad_key.conf",
			err:      errors.New("bad key"),
		},
		{
			filename: "testdata/config_test_bad_cert.conf",
			err:      errors.New("bad cert"),
		},
		{
			filename: "testdata/config_test_bad_url.conf",
			err:      errors.New("bad URL"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			var conf, err = NewConfigFromFile(tc.filename)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if tc.err != nil {
				return
			}

			if conf.URL != tc.want.URL {
				t.Fatalf("got URL %s, want %s", conf.URL, tc.want.URL)
			}

			if conf.version != tc.want.version {
				t.Fatalf("got version %d, want %d", conf.version, tc.want.version)
			}

			if conf.APIKey != tc.want.APIKey {
				t.Fatalf("got API key %s, want %s", conf.APIKey, tc.want.APIKey)
			}

			if conf.APISecret != tc.want.APISecret {
				t.Fatalf("got API secret %s, want %s", conf.APISecret, tc.want.APISecret)
			}

			if (conf.TLSKey == nil) != (tc.keyType == nil) {
				t.Fatalf("got key type %T, want %v", conf.TLSKey, tc.keyType)
			}
		})
	}
}

func TestConfigUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		filename string
		err      error
	}{
		{
			name:     "OK",
			filename: "testdata/config_test.conf",
		},
		{
			name:     "BadKey",
			filename: "testdata/config_test_bad_key.conf",
			err:      errors.New("bad key"),
		},
		{
			name:     "BadCert",
			filename: "testdata/config_test_bad_cert.conf",
			err:      errors.New("bad cert"),
		},
		{
			name:     "BadCert",
			filename: "testdata/config_test_bad_url.conf",
			err:      errors.New("bad URL"),
		},
		{
			name:     "BadType",
			filename: "testdata/config_test_bad_type.conf",
			err:      errors.New("bad type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var data, err = ioutil.ReadFile(tc.filename)
			if err != nil {
				t.Fatalf("failed to read file: %v", err)
			}

			var cfg Config
			err = json.Unmarshal(data, &cfg)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}
		})
	}
}

func TestConfigValidateFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		conf Config
	}{
		{
			name: "NoURL",
			conf: Config{
				URL:       "",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			name: "NoAPIKey",
			conf: Config{
				URL:       "http://example.com/v2",
				APIKey:    "",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			name: "NoAPISecret",
			conf: Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			name: "NoKey",
			conf: Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    nil,
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			name: "NoCert",
			conf: Config{
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

			if err := tc.conf.Validate(); err == nil {
				t.Fatalf("unexpectedly validated")
			}
		})
	}
}
