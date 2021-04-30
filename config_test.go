/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"crypto/rsa"
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
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			var conf *Config
			var err error

			if conf, err = NewConfigFromFile(tc.filename); err != nil {
				t.Fatalf("couldn't get config file: %v", err)
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

func TestConfigNewFromFileFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.conf",
		"testdata/config_test_bad_key.conf",
		"testdata/config_test_bad_cert.conf",
		"testdata/config_test_bad_url.conf",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if _, err := NewConfigFromFile(tc); err == nil {
				t.Fatalf("unexpectedly got config from file: %v", err)
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
			"NoURL",
			Config{
				URL:       "",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPIKey",
			Config{
				URL:       "http://example.com/v2",
				APIKey:    "",
				APISecret: "abcdefgh",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoAPISecret",
			Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "",
				TLSKey:    testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoKey",
			Config{
				URL:       "http://example.com/v2",
				APIKey:    "1234",
				APISecret: "abcdefgh",
				TLSKey:    nil,
				TLSCert:   testhelpers.MustGetCertFromFile(t, "testdata/tls.cert"),
			},
		},
		{
			"NoCert",
			Config{
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
