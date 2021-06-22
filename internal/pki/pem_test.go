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

package pki_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"reflect"
	"testing"

	"github.com/globalsign/hvclient/internal/pki"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestFileIsEncryptedPEMBlock(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename  string
		encrypted bool
	}{
		{"testdata/no_such_file.key", false},
		{"testdata/ec_priv_extra_data.key", false},
		{"testdata/rsa_pub.key", false},
		{"testdata/rsa_priv.key", false},
		{"testdata/rsa_priv_enc.key", true},
		{"testdata/ec_pub.key", false},
		{"testdata/ec_priv.key", false},
		{"testdata/ec_priv_enc.key", true},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			if got := pki.FileIsEncryptedPEMBlock(tc.filename); got != tc.encrypted {
				t.Fatalf("got %t, want %t", got, tc.encrypted)
			}
		})
	}
}

func TestPrivateKeyFromFileWithPassword(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename, password string
		key                interface{}
	}{
		{"testdata/rsa_priv.key", "", &rsa.PrivateKey{}},
		{"testdata/rsa_priv_enc.key", "strongpassword", &rsa.PrivateKey{}},
		{"testdata/ec_priv.key", "", &ecdsa.PrivateKey{}},
		{"testdata/ec_priv_enc.key", "somesecret", &ecdsa.PrivateKey{}},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			var key, err = pki.PrivateKeyFromFileWithPassword(tc.filename, tc.password)
			if err != nil {
				t.Fatalf("couldn't get private key from file: %v", err)
			}

			if reflect.TypeOf(key) != reflect.TypeOf(tc.key) {
				t.Fatalf("got %T, want %T", key, tc.key)
			}
		})
	}
}

func TestPrivateKeyFromFileWithPasswordBad(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename, password string
	}{
		{"testdata/no_such_file.key", ""},
		{"testdata/ec_priv_extra_data.key", ""},
		{"testdata/ec_priv_oakley.key", ""},
		{"testdata/rsa_pub.key", ""},
		{"testdata/rsa_priv_enc.key", "wrongpassword"},
		{"testdata/ec_pub.key", ""},
		{"testdata/ec_priv_enc.key", "wrongsecret"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.PrivateKeyFromFileWithPassword(tc.filename, tc.password)
			if err == nil {
				t.Fatalf("unexpectedly got private key from file")
			}
		})
	}
}

func TestPublicKeyFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename, password string
		key                interface{}
	}{
		{"testdata/rsa_pub.key", "", &rsa.PublicKey{}},
		{"testdata/rsa_pub_pkcs1.key", "", &rsa.PublicKey{}},
		{"testdata/ec_pub.key", "", &ecdsa.PublicKey{}},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			var key, err = pki.PublicKeyFromFile(tc.filename)
			if err != nil {
				t.Fatalf("couldn't get public key from file: %v", err)
			}

			if reflect.TypeOf(key) != reflect.TypeOf(tc.key) {
				t.Fatalf("got %T, want %T", key, tc.key)
			}
		})
	}
}

func TestPublicKeyFromFileBad(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.key",
		"testdata/rsa_priv.key",
		"testdata/ec_priv.key",
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.PublicKeyFromFile(tc)
			if err == nil {
				t.Fatalf("case %d, unexpectedly got public key from file", n+1)
			}
		})
	}
}

func TestCSRFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/request.p10",
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.CSRFromFile(tc)
			if err != nil {
				t.Fatalf("case %d, couldn't get CSR from file: %v", n+1, err)
			}
		})
	}
}

func TestCSRFromFileBad(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.p10",
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.CSRFromFile(tc)
			if err == nil {
				t.Fatalf("case %d, unexpectedly got CSR from file", n+1)
			}
		})
	}
}

func TestCertFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/cert.pem",
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.CertFromFile(tc)
			if err != nil {
				t.Fatalf("case %d, couldn't get cert from file: %v", n+1, err)
			}
		})
	}
}

func TestCertFromFileBad(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"testdata/no_such_file.cert",
	}

	for n, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var _, err = pki.CertFromFile(tc)
			if err == nil {
				t.Fatalf("case %d, unexpectedly got cert from file", n+1)
			}
		})
	}
}

func TestCertToPEMString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *x509.Certificate
		want string
	}{
		{
			name: "testdata/cert.pem",
			in:   testhelpers.MustGetCertFromFile(t, "testdata/cert.pem"),
			want: string(testhelpers.MustReadFile(t, "testdata/cert.pem")),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := pki.CertToPEMString(tc.in); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestCSRToPEMString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *x509.CertificateRequest
		want string
	}{
		{
			name: "testdata/request.p10",
			in:   testhelpers.MustGetCSRFromFile(t, "testdata/request.p10"),
			want: string(testhelpers.MustReadFile(t, "testdata/request.p10")),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := pki.CSRToPEMString(tc.in); got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPublicKeyToPEMString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   interface{}
		want string
		err  error
	}{
		{
			name: "testdata/rsa_pub.key",
			in:   testhelpers.MustGetPublicKeyFromFile(t, "testdata/rsa_pub.key"),
			want: string(testhelpers.MustReadFile(t, "testdata/rsa_pub.key")),
		},
		{
			name: "BadType",
			in:   "not a public key",
			err:  errors.New("unsupported public key type"),
		},
		{
			name: "testdata/ec_pub.key",
			in:   testhelpers.MustGetPublicKeyFromFile(t, "testdata/ec_pub.key"),
			want: string(testhelpers.MustReadFile(t, "testdata/ec_pub.key")),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = pki.PublicKeyToPEMString(tc.in)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
