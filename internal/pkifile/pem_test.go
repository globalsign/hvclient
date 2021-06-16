/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package pkifile_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"reflect"
	"testing"

	"github.com/globalsign/hvclient/internal/pkifile"
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

			if got := pkifile.FileIsEncryptedPEMBlock(tc.filename); got != tc.encrypted {
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
			var key, err = pkifile.PrivateKeyFromFileWithPassword(tc.filename, tc.password)
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

			var _, err = pkifile.PrivateKeyFromFileWithPassword(tc.filename, tc.password)
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

			var key, err = pkifile.PublicKeyFromFile(tc.filename)
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

			var _, err = pkifile.PublicKeyFromFile(tc)
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

			var _, err = pkifile.CSRFromFile(tc)
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

			var _, err = pkifile.CSRFromFile(tc)
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

			var _, err = pkifile.CertFromFile(tc)
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

			var _, err = pkifile.CertFromFile(tc)
			if err == nil {
				t.Fatalf("case %d, unexpectedly got cert from file", n+1)
			}
		})
	}
}
