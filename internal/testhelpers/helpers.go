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

package testhelpers

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"math/big"
	"net/url"
	"os"
	"testing"

	"github.com/globalsign/hvclient/internal/pki"
)

const (
	alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJLKMNOPQRSTUVWXYZ"
)

// MustGetPublicKeyFromFile successfully retrieves a public key from a
// PEM-encoded file or fails the test.
func MustGetPublicKeyFromFile(t *testing.T, filename string) interface{} {
	t.Helper()

	var key, err = pki.PublicKeyFromFile(filename)
	if err != nil {
		t.Fatalf("couldn't get public key from file: %v", err)
	}

	return key
}

// MustGetPrivateKeyFromFile successfully retrieves a private key from a
// PEM-encoded file or fails the test.
func MustGetPrivateKeyFromFile(t *testing.T, filename string) interface{} {
	t.Helper()

	var key, err = pki.PrivateKeyFromFileWithPassword(filename, "")
	if err != nil {
		t.Fatalf("couldn't get private key from file: %v", err)
	}

	return key
}

// MustGetPrivateKeyFromFileWithPassword successfully retrieves an encrypted
// private key from a PEM-encoded file or fails the test.
func MustGetPrivateKeyFromFileWithPassword(t *testing.T, filename, password string) interface{} {
	t.Helper()

	var key, err = pki.PrivateKeyFromFileWithPassword(filename, password)
	if err != nil {
		t.Fatalf("couldn't get private key from file: %v", err)
	}

	return key
}

// MustGetCSRFromFile successfully retrieves a CSR from a
// PEM-encoded file or fails the test.
func MustGetCSRFromFile(t *testing.T, filename string) *x509.CertificateRequest {
	t.Helper()

	var cert, err = pki.CSRFromFile(filename)
	if err != nil {
		t.Fatalf("couldn't get certificate request from file: %v", err)
	}

	return cert
}

// MustGetCertFromFile successfully retrieves a certificate from a
// PEM-encoded file or fails the test.
func MustGetCertFromFile(t *testing.T, filename string) *x509.Certificate {
	t.Helper()

	var cert, err = pki.CertFromFile(filename)
	if err != nil {
		t.Fatalf("couldn't get certificate from file: %v", err)
	}

	return cert
}

// MustParseURI successfully converts a string to a *url.URL or fails
// the test.
func MustParseURI(t *testing.T, s string) *url.URL {
	t.Helper()

	var uri, err = url.Parse(s)
	if err != nil {
		t.Fatalf("couldn't parse URL: %v", err)
	}

	return uri
}

// MustParseCSR successfully parses a PEM-encoded PKCS#10 certificate
// signing request or fails the test.
func MustParseCSR(t *testing.T, reqPEM string) *x509.CertificateRequest {
	t.Helper()

	var block, _ = pem.Decode([]byte(reqPEM))

	var csr, err = x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse certificate request: %v", err)
	}

	return csr
}

// MustParseCert successfully parses a PEM-encoded X509 certificate or
// fails the test.
func MustParseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	var block, _ = pem.Decode([]byte(certPEM))

	var csr, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse certificate: %v", err)
	}

	return csr
}

// MustParseRSAPrivateKey successfully parses a PEM-encoded RSA private
// key or fails the test.
func MustParseRSAPrivateKey(t *testing.T, keyPEM string) *rsa.PrivateKey {
	t.Helper()

	var block, _ = pem.Decode([]byte(keyPEM))

	var key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse RSA private key: %v", err)
	}

	return key
}

// MustExtractRSAPublicKey successfully parses a PEM-encoded RSA private
// key and extracts the public key from it or fails the test.
func MustExtractRSAPublicKey(t *testing.T, keyPEM string) *rsa.PublicKey {
	return &MustParseRSAPrivateKey(t, keyPEM).PublicKey
}

// MustParseECPrivateKey successfully parses a PEM-encoded EC private
// key or fails the test.
func MustParseECPrivateKey(t *testing.T, keyPEM string) *ecdsa.PrivateKey {
	t.Helper()

	var block, _ = pem.Decode([]byte(keyPEM))

	var key, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("couldn't parse ECDSA private key: %v", err)
	}

	return key
}

// MustExtractECPublicKey successfully parses a PEM-encoded EC private
// key and extracts the public key from it or fails the test.
func MustExtractECPublicKey(t *testing.T, keyPEM string) *ecdsa.PublicKey {
	return &MustParseECPrivateKey(t, keyPEM).PublicKey
}

// MustGetConfigFromEnv retrieves a value from the named environment variable,
// or exits if the environment variable is not set.
func MustGetConfigFromEnv(v string) string {
	var s, ok = os.LookupEnv(v)
	if !ok {
		log.Fatalf("environment variable %s not set", v)
	}

	return s
}

// MustMakeRandomIdentifier returns a random alphabetic identifier of length
// n, or fails the test.
func MustMakeRandomIdentifier(t *testing.T, n int) string {
	t.Helper()

	var id = make([]byte, n)
	var alen = big.NewInt(int64(len(alphabet)))

	for i := range id {
		var b, err = rand.Int(rand.Reader, alen)
		if err != nil {
			t.Fatalf("failed to generate random number: %v", err)
		}

		id[i] = alphabet[b.Int64()]
	}

	return string(id)
}

// MustReadFile reads the contents of a file or fails the test.
func MustReadFile(t *testing.T, filename string) []byte {
	t.Helper()

	var b, err = ioutil.ReadFile(filename)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}

	return b
}
