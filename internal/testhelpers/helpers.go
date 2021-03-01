/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package testhelpers

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"net/url"
	"os"
	"testing"

	"github.com/globalsign/hvclient/internal/pkifile"
)

// MustGetPublicKeyFromFile successfully retrieves a public key from a
// PEM-encoded file or fails the test.
func MustGetPublicKeyFromFile(t *testing.T, filename string) interface{} {
	t.Helper()

	var key interface{}
	var err error

	if key, err = pkifile.PublicKeyFromFile(filename); err != nil {
		t.Fatalf("couldn't get public key from file: %v", err)
	}

	return key
}

// MustGetPrivateKeyFromFile successfully retrieves a private key from a
// PEM-encoded file or fails the test.
func MustGetPrivateKeyFromFile(t *testing.T, filename string) interface{} {
	t.Helper()

	var key interface{}
	var err error

	if key, err = pkifile.PrivateKeyFromFileWithPassword(filename, ""); err != nil {
		t.Fatalf("couldn't get private key from file: %v", err)
	}

	return key
}

// MustGetPrivateKeyFromFileWithPassword successfully retrieves an encrypted
// private key from a PEM-encoded file or fails the test.
func MustGetPrivateKeyFromFileWithPassword(t *testing.T, filename, password string) interface{} {
	t.Helper()

	var key interface{}
	var err error

	if key, err = pkifile.PrivateKeyFromFileWithPassword(filename, password); err != nil {
		t.Fatalf("couldn't get private key from file: %v", err)
	}

	return key
}

// MustGetCSRFromFile successfully retrieves a CSR from a
// PEM-encoded file or fails the test.
func MustGetCSRFromFile(t *testing.T, filename string) *x509.CertificateRequest {
	t.Helper()

	var cert *x509.CertificateRequest
	var err error

	if cert, err = pkifile.CSRFromFile(filename); err != nil {
		t.Fatalf("couldn't get certificate request from file: %v", err)
	}

	return cert
}

// MustGetCertFromFile successfully retrieves a certificate from a
// PEM-encoded file or fails the test.
func MustGetCertFromFile(t *testing.T, filename string) *x509.Certificate {
	t.Helper()

	var cert *x509.Certificate
	var err error

	if cert, err = pkifile.CertFromFile(filename); err != nil {
		t.Fatalf("couldn't get certificate from file: %v", err)
	}

	return cert
}

// MustParseURI successfully converts a string to a *url.URL or fails
// the test.
func MustParseURI(t *testing.T, s string) *url.URL {
	t.Helper()

	var uri *url.URL
	var err error

	if uri, err = url.Parse(s); err != nil {
		t.Fatalf("couldn't parse URL: %v", err)
	}

	return uri
}

// MustParseCSR successfully parses a PEM-encoded PKCS#10 certificate
// signing request or fails the test.
func MustParseCSR(t *testing.T, reqPEM string) *x509.CertificateRequest {
	t.Helper()

	var block *pem.Block
	block, _ = pem.Decode([]byte(reqPEM))

	var csr *x509.CertificateRequest
	var err error

	if csr, err = x509.ParseCertificateRequest(block.Bytes); err != nil {
		t.Fatalf("couldn't parse certificate request: %v", err)
	}

	return csr
}

// MustParseCert successfully parses a PEM-encoded X509 certificate or
// fails the test.
func MustParseCert(t *testing.T, certPEM string) *x509.Certificate {
	t.Helper()

	var block *pem.Block
	block, _ = pem.Decode([]byte(certPEM))

	var csr *x509.Certificate
	var err error

	if csr, err = x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("couldn't parse certificate: %v", err)
	}

	return csr
}

// MustParseRSAPrivateKey successfully parses a PEM-encoded RSA private
// key or fails the test.
func MustParseRSAPrivateKey(t *testing.T, keyPEM string) *rsa.PrivateKey {
	t.Helper()

	var block *pem.Block
	block, _ = pem.Decode([]byte(keyPEM))

	var key *rsa.PrivateKey
	var err error

	if key, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
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

	var block *pem.Block
	block, _ = pem.Decode([]byte(keyPEM))

	var key *ecdsa.PrivateKey
	var err error

	if key, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
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
