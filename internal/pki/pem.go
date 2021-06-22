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

package pki

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

var errExtraneousPEMData = errors.New("extraneous data in PEM file")

// PEMBlockFromFile reads a PEM-encoded file and returns a pem.Block.
func PEMBlockFromFile(filename string) (*pem.Block, error) {
	var data, err = ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var block, rest = pem.Decode(data)
	if len(rest) != 0 {
		return nil, errExtraneousPEMData
	}

	return block, nil
}

// FileIsEncryptedPEMBlock checks if the specified file is an encrypted
// PEM block.
func FileIsEncryptedPEMBlock(filename string) bool {
	var block, err = PEMBlockFromFile(filename)
	if err != nil {
		return false
	}

	if x509.IsEncryptedPEMBlock(block) {
		return true
	}

	return false
}

// PrivateKeyFromFileWithPassword reads a PEM-encoded file and returns the
// private key it contains, decrypting it with the supplied password if
// necessary. If the file does not contain a PEM-encoded private key, an error
// is returned.
func PrivateKeyFromFileWithPassword(filename, password string) (interface{}, error) {
	var block, err = PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	var keybytes []byte

	if x509.IsEncryptedPEMBlock(block) {
		if keybytes, err = x509.DecryptPEMBlock(block, []byte(password)); err != nil {
			return nil, err
		}
	} else {
		keybytes = block.Bytes
	}

	if eckey, err := x509.ParseECPrivateKey(keybytes); err == nil {
		return eckey, nil
	}

	if rsakey, err := x509.ParsePKCS1PrivateKey(keybytes); err == nil {
		return rsakey, nil
	}

	return nil, errors.New("unsupported private key type")
}

// PublicKeyFromFile reads a PEM-encoded file and returns the public key it
// private key it contains. If the file does not contain a PEM-encoded public
// key, an error is returned.
func PublicKeyFromFile(filename string) (interface{}, error) {
	var block, err = PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, errors.New("unsupported public key type")
}

// CSRFromFile reads a PEM-encoded file and returns the PKCS#10 certificate
// signing request it contains. If the file does not contain a PEM-encoded
// PKCS#10 certificate signing request, an error is returned.
func CSRFromFile(filename string) (*x509.CertificateRequest, error) {
	var block, err = PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

// CertFromFile reads a PEM-encoded file and returns the X509 certificate
// it contains. If the file does not contain a PEM-encoded X509 certificate,
// an error is returned.
func CertFromFile(filename string) (*x509.Certificate, error) {
	var block, err = PEMBlockFromFile(filename)
	if err != nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}

// CertToPEMString encodes a certificate to a PEM-encoded string.
func CertToPEMString(cert *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}))
}

// CSRToPEMString encodes a CSR to a PEM-encoded string.
func CSRToPEMString(csr *x509.CertificateRequest) string {
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr.Raw,
	}))
}

// PublicKeyToPEMString encodes a PKIX public key to a PEM-encoded string.
func PublicKeyToPEMString(key interface{}) (string, error) {
	var b, err = x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("failed to marshal PKIX public key: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: b,
	})), nil
}
