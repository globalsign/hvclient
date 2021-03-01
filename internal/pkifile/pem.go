/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package pkifile

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
)

var errExtraneousPEMData = errors.New("extraneous data in PEM file")

// PEMBlockFromFile reads a PEM-encoded file and returns a pem.Block.
func PEMBlockFromFile(filename string) (*pem.Block, error) {
	var err error
	var data []byte
	if data, err = ioutil.ReadFile(filename); err != nil {
		return nil, err
	}

	var block *pem.Block
	var rest []byte
	block, rest = pem.Decode(data)

	if len(rest) != 0 {
		return nil, errExtraneousPEMData
	}

	return block, nil
}

// FileIsEncryptedPEMBlock checks if the specified file is an encrypted
// PEM block.
func FileIsEncryptedPEMBlock(filename string) bool {
	var block *pem.Block
	var err error

	if block, err = PEMBlockFromFile(filename); err != nil {
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
	var block *pem.Block
	var err error

	if block, err = PEMBlockFromFile(filename); err != nil {
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
	var block *pem.Block
	var err error

	if block, err = PEMBlockFromFile(filename); err != nil {
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
	var block *pem.Block
	var err error

	if block, err = PEMBlockFromFile(filename); err != nil {
		return nil, err
	}

	return x509.ParseCertificateRequest(block.Bytes)
}

// CertFromFile reads a PEM-encoded file and returns the X509 certificate
// it contains. If the file does not contain a PEM-encoded X509 certificate,
// an error is returned.
func CertFromFile(filename string) (*x509.Certificate, error) {
	var block *pem.Block
	var err error

	if block, err = PEMBlockFromFile(filename); err != nil {
		return nil, err
	}

	return x509.ParseCertificate(block.Bytes)
}
