/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// generateRSAKey generates and outputs an RSA private key, optionally
// encrypting it.
func generateRSAKey(bits int, encrypt bool) (*rsa.PrivateKey, error) {
	var newkey *rsa.PrivateKey
	var err error

	if newkey, err = rsa.GenerateKey(rand.Reader, bits); err != nil {
		return nil, err
	}

	var data = x509.MarshalPKCS1PrivateKey(newkey)

	var block = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: data,
	}

	if encrypt {
		var password string

		if password, err = getPasswordFromTerminal(
			"Enter passphrase to encrypt private key",
			true,
		); err != nil {
			return nil, err
		}

		if block, err = x509.EncryptPEMBlock(
			rand.Reader,
			block.Type,
			block.Bytes,
			[]byte(password),
			x509.PEMCipherAES256,
		); err != nil {
			return nil, err
		}
	}

	fmt.Print(string(pem.EncodeToMemory(block)))

	return newkey, nil
}
