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
