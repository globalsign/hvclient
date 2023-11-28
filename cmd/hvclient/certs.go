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
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/globalsign/hvclient"
)

// retrieveCert outputs the certificate with the specified serial
// number, in PEM format.
func retrieveCert(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var sn, ok = big.NewInt(0).SetString(serialNumber, 16)
	if !ok {
		log.Fatalf("invalid serial number: %s", serialNumber)
	}

	var cert, err = clnt.CertificateRetrieve(ctx, sn)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s", cert.PEM)
}

// retrieveCertStatus outputs the issued/revoked status for the
// certificate with the specified serial number.
func retrieveCertStatus(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var sn, ok = big.NewInt(0).SetString(serialNumber, 16)
	if !ok {
		log.Fatalf("invalid serial number: %s", sn)
	}

	var cert, err = clnt.CertificateRetrieve(ctx, sn)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s\n", cert.Status)
}

// retrieveCertUpdatedAt outputs the updated-at time for the
// certificate with the specified serial number.
func retrieveCertUpdatedAt(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var sn, ok = big.NewInt(0).SetString(serialNumber, 16)
	if !ok {
		log.Fatalf("invalid serial number: %s", serialNumber)
	}

	var cert, err = clnt.CertificateRetrieve(ctx, sn)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%v\n", cert.UpdatedAt)
}

// revokeCert revokes the certificate with the specified serial number.
func revokeCert(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var sn, ok = big.NewInt(0).SetString(serialNumber, 16)
	if !ok {
		log.Fatalf("invalid serial number: %s", serialNumber)
	}

	if err := clnt.CertificateRevoke(ctx, sn); err != nil {
		log.Fatalf("%v", err)
	}
}

// rekeyCert reissues the certificate with the specified serial number.
func rekeyCert(clnt *hvclient.Client, serialNumber string) error {

	var input string
	if *fCSR != "" {
		input = *fCSR
	} else if *fPublicKey != "" {
		input = *fPublicKey
	} else {
		fmt.Println("you must specify either -csr or -publickey")
		return nil
	}

	publicKey, err := os.ReadFile(input)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return err
	}

	// initializing the CertificateRekeyRequest
	var req = &hvclient.CertificateRekeyRequest{}
	req.PublicKey = string(publicKey)

	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var sn *string
	if sn, err = clnt.CertificateRekey(ctx, req, serialNumber); err != nil {
		fmt.Println(err)
		return fmt.Errorf("couldn't obtain certificate: %v", err)
	}

	fmt.Println("Reissued Certificate :", *sn)

	return nil
}
