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

	"github.com/globalsign/hvclient"
)

// retrieveCert outputs the certificate with the specified serial
// number, in PEM format.
func retrieveCert(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var cert, err = clnt.CertificateRetrieve(ctx, serialNumber)
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

	var cert, err = clnt.CertificateRetrieve(ctx, serialNumber)
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

	var cert, err = clnt.CertificateRetrieve(ctx, serialNumber)
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%v\n", cert.UpdatedAt)
}

// revokeCert revokes the certificate with the specified serial number.
func revokeCert(clnt *hvclient.Client, serialNumber string) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := clnt.CertificateRevoke(ctx, serialNumber); err != nil {
		log.Fatalf("%v", err)
	}
}
