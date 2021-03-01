/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
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
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	var cert *hvclient.CertInfo

	if cert, err = clnt.CertificateRetrieve(ctx, serialNumber); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s", cert.PEM)
}

// retrieveCertStatus outputs the issued/revoked status for the
// certificate with the specified serial number.
func retrieveCertStatus(clnt *hvclient.Client, serialNumber string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	var cert *hvclient.CertInfo

	if cert, err = clnt.CertificateRetrieve(ctx, serialNumber); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s\n", cert.Status)
}

// retrieveCertUpdatedAt outputs the updated-at time for the
// certificate with the specified serial number.
func retrieveCertUpdatedAt(clnt *hvclient.Client, serialNumber string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	var cert *hvclient.CertInfo

	if cert, err = clnt.CertificateRetrieve(ctx, serialNumber); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%v\n", cert.UpdatedAt)
}

// revokeCert revokes the certificate with the specified serial number.
func revokeCert(clnt *hvclient.Client, serialNumber string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := clnt.CertificateRevoke(ctx, serialNumber); err != nil {
		log.Fatalf("%v", err)
	}
}
