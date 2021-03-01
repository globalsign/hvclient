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

// trustChain outputs the chain of trust for the certificates issued
// by the calling account, in PEM format.
func trustChain(clnt *hvclient.Client) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	var certs []string

	if certs, err = clnt.TrustChain(ctx); err != nil {
		log.Fatalf("%v", err)
	}

	for _, cert := range certs {
		fmt.Printf("%s", cert)
	}
}
