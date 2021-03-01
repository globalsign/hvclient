/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/globalsign/hvclient"
)

// validationPolicy outputs the validation policy in JSON format.
func validationPolicy(clnt *hvclient.Client) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	var pol *hvclient.Policy

	if pol, err = clnt.Policy(ctx); err != nil {
		log.Fatalf("%v", err)
	}

	var data []byte
	if data, err = json.MarshalIndent(pol, "", "   "); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s\n", string(data))
}
