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
	"github.com/globalsign/hvclient/internal/pki"
)

// trustChain outputs the chain of trust for the certificates issued
// by the calling account, in PEM format.
func trustChain(clnt *hvclient.Client) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var certs, err = clnt.TrustChain(ctx)
	if err != nil {
		log.Fatalf("%v", err)
	}

	for _, cert := range certs {
		fmt.Printf("%s", pki.CertToPEMString(cert))
	}
}
