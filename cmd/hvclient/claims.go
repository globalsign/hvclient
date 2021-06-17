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

// claimsDomains lists the ID, status, domain, created-at and assert-by times (or the
// total count) for either pending or verified domain hvclient.
func claimsDomains(clnt *hvclient.Client, page, pagesize int, pending bool) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var status hvclient.ClaimStatus
	if pending {
		status = hvclient.StatusPending
	} else {
		status = hvclient.StatusVerified
	}

	var clms []hvclient.Claim
	var count int64
	var err error

	if clms, count, err = clnt.ClaimsDomains(ctx, page, pagesize, status); err != nil {
		log.Fatalf("%v", err)
	}

	if *fTotalCount {
		fmt.Printf("%d\n", count)
	} else {
		for _, clm := range clms {
			fmt.Printf("%s,%s,%s,%v,%v\n", clm.ID, clm.Status, clm.Domain, clm.CreatedAt, clm.AssertBy)
		}
	}
}

// claimRetrieve lists the ID, status, domain, created-at and assert-by times for the domain
// claim with the specified ID.
func claimRetrieve(clnt *hvclient.Client, id string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var clm *hvclient.Claim
	var err error

	if clm, err = clnt.ClaimRetrieve(ctx, id); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s,%s,%s,%v,%v\n", clm.ID, clm.Status, clm.Domain, clm.CreatedAt, clm.AssertBy)
}

// claimSubmit submits a domain claim for the specified domain and
// outputs the claim token, assert-by date, and claim ID on success.
func claimSubmit(clnt *hvclient.Client, domain string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var clm *hvclient.ClaimAssertionInfo
	var err error

	if clm, err = clnt.ClaimSubmit(ctx, domain); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s,%v,%s\n", clm.Token, clm.AssertBy, clm.ID)
}

// revokeCert revokes the certificate with the specified serial number.
func claimDelete(clnt *hvclient.Client, id string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := clnt.ClaimDelete(ctx, id); err != nil {
		log.Fatalf("%v", err)
	}
}

// claimDNS requests assertion of domain control using DNS for
// the specified claim ID.
func claimDNS(clnt *hvclient.Client, id string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var clm bool
	var err error

	if clm, err = clnt.ClaimDNS(ctx, id, ""); err != nil {
		log.Fatalf("%v", err)
	}

	if clm {
		fmt.Printf("VERIFIED\n")
	} else {
		fmt.Printf("CREATED\n")
	}
}

// claimReassert reasserts an existing domain claim with the specified
// id and outputs the claim token, and assert-by date.
func claimReassert(clnt *hvclient.Client, id string) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var clm *hvclient.ClaimAssertionInfo
	var err error

	if clm, err = clnt.ClaimReassert(ctx, id); err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%s,%v\n", clm.Token, clm.AssertBy)
}
