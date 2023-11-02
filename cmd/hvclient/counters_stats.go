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
	"time"

	"github.com/globalsign/hvclient"
)

// countIssued outputs the total count of certificates issued.
func countIssued(clnt *hvclient.Client) {
	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCount(clnt.CounterCertsIssued(ctx))
}

// countRevoked outputs the total count of certificates revoked.
func countRevoked(clnt *hvclient.Client) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCount(clnt.CounterCertsRevoked(ctx))
}

// quota outputs the remaining quota of certificate issuances.
func quota(clnt *hvclient.Client) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCount(clnt.QuotaIssuance(ctx))
}

// outputCount outputs a count.
func outputCount(count int64, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}

	fmt.Printf("%d\n", count)
}

// certsExpiring lists the serial numbers, not-before times, and not-after times of
// the certificates expiring in the specified time window.
func certsExpiring(clnt *hvclient.Client, from, to time.Time, page, pagesize int) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCertsMeta(clnt.StatsExpiring(ctx, page, pagesize, from, to))
}

// certsIssued lists the serial numbers, not-before times, and not-after times of
// the certificates issued in the specified time window.
func certsIssued(clnt *hvclient.Client, from, to time.Time, page, pagesize int) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCertsMeta(clnt.StatsIssued(ctx, page, pagesize, from, to))
}

// certsRevoked lists the serial numbers, not-before times, and not-after times of
// the certificates revoked in the specified time window.
func certsRevoked(clnt *hvclient.Client, from, to time.Time, page, pagesize int) {
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outputCertsMeta(clnt.StatsRevoked(ctx, page, pagesize, from, to))
}

// outputCertsMeta outputs an array of certificate metadata, or a total count if
// the -totalcount flag is set.
func outputCertsMeta(metas []hvclient.CertMeta, count int64, err error) {
	if err != nil {
		log.Fatalf("%v", err)
	}

	if *fTotalCount {
		fmt.Printf("%d\n", count)
	} else {
		for _, meta := range metas {
			fmt.Printf("%x,%v,%v\n", meta.SerialNumber, meta.NotBefore, meta.NotAfter)
		}
	}
}
