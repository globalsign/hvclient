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
	"flag"
	"log"
	"os"
	"path"
	"time"

	"github.com/globalsign/hvclient"
)

const (
	defaultConfigFile     = ".hvclient/hvclient.conf"
	defaultTimeLayout     = "2006-01-02T15:04:05MST"
	defaultTimeWindowDays = 30
)

var timeout = time.Second * 5

func main() {
	// Parse flags and set logger.
	flag.Parse()

	log.SetFlags(0)
	log.SetPrefix("hvclient: ")

	// Handle any non-request options.
	var err error

	switch {
	case *fHelp:
		showHelp()
		return

	case *fVersion:
		showVersion()
		return

	case *fSampleTemplate:
		showSampleTemplate()
		return

	case *fGenerate, *fCSROut:
		if err = requestCert(nil); err != nil {
			log.Fatalf("%v", err)
		}
		return

	case *fGenRSA > 0:
		if _, err = generateRSAKey(*fGenRSA, *fEncrypt); err != nil {
			log.Fatalf("%v", err)
		}

		return
	}

	// Validate and parse time window.
	if *fFrom == "" && *fTo != "" {
		log.Fatalf("you must specify -from if you specify -to")
	} else if *fSince != "" && (*fFrom != "" || *fTo != "") {
		log.Fatalf("you cannot specify -from or -to if you specify -since")
	}

	var from time.Time
	var to time.Time
	if from, to, err = parseTimeWindow(*fFrom, *fTo, *fSince); err != nil {
		log.Fatalf("%v", err)
	}

	// Validate that configuration file is specified or default is available.
	var configFile string
	if *fConfigFile == "" {
		var homeDir = os.Getenv("HOME")

		if homeDir == "" {
			log.Fatalf("you must specify a configuration file")
		}

		configFile = path.Join(homeDir, defaultConfigFile)
	} else {
		configFile = *fConfigFile
	}

	// Create HVCA client.
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var clnt *hvclient.Client
	if clnt, err = hvclient.NewClientFromFile(ctx, configFile); err != nil {
		log.Fatalf("couldn't create client: %v", err)
	}

	// Set the timeout based on the configuration file.
	timeout = clnt.DefaultTimeout()

	// Select and execute desired operation.
	var willRequest = (!(*fPublicKey == "" && *fPrivateKey == "" && *fCSR == "") && (*fRekey == ""))

	switch {
	case willRequest:
		if err = requestCert(clnt); err != nil {
			log.Fatalf("%v", err)
		}

	case *fRetrieve != "":
		retrieveCert(clnt, *fRetrieve)

	case *fRekey != "":
		rekeyCert(clnt, *fRekey)

	case *fRevoke != "":
		revokeCert(clnt, *fRevoke)

	case *fStatus != "":
		retrieveCertStatus(clnt, *fStatus)

	case *fUpdated != "":
		retrieveCertUpdatedAt(clnt, *fUpdated)

	case *fTrustChain:
		trustChain(clnt)

	case *fPolicy:
		validationPolicy(clnt)

	case *fCountIssued:
		countIssued(clnt)

	case *fCountRevoked:
		countRevoked(clnt)

	case *fCertsIssued:
		certsIssued(clnt, from, to, *fPage, *fPageSize)

	case *fCertsRevoked:
		certsRevoked(clnt, from, to, *fPage, *fPageSize)

	case *fCertsExpiring:
		certsExpiring(clnt, from, to, *fPage, *fPageSize)

	case *fQuota:
		quota(clnt)

	case *fClaims:
		claimsDomains(clnt, *fPage, *fPageSize, *fPending)

	case *fClaimSubmit != "":
		claimSubmit(clnt, *fClaimSubmit)

	case *fClaimRetrieve != "":
		claimRetrieve(clnt, *fClaimRetrieve)

	case *fClaimDelete != "":
		claimDelete(clnt, *fClaimDelete)

	case *fClaimDNS != "":
		claimDNS(clnt, *fClaimDNS, *fAuthDomain)

	case *fClaimHTTP != "":
		claimHTTP(clnt, *fClaimHTTP, *fScheme, *fAuthDomain)

	case *fClaimEmail != "":
		claimEmail(clnt, *fClaimEmail, *fEmailAddress)

	case *fClaimEmailList != "":
		claimEmailRetrieve(clnt, *fClaimEmailList, *fEmailAddress)

	case *fClaimReassert != "":
		claimReassert(clnt, *fClaimReassert)

	default:
		log.Fatalf("no operation selected")
	}
}
