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
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/pki"
)

// requestCert requests a new certificate from HVCA and retrieves and outputs
// it, if successful.
func requestCert(clnt *hvclient.Client) error {
	// Build a request from the information supplied via the command line.
	var request, err = buildRequest(
		&requestValues{
			template: *fTemplate,
			validity: validityValues{
				notBefore: *fNotBefore,
				notAfter:  *fNotAfter,
				duration:  *fDuration,
			},
			subject: subjectValues{
				commonName:         *fSubjectCommonName,
				serialNumber:       *fSubjectSerialNumber,
				organization:       *fSubjectOrganization,
				organizationalUnit: *fSubjectOrganizationalUnit,
				streetAddress:      *fSubjectStreetAddress,
				locality:           *fSubjectLocality,
				state:              *fSubjectState,
				country:            *fSubjectCountry,
				email:              *fSubjectEmail,
				joiLocality:        *fSubjectJOILocality,
				joiState:           *fSubjectJOIState,
				joiCountry:         *fSubjectJOICountry,
				businessCategory:   *fSubjectBusinessCategory,
				extraAttributes:    *fSubjectExtraAttributes,
			},
			san: sanValues{
				dnsNames: *fDNSNames,
				emails:   *fEmails,
				ips:      *fIPs,
				uris:     *fURIs,
			},
			ekus:       *fEKUs,
			publickey:  *fPublicKey,
			privatekey: *fPrivateKey,
			csr:        *fCSR,
			gencsr:     *fGenCSR,
		},
	)
	if err != nil {
		return err
	}

	// If the user requested to output the certificate request JSON without
	// actually making the request, then do so.
	if *fGenerate {
		var encoder = json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "    ")

		if err = encoder.Encode(request); err != nil {
			return fmt.Errorf("couldn't marshal request JSON: %v", err)
		}

		return nil
	}

	// If the user requested to output a PKCS#10 certificate signing request
	// without actually making the request, then do so.
	if *fCSROut {
		var csr, err = request.PKCS10()
		if err != nil {
			return fmt.Errorf("couldn't generate PKCS#10 request: %v", err)
		}

		fmt.Printf("%s", pki.CSRToPEMString(csr))

		return nil
	}

	// Otherwise, request new certificate and obtain its serial number.
	var ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var serialNumber *string
	if serialNumber, err = clnt.CertificateRequest(ctx, request); err != nil {
		return fmt.Errorf("couldn't obtain certificate: %v", err)
	}

	var sn, ok = big.NewInt(0).SetString(*serialNumber, 16)
	if !ok {
		log.Fatalf("invalid serial number: %s", *serialNumber)
	}

	// Using the serial number of the new certificate, request the
	// certificate itself and output it.
	var info *hvclient.CertInfo
	if info, err = clnt.CertificateRetrieve(ctx, sn); err != nil {
		return fmt.Errorf("couldn't retrieve certificate %s: %v", *serialNumber, err)
	}

	// Output the PEM-encoded certificate.
	fmt.Printf("%s", info.PEM)

	return nil
}
