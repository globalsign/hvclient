/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/globalsign/hvclient"
)

// requestCert requests a new certificate from HVCA and retrieves and outputs
// it, if successful.
func requestCert(clnt *hvclient.Client) error {
	// Build a request from the information supplied via the command line.

	var request *hvclient.Request
	var err error
	if request, err = buildRequest(
		&requestValues{
			template: *fTemplate,
			validity: validityValues{
				notBefore: *fNotBefore,
				notAfter:  *fNotAfter,
				duration:  *fDuration,
			},
			subject: subjectValues{
				commonName:         *fSubjectCommonName,
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
	); err != nil {
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
		var csr *x509.CertificateRequest

		if csr, err = request.PKCS10(); err != nil {
			return fmt.Errorf("couldn't generate PKCS#10 request: %v", err)
		}

		fmt.Printf(
			"%s",
			string(pem.EncodeToMemory(
				&pem.Block{
					Type:  "CERTIFICATE REQUEST",
					Bytes: csr.Raw,
				},
			)),
		)

		return nil
	}

	// Otherwise, request new certificate and obtain its serial number.

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var serialNumber string
	if serialNumber, err = clnt.CertificateRequest(ctx, request); err != nil {
		return fmt.Errorf("couldn't obtain certificate: %v", err)
	}

	// Using the serial number of the new certificate, request the
	// certificate itself and output it.

	var info *hvclient.CertInfo
	if info, err = clnt.CertificateRetrieve(ctx, serialNumber); err != nil {
		return fmt.Errorf("couldn't retrieve certificate %s: %v", serialNumber, err)
	}

	// Output the PEM-encoded certificate.

	fmt.Printf("%s", info.PEM)

	return nil
}
