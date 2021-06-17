// +build integration

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

package hvclient_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

var (
	apikey             string
	apisecret          string
	tlsPrivateKey      interface{}
	tlsCertificate     *x509.Certificate
	testConfigFilename = testhelpers.MustGetConfigFromEnv("HVCLIENT_TEST_CONFIG_PKCS8")
)

func init() {
	var config *hvclient.Config
	var err error
	if config, err = hvclient.NewConfigFromFile(testConfigFilename); err != nil {
		log.Fatalf("couldn't get configuration object from file: %v", err)
	}

	apikey = config.APIKey
	apisecret = config.APISecret
	tlsPrivateKey = config.TLSKey
	tlsCertificate = config.TLSCert
}

func ExampleClient_CertificateRequest() {
	// Generate a new key for the requested certificate.

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("couldn't generate key: %v", err)
	}

	// Create context for API requests with a reasonable timeout.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Create new HVCA client.

	hv, err := hvclient.NewClient(
		ctx,
		&hvclient.Config{
			URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
			APIKey:    apikey,
			APISecret: apisecret,
			TLSKey:    tlsPrivateKey,
			TLSCert:   tlsCertificate,
		},
	)
	if err != nil {
		log.Fatalf("couldn't create HVCA client: %v", err)
	}

	// Request certificate.

	serialNumber, err := hv.CertificateRequest(
		ctx,
		&hvclient.Request{
			Validity: &hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Unix(0, 0),
			},
			Subject: &hvclient.DN{
				CommonName:         "John Doe",
				OrganizationalUnit: []string{"Finance", "Complaints"},
			},
			PublicKey: key.PublicKey,
		},
	)
	if err != nil {
		log.Fatalf("certificate request failed: %v", err)
	}

	// Retrieve certificate by serial number.

	certInfo, err := hv.CertificateRetrieve(ctx, serialNumber)
	if err != nil {
		log.Fatalf("certificate retrieval failed: %v", err)
	}

	// Parse returned PEM-encoded certificate into an x509.Certificate structure.

	block, _ := pem.Decode([]byte(certInfo.PEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("couldn't parse certificate: %v", err)
	}

	// Output some details from the issued and parsed certificate.

	fmt.Printf("Issued certificate subject common name: %s\n", cert.Subject.CommonName)
	fmt.Printf("Issued certificate subject organizational unit: %v\n", cert.Subject.OrganizationalUnit)

	// Output:
	// Issued certificate subject common name: John Doe
	// Issued certificate subject organizational unit: [Finance Complaints]
}

func ExampleClient_CounterCertsIssued() {
	// Create context for API request with a reasonable timeout.

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	// Create new HVCA client.

	hv, err := hvclient.NewClient(
		ctx,
		&hvclient.Config{
			URL:       "https://emea.api.hvca.globalsign.com:8443/v2",
			APIKey:    apikey,
			APISecret: apisecret,
			TLSKey:    tlsPrivateKey,
			TLSCert:   tlsCertificate,
		},
	)
	if err != nil {
		log.Fatalf("couldn't create HVCA client: %v", err)
	}

	// Request count of certificates issued from this account.

	count, err := hv.CounterCertsIssued(ctx)
	if err != nil {
		log.Fatalf("couldn't get count of certificates issued: %v", err)
	}

	// Output a message based on the count.

	if count > 100 {
		fmt.Print("More than 100 certificates issued from this account.\n")
	} else {
		fmt.Print("100 or less certificates issued from this account.\n")
	}

	// Output:
	// More than 100 certificates issued from this account.
}
