// +build integration

/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
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

func ExampleClient_StatsIssued() {
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

	// Request statistics for certificates issued during the specified time
	// window.

	stats, totalcount, err := hv.StatsIssued(
		ctx,
		1,
		100,
		time.Date(2018, 10, 5, 14, 10, 0, 0, time.UTC),
		time.Date(2018, 10, 5, 14, 23, 20, 0, time.UTC),
	)
	if err != nil {
		log.Fatalf("couldn't get statistics of certificates issued: %v", err)
	}

	// Output serial numbers of certificates issued during the time window.

	for n, stat := range stats {
		fmt.Printf("%d: %s\n", n+1, stat.SerialNumber)
	}
	fmt.Printf("Total count: %d\n", totalcount)

	// Output:
	// 1: 01CFABDF1EBA6325930BF8B6FFD89F12
	// 2: 01F61750041A52E5561F0DC342A4BF3D
	// 3: 01BE04ABA4D398ABA21D3C6E56274D18
	// 4: 0120706646DB29EDC8F168F76ACE65C1
	// Total count: 4
}
