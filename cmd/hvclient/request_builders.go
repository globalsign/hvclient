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
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/pki"
)

type requestValues struct {
	template   string
	validity   validityValues
	subject    subjectValues
	san        sanValues
	ekus       string
	publickey  string
	privatekey string
	csr        string
	gencsr     bool
}

type validityValues struct {
	notBefore string
	notAfter  string
	duration  string
}

// subjectValues is used to aggregate subject distinguished name fields
// specified at the command line for ease of passing to functions.
type subjectValues struct {
	commonName         string
	serialNumber       string
	organization       string
	organizationalUnit string
	streetAddress      string
	locality           string
	state              string
	country            string
	joiLocality        string
	joiState           string
	joiCountry         string
	businessCategory   string
	email              string
	extraAttributes    string
}

type sanValues struct {
	dnsNames string
	emails   string
	ips      string
	uris     string
}

// IsEmpty returns true if all the fields are the empty string.
func (s subjectValues) isEmpty() bool {
	return checkAllEmpty(
		s.commonName,
		s.serialNumber,
		s.organization,
		s.organizationalUnit,
		s.streetAddress,
		s.locality,
		s.state,
		s.country,
		s.joiLocality,
		s.joiState,
		s.joiCountry,
		s.businessCategory,
		s.email,
		s.extraAttributes,
	)
}

// buildRequest builds an HVCA certificate request from information provided.
func buildRequest(reqinfo *requestValues) (*hvclient.Request, error) {
	// Create the request and, if necesssary, prepopulate it with values from
	// a template file.
	var request, err = getRequestFromTemplateOrNew(reqinfo.template)
	if err != nil {
		return nil, err
	}

	// Populate certificate request with values specified at the command line.
	if request.Validity, err = buildValidity(
		request.Validity,
		reqinfo.validity.notBefore,
		reqinfo.validity.notAfter,
		reqinfo.validity.duration,
	); err != nil {
		return nil, err
	}

	if request.Subject, err = buildDN(
		request.Subject,
		reqinfo.subject,
	); err != nil {
		return nil, err
	}

	if request.SAN, err = buildSAN(
		request.SAN,
		reqinfo.san.dnsNames,
		reqinfo.san.emails,
		reqinfo.san.ips,
		reqinfo.san.uris,
	); err != nil {
		return nil, err
	}

	if request.EKUs, err = buildEKUs(
		request.EKUs,
		reqinfo.ekus,
	); err != nil {
		return nil, err
	}

	if request.PublicKey, request.PrivateKey, request.CSR, err = getKeys(
		reqinfo.publickey,
		reqinfo.privatekey,
		reqinfo.csr,
		getPasswordFromTerminal,
	); err != nil {
		return nil, err
	}

	if reqinfo.gencsr {
		if request.CSR, err = request.PKCS10(); err != nil {
			return nil, err
		}

		request.PrivateKey = nil
	}

	return request, nil
}

// getRequestFromTemplateOrNew creates a new HVCA certificate request and,
// if the argument contains the filename of a template, initializes it with
// the values from that template.
func getRequestFromTemplateOrNew(template string) (*hvclient.Request, error) {
	var request = &hvclient.Request{}

	// Initialize request with values from template, if present.
	if template != "" {
		var data, err = ioutil.ReadFile(template)
		if err != nil {
			return nil, fmt.Errorf("couldn't read template file: %v", err)
		}

		err = json.Unmarshal(data, &request)
		if err != nil {
			return nil, fmt.Errorf("couldn't unmarshal JSON in template file: %v", err)
		}
	}

	return request, nil
}

// buildValidity takes an existing Validity object, and overrides its values
// with any specified at the command line, calculating any default values as
// necessary.
func buildValidity(
	validity *hvclient.Validity,
	notbefore, notafter, duration string,
) (*hvclient.Validity, error) {
	// If initial object is nil, create it.
	if validity == nil {
		validity = &hvclient.Validity{}
	}

	// Parse command line fields.
	var err error

	var timeBefore time.Time
	if notbefore != "" {
		if timeBefore, err = time.Parse(defaultTimeLayout, notbefore); err != nil {
			return nil, fmt.Errorf("invalid not-before time %q: %v", notbefore, err)
		}
	}

	var timeAfter time.Time
	if notafter != "" {
		if timeAfter, err = time.Parse(defaultTimeLayout, notafter); err != nil {
			return nil, fmt.Errorf("invalid not-after time %q: %v", notafter, err)
		}
	}

	var timeDuration time.Duration
	if duration != "" {
		if timeDuration, err = parseDuration(duration); err != nil {
			return nil, fmt.Errorf("invalid duration time %q: %v", duration, err)
		}
	}

	// Set or override initial values as necessary.
	if validity.NotBefore.IsZero() {
		// Not-before time was not already set, so set it the value specified
		// at the command line, or to now if no value was specified.
		if timeBefore.IsZero() {
			validity.NotBefore = time.Now()
		} else {
			validity.NotBefore = timeBefore
		}
	} else if !timeBefore.IsZero() {
		// Not-before time was already set, so override it with the value
		// specified at the command line, or leave it alone if no value was
		// specified.
		validity.NotBefore = timeBefore
	}

	if validity.NotAfter.IsZero() {
		// Not-after time was not already set, so we need to check if
		// either the not-after time or the certificate duration were
		// set at the command line.
		if timeAfter.IsZero() {
			// Not-after time was not set at the command line, so...
			if timeDuration == 0 {
				// ...set the not-after time to the maximum allowed by the
				// validation policy if the duration was not set at the
				// command line either...
				validity.NotAfter = time.Unix(0, 0)
			} else {
				// ...or calculate it based on the duration that was set at
				// the command line.
				validity.NotAfter = validity.NotBefore.Add(timeDuration)
			}
		} else {
			// Not-after time was set at the command line, so use it.
			validity.NotAfter = timeAfter
		}
	} else if !timeAfter.IsZero() {
		// Not-after time was already set, but it was also specified at the
		// command line, so override the initial value.
		validity.NotAfter = timeAfter
	} else if timeDuration != 0 {
		// Not-after time was already set, and was not specified at the
		// command line, but the certificate duration was set at the command
		// line, so override the initial value with an appropriately
		// calculated one.
		validity.NotAfter = validity.NotBefore.Add(timeDuration)
	}

	// Ensure that the not-after time is later than the not-before time, but
	// omit this check if the not-after time is set to the special value of
	// UNIX timestamp zero, which signifies the maximum duration allowed by
	// the validation policy.
	if !validity.NotAfter.Equal(time.Unix(0, 0)) {
		if d := validity.NotAfter.Sub(validity.NotBefore); d < 0 {
			return nil, errors.New("not-before time is later than not-after time")
		} else if d == 0 {
			return nil, errors.New("not-before time is equal to not-after time")
		}
	}

	return validity, nil
}

// buildDN takes an existing DN object, appends to its fields any
// values specified at the command line, and returns the address of the
// modified object. If the existing DN object is nil, a new DN
// object is created and populated and its address is returned.
func buildDN(dn *hvclient.DN, values subjectValues) (*hvclient.DN, error) {
	// Return initial value without changes if no other values are specified.
	if values.isEmpty() {
		return dn, nil
	}

	// Create the DN object if the initial value is nil.
	if dn == nil {
		dn = &hvclient.DN{}
	}

	// Set or override any single-value fields as required.
	for _, field := range []struct {
		from string
		to   *string
	}{
		{values.serialNumber, &dn.SerialNumber},
		{values.commonName, &dn.CommonName},
		{values.organization, &dn.Organization},
		{values.streetAddress, &dn.StreetAddress},
		{values.locality, &dn.Locality},
		{values.state, &dn.State},
		{values.country, &dn.Country},
		{values.email, &dn.Email},
		{values.joiLocality, &dn.JOILocality},
		{values.joiState, &dn.JOIState},
		{values.joiCountry, &dn.JOICountry},
		{values.businessCategory, &dn.BusinessCategory},
	} {
		if field.from != "" {
			*field.to = field.from
		}
	}

	// Append to organizational unit field as required.
	if values.organizationalUnit != "" {
		for _, s := range strings.Split(values.organizationalUnit, ",") {
			var trimmed = strings.TrimSpace(s)

			if len(trimmed) == 0 {
				return nil, fmt.Errorf("missing organizational unit value: %q",
					values.organizationalUnit)
			}

			dn.OrganizationalUnit = append(dn.OrganizationalUnit, trimmed)
		}
	}

	// Append to extra attributes as required.
	if values.extraAttributes != "" {
		var err error

		if dn.ExtraAttributes, err = stringToOIDAndStrings(values.extraAttributes); err != nil {
			return nil, err
		}
	}

	return dn, nil
}

// buildSAN takes an existing SAN object, appends to its fields any values
// specified at the command line, and returns the address of the modified
// object. If the existing SAN object is nil, a new SAN object is created
// and populated and its address is returned.
func buildSAN(
	san *hvclient.SAN,
	dnsnames string,
	emails string,
	ips string,
	uris string,
) (*hvclient.SAN, error) {
	// Return initial value without changes if no other values are specified.
	if checkAllEmpty(dnsnames, emails, ips, uris) {
		return san, nil
	}

	// Create the SAN object if the initial value is nil.
	if san == nil {
		san = &hvclient.SAN{}
	}

	// Append to the fields as required.
	if dnsnames != "" {
		for _, s := range strings.Split(dnsnames, ",") {
			var trimmed = strings.TrimSpace(s)

			if len(trimmed) == 0 {
				return nil, fmt.Errorf("missing DNS name: %q", dnsnames)
			}

			san.DNSNames = append(san.DNSNames, trimmed)
		}
	}

	if emails != "" {
		for _, s := range strings.Split(emails, ",") {
			var trimmed = strings.TrimSpace(s)

			if len(trimmed) == 0 {
				return nil, fmt.Errorf("missing email address: %q", emails)
			}

			san.Emails = append(san.Emails, trimmed)
		}
	}

	if ips != "" {
		var newIPs []net.IP
		var err error

		if newIPs, err = stringToIPs(ips); err != nil {
			return nil, err
		}

		san.IPAddresses = append(san.IPAddresses, newIPs...)
	}

	if uris != "" {
		var newURIs []*url.URL
		var err error

		if newURIs, err = stringToURIs(uris); err != nil {
			return nil, err
		}

		san.URIs = append(san.URIs, newURIs...)
	}

	return san, nil
}

// buildEKUs takes an existing EKUs object, appends to its fields any values
// specified at the command line, and returns the address of the modified
// object. If the existing EKUs object is nil, a new EKUs object is created
// and populated and its address is returned.
func buildEKUs(
	ekus []asn1.ObjectIdentifier,
	field string,
) ([]asn1.ObjectIdentifier, error) {
	// Return without changing the request if no extended key usages were
	// specified at the command line.
	if field == "" {
		return ekus, nil
	}

	// Extract the OIDs from the field.
	var oids, err = stringToOIDs(field)
	if err != nil {
		return nil, err
	}

	// If the initial object is nil, return the new one.
	if ekus == nil {
		return oids, nil
	}

	// Otherwise, append the new one to the old one and return it.
	return append(ekus, oids...), nil
}

// populateKeys populates a certificate request object with the public key,
// private key, or certificate signing request specified at the command line.
func getKeys(
	public, private, csr string,
	passwordFunc func(string, bool) (string, error),
) (interface{}, interface{}, *x509.CertificateRequest, error) {
	var err error
	var publickey, privatekey interface{}
	var request *x509.CertificateRequest

	if !checkOneValue(public, private, csr) {
		return nil, nil, nil,
			fmt.Errorf("you must specify one and only one of -%s, -%s and -%s",
				flagNamePublicKey, flagNamePrivateKey, flagNameCSR)
	}

	if public != "" {
		if publickey, err = pki.PublicKeyFromFile(public); err != nil {
			return nil, nil, nil, err
		}
	}

	if private != "" {
		var password string

		if pki.FileIsEncryptedPEMBlock(private) {
			if password, err = passwordFunc("Enter passphrase to decrypt private key", false); err != nil {
				return nil, nil, nil, err
			}
		}

		if privatekey, err = pki.PrivateKeyFromFileWithPassword(private,
			password); err != nil {
			return nil, nil, nil, fmt.Errorf("couldn't read private key file: %v", err)
		}
	}

	if csr != "" {
		if request, err = pki.CSRFromFile(csr); err != nil {
			return nil, nil, nil, err
		}
	}

	return publickey, privatekey, request, nil
}
