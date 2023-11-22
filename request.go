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

package hvclient

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"time"

	"github.com/globalsign/hvclient/internal/oids"
	"github.com/globalsign/hvclient/internal/pki"
)

// Request is a request to HVCA for the issuance of a new certificate.
//
// An HVCA account will be set up with one of three options regarding
// proof-of-possession of the private key corresponding to the public key to
// be included in the certificate:
//
// 1. No proof required
//
// 2. Provide the public key signed by the private key
//
// 3. Provide a signed PKCS#10 certificate signing request.
//
// For case 1, simply assign the public key in question to the PublicKey field
// of the Request. For case 2, leave the PublicKey field empty and assign the
// private key to the PrivateKey field of the Request, and the public key will
// be automatically extracted and the appropriate signature generated. For case
// 3, leave both the PublicKey and PrivateKey fields empty and assign the
// PKCS#10 certificate signed request to the CSR field. Note that when providing
// a PKCS#10 certificate signing request, none of the fields in the CSR are
// examined by HVCA except for the public key and the signature, and none of
// the fields in the CSR are automatically copied to the Request object.
type Request struct {
	Validity            *Validity
	Subject             *DN
	SAN                 *SAN
	EKUs                []asn1.ObjectIdentifier
	DA                  *DA
	QualifiedStatements *QualifiedStatements
	MSExtension         *MSExtension
	CustomExtensions    []OIDAndString
	CSR                 *x509.CertificateRequest
	Signature           *Signature
	PrivateKey          interface{}
	PublicKey           interface{}
}

// CertificateRekeyRequest is a request to HVCA to reissue a certificate.
type CertificateRekeyRequest struct {
	Signature          *Signature `json:"signature"`
	PublicKey          string     `json:"public_key"`
	PublicKeySignature string     `json:"public_key_signature"`
}

// Validity contains the requested not-before and not-after times for a
// certificate. If NotAfter is set to time.Unix(0, 0), the maximum duration
// allowed by the validation policy will be applied.
type Validity struct {
	NotBefore time.Time
	NotAfter  time.Time
}

// DN is a list of Distinguished Name attributes to include in a
// certificate. See RFC 5280 4.1.2.6.
type DN struct {
	Country            string         `json:"country,omitempty"`
	State              string         `json:"state,omitempty"`
	Locality           string         `json:"locality,omitempty"`
	StreetAddress      string         `json:"street_address,omitempty"`
	Organization       string         `json:"organization,omitempty"`
	OrganizationalUnit []string       `json:"organizational_unit,omitempty"`
	CommonName         string         `json:"common_name,omitempty"`
	SerialNumber       string         `json:"serial_number,omitempty"`
	Email              string         `json:"email,omitempty"`
	JOILocality        string         `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
	JOIState           string         `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
	JOICountry         string         `json:"jurisdiction_of_incorporation_country_name,omitempty"`
	BusinessCategory   string         `json:"business_category,omitempty"`
	ExtraAttributes    []OIDAndString `json:"extra_attributes,omitempty"`
}

// OIDAndString is an ASN.1 object identifier (OID) together with an
// associated string value.
type OIDAndString struct {
	OID   asn1.ObjectIdentifier
	Value string
}

// SAN is a list of Subject Alternative Name attributes to include in a
// certificate. See RFC 5280 4.2.1.6.
type SAN struct {
	DNSNames    []string
	Emails      []string
	IPAddresses []net.IP
	URIs        []*url.URL
	OtherNames  []OIDAndString
}

// DA is a list of Subject Directory Attributes to include in a
// certificate. See RFC 3739.
type DA struct {
	Gender               string
	DateOfBirth          time.Time
	PlaceOfBirth         string
	CountryOfCitizenship []string
	CountryOfResidence   []string
	ExtraAttributes      []OIDAndString
}

// QualifiedStatements is a list of qualified statements to include in a
// certificate. See RFC 3739 3.2.6.
type QualifiedStatements struct {
	Semantics         Semantics
	QCCompliance      bool
	QCSSCDCompliance  bool
	QCType            asn1.ObjectIdentifier
	QCRetentionPeriod int
	QCPDs             map[string]string
}

// Semantics is the OID and optional name authorities for a qualified
// certificate statement. See RFC 3739 3.2.6.1.
type Semantics struct {
	OID             asn1.ObjectIdentifier
	NameAuthorities []string
}

// MSExtension contains values with which to populate a Microsoft template
// extension (91.3.6.1.4.1.311.21.7) with.
type MSExtension struct {
	OID          asn1.ObjectIdentifier
	MajorVersion int
	MinorVersion int
}

// Signature is the signature field in Request.
type Signature struct {
	Algorithm     string `json:"algorithm"`
	HashAlgorithm string `json:"hash_algorithm"`
}

// jsonRequest is used internally for JSON marshalling/unmarshalling.
type jsonRequest struct {
	Validity            *Validity            `json:"validity,omitempty"`
	Subject             *DN                  `json:"subject_dn,omitempty"`
	SAN                 *SAN                 `json:"san,omitempty"`
	EKUs                []jsonOID            `json:"extended_key_usages,omitempty"`
	DA                  *DA                  `json:"subject_da,omitempty"`
	QualifiedStatements *QualifiedStatements `json:"qualified_statements,omitempty"`
	MSExtension         *MSExtension         `json:"ms_extension_template,omitempty"`
	CustomExtensions    json.RawMessage      `json:"custom_extensions,omitempty"`
	Signature           *Signature           `json:"signature,omitempty"`
	PublicKey           interface{}          `json:"public_key,omitempty"`
	PublicKeySignature  string               `json:"public_key_signature,omitempty"`
}

// jsonOID is used internally for JSON marshalling/unmarshalling of
// asn1.ObjectIdentifier values.
type jsonOID asn1.ObjectIdentifier

// jsonValidity is used internally for JSON marshalling/unmarshalling.
type jsonValidity struct {
	NotBefore int64 `json:"not_before"`
	NotAfter  int64 `json:"not_after"`
}

// jsonSAN is used internally for JSON marshalling/unmarshalling.
type jsonSAN struct {
	DNSNames    []string       `json:"dns_names,omitempty"`
	Emails      []string       `json:"emails,omitempty"`
	IPAddresses []string       `json:"ip_addresses,omitempty"`
	URIs        []string       `json:"uris,omitempty"`
	OtherNames  []OIDAndString `json:"other_names,omitempty"`
}

// jsonOIDAndString is used internally for JSON marshalling/unmarshalling.
type jsonOIDAndString struct {
	Type  jsonOID `json:"type"`
	Value string  `json:"value,omitempty"`
}

// jsonDA is used internally for JSON marshalling/unmarshalling.
type jsonDA struct {
	Gender               string         `json:"gender,omitempty"`
	DateOfBirth          string         `json:"date_of_birth,omitempty"`
	PlaceOfBirth         string         `json:"place_of_birth,omitempty"`
	CountryOfCitizenship []string       `json:"country_of_citizenship,omitempty"`
	CountryOfResidence   []string       `json:"country_of_residence,omitempty"`
	ExtraAttributes      []OIDAndString `json:"extra_attributes,omitempty"`
}

// jsonQS is used internally for JSON marshalling/unmarshalling.
type jsonQS struct {
	Semantics         Semantics       `json:"semantics,omitempty"`
	QCCompliance      bool            `json:"etsi_qc_compliance"`
	QCSSCDCompliance  bool            `json:"etsi_qc_sscd_compliance"`
	QCType            jsonOID         `json:"etsi_qc_type,omitempty"`
	QCRetentionPeriod int             `json:"etsi_qc_retention_period"`
	QCPDs             json.RawMessage `json:"etsi_qc_pds,omitempty"`
}

// jsonSemantics is used internally for JSON marshalling/unmarshalling.
type jsonSemantics struct {
	OID             jsonOID  `json:"identifier"`
	NameAuthorities []string `json:"name_authorities,omitempty"`
}

// jsonMSExtension is used internally for JSON marshalling/unmarshalling.
type jsonMSExtension struct {
	OID          jsonOID `json:"id,omitempty"`
	MajorVersion int     `json:"major_version,omitempty"`
	MinorVersion int     `json:"minor_version,omitempty"`
}

// dobLayout is the appropriate time layout for the DateOfBirth field.
const dobLayout = `2006-01-02`

// Equal checks if two certificate requests are equivalent.
func (r Request) Equal(other Request) bool {
	// Check for equality of extended key usages.
	if len(r.EKUs) != len(other.EKUs) {
		return false
	}

	for i := range r.EKUs {
		if !r.EKUs[i].Equal(other.EKUs[i]) {
			return false
		}
	}

	// Check for equality of custom extensions.
	if len(r.CustomExtensions) != len(other.CustomExtensions) {
		return false
	}

	for i := range r.CustomExtensions {
		if !r.CustomExtensions[i].Equal(other.CustomExtensions[i]) {
			return false
		}
	}

	// Check for equality of other fields.
	return r.Validity.Equal(other.Validity) &&
		r.Subject.Equal(other.Subject) &&
		r.SAN.Equal(other.SAN) &&
		r.DA.Equal(other.DA) &&
		r.QualifiedStatements.Equal(other.QualifiedStatements) &&
		r.MSExtension.Equal(other.MSExtension)
}

// MarshalJSON returns the JSON encoding of a certificate request.
func (r Request) MarshalJSON() ([]byte, error) {
	// Marshal the custom extensions if any are present.
	var raw json.RawMessage
	if len(r.CustomExtensions) > 0 {
		raw = json.RawMessage("{")

		for i, ext := range r.CustomExtensions {
			var item string

			if i+1 == len(r.CustomExtensions) {
				// Close object encoding if this is the last extension.
				item = fmt.Sprintf(`"%s":"%s"}`, ext.OID.String(), ext.Value)
			} else {
				// Otherwise add a trailing comma.
				item = fmt.Sprintf(`"%s":"%s",`, ext.OID.String(), ext.Value)
			}

			raw = append(raw, []byte(item)...)
		}
	}

	// Convert extended key usages.
	var ekus = make([]jsonOID, len(r.EKUs))
	for i := range r.EKUs {
		ekus[i] = jsonOID(r.EKUs[i])
	}

	return json.Marshal(jsonRequest{
		Validity:            r.Validity,
		Subject:             r.Subject,
		SAN:                 r.SAN,
		DA:                  r.DA,
		EKUs:                ekus,
		QualifiedStatements: r.QualifiedStatements,
		MSExtension:         r.MSExtension,
		CustomExtensions:    raw,
		Signature:           r.Signature,
		// PublicKey:           publicKey,
		// PublicKeySignature:  publicKeySig,
		PublicKey: r.PublicKey,
	})
}

// UnmarshalJSON parses a JSON-encoded certificate request and stores the
// result in the object.
func (r *Request) UnmarshalJSON(b []byte) error {
	var jsonreq *jsonRequest
	var err = json.Unmarshal(b, &jsonreq)
	if err != nil {
		return err
	}

	// Unmarshal the custom extensions if any are present.
	var exts []OIDAndString

	if len(jsonreq.CustomExtensions) > 0 {
		var elems map[string]string

		if err = json.Unmarshal(jsonreq.CustomExtensions, &elems); err != nil {
			// Unmarshalling to a map[string]string appears to never trigger
			// an error, but retain the error check just in case.
			return err
		}

		// Build sorted list of keys. This is not necessary for HVCA, but
		// ensures a predictable order in the JSON encoding which facilitates
		// testing. Performance impact is negligible.
		var keys = make([]string, 0, len(elems))
		for key := range elems {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		for _, key := range keys {
			var oid, err = oids.StringToOID(key)
			if err != nil {
				return err
			}

			exts = append(exts, OIDAndString{
				OID:   oid,
				Value: elems[key],
			})
		}
	}

	// Convert extended key usages.
	var ekus = make([]asn1.ObjectIdentifier, 0, len(jsonreq.EKUs))
	for _, oid := range jsonreq.EKUs {
		ekus = append(ekus, asn1.ObjectIdentifier(oid))
	}

	// Store the result in the object.
	*r = Request{
		Validity:            jsonreq.Validity,
		Subject:             jsonreq.Subject,
		SAN:                 jsonreq.SAN,
		DA:                  jsonreq.DA,
		EKUs:                ekus,
		QualifiedStatements: jsonreq.QualifiedStatements,
		MSExtension:         jsonreq.MSExtension,
		CustomExtensions:    exts,
		Signature:           jsonreq.Signature,
		PublicKey:           jsonreq.PublicKey,
	}

	return nil
}

// PKCS10 converts a Request object into a PKCS#10 certificate signing request.
//
// BUG(paul): Not all fields are currently marshalled into the PKCS#10 request.
// The fields currently marshalled include: subject distinguished name (all
// fields, including extra attributes); subject alternative names (excluding
// other names); and extended key usages.
func (r *Request) PKCS10() (*x509.CertificateRequest, error) {
	// We need a private key to sign the CSR, so abandon immediately if
	// the request doesn't contain one.
	if r.PrivateKey == nil {
		return nil, errors.New("no private key in request")
	}

	// Build up the CSR template.
	var csrtemplate = &x509.CertificateRequest{}

	if r.Subject != nil {
		csrtemplate.Subject = r.Subject.PKIXName()
	}

	if r.SAN != nil {
		csrtemplate.DNSNames = r.SAN.DNSNames
		csrtemplate.EmailAddresses = r.SAN.Emails
		csrtemplate.IPAddresses = r.SAN.IPAddresses
		csrtemplate.URIs = r.SAN.URIs
	}

	if len(r.EKUs) > 0 {
		var value, err = asn1.Marshal(r.EKUs)
		if err != nil {
			return nil, fmt.Errorf("couldn't marshal extended key usages: %v", err)
		}

		// Note that the Request object contains no information on whether
		// extensions should be marked critical, so we'll err on the side
		// of omitting the critical flag. The CA is free to add a critical
		// flag if the policy so dicates.
		csrtemplate.ExtraExtensions = append(
			csrtemplate.ExtraExtensions,
			pkix.Extension{
				Id:    oids.OIDExtendedKeyUsage,
				Value: value,
			},
		)
	}

	// Create and marshal the PKCS#10 certificate signing request.
	var data, err = x509.CreateCertificateRequest(
		rand.Reader,
		csrtemplate,
		r.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("couldn't create PKCS#10 CSR: %v", err)
	}

	var csr *x509.CertificateRequest
	csr, err = x509.ParseCertificateRequest(data)
	if err != nil {
		return nil, fmt.Errorf("couldn't parse certificate request: %v", err)
	}

	return csr, nil
}

// Equal checks if two validity objects are equivalent.
func (v *Validity) Equal(other *Validity) bool {
	// Check for nil in both objects.
	if v == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check for equality of fields.
	return v.NotBefore.Equal(other.NotBefore) &&
		v.NotAfter.Equal(other.NotAfter)
}

// MarshalJSON returns the JSON encoding of a validity object.
func (v *Validity) MarshalJSON() ([]byte, error) {
	return json.Marshal(&jsonValidity{
		NotBefore: v.NotBefore.Unix(),
		NotAfter:  v.NotAfter.Unix(),
	})
}

// UnmarshalJSON parses a JSON-encoded validity object and stores the result in
// the object.
func (v *Validity) UnmarshalJSON(b []byte) error {
	var jsonobj jsonValidity
	if err := json.Unmarshal(b, &jsonobj); err != nil {
		return err
	}

	// Store result in object.
	*v = Validity{
		NotBefore: time.Unix(jsonobj.NotBefore, 0),
		NotAfter:  time.Unix(jsonobj.NotAfter, 0),
	}

	return nil
}

// Equal checks if two subject distinguished names are equivalent.
func (n *DN) Equal(other *DN) bool {
	// Check for nil in both objects.
	if n == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check equality of organizational units.
	if len(n.OrganizationalUnit) != len(other.OrganizationalUnit) {
		return false
	}

	for i := range n.OrganizationalUnit {
		if n.OrganizationalUnit[i] != other.OrganizationalUnit[i] {
			return false
		}
	}

	// Check equality of extra attributes.
	if len(n.ExtraAttributes) != len(other.ExtraAttributes) {
		return false
	}

	for i := range n.ExtraAttributes {
		if !n.ExtraAttributes[i].Equal(other.ExtraAttributes[i]) {
			return false
		}
	}

	// Check equality of other fields.
	return n.Country == other.Country &&
		n.State == other.State &&
		n.Locality == other.Locality &&
		n.StreetAddress == other.StreetAddress &&
		n.Organization == other.Organization &&
		n.CommonName == other.CommonName &&
		n.Email == other.Email &&
		n.JOILocality == other.JOILocality &&
		n.JOIState == other.JOIState &&
		n.JOICountry == other.JOICountry &&
		n.BusinessCategory == other.BusinessCategory &&
		n.SerialNumber == other.SerialNumber
}

// PKIXName converts a subject distinguished name into a pkix.Name object.
func (n *DN) PKIXName() pkix.Name {
	// Initialize name with all fields that are single-value in both structs.
	var name = pkix.Name{
		CommonName:   n.CommonName,
		SerialNumber: n.SerialNumber,
	}

	// Next copy over all fields that are single-value in n but are
	// multi-value in pkix.Name.
	for _, field := range []struct {
		value    string
		location *[]string
	}{
		{n.Organization, &name.Organization},
		{n.StreetAddress, &name.StreetAddress},
		{n.Locality, &name.Locality},
		{n.State, &name.Province},
		{n.Country, &name.Country},
	} {
		if field.value != "" {
			*field.location = []string{field.value}
		}
	}

	// Copy organizational units, if there are any.
	if len(n.OrganizationalUnit) > 0 {
		name.OrganizationalUnit = n.OrganizationalUnit
	}

	// Convert and add other fields which must be represented as extra names.
	for _, other := range []struct {
		value string
		oid   asn1.ObjectIdentifier
	}{
		{n.JOILocality, oids.OIDSubjectJOILocality},
		{n.JOIState, oids.OIDSubjectJOIState},
		{n.JOICountry, oids.OIDSubjectJOICountry},
		{n.Email, oids.OIDSubjectEmail},
		{n.BusinessCategory, oids.OIDSubjectBusinessCategory},
	} {
		if other.value != "" {
			name.ExtraNames = append(name.ExtraNames, pkix.AttributeTypeAndValue{
				Type:  other.oid,
				Value: other.value,
			})
		}
	}

	// Convert and add extra attributes to extra names.
	for _, ea := range n.ExtraAttributes {
		name.ExtraNames = append(name.ExtraNames, ea.AttributeTypeAndValue())
	}

	return name
}

// MarshalJSON returns the JSON encoding of a subject distinguished name.
func (o jsonOID) MarshalJSON() ([]byte, error) {
	return json.Marshal(asn1.ObjectIdentifier(o).String())
}

// UnmarshalJSON parses a JSON-encoded subject distinguished name and stores
// the result in the object.
func (o *jsonOID) UnmarshalJSON(b []byte) error {
	var oidvalue string
	var err = json.Unmarshal(b, &oidvalue)
	if err != nil {
		return err
	}

	var newOID asn1.ObjectIdentifier
	newOID, err = oids.StringToOID(oidvalue)
	if err != nil {
		return err
	}

	*o = jsonOID(newOID)

	return nil
}

// Equal checks if two OID and string objects are equivalent.
func (o OIDAndString) Equal(other OIDAndString) bool {
	return o.OID.Equal(other.OID) &&
		o.Value == other.Value
}

// MarshalJSON returns the JSON encoding of an OID and string.
func (o OIDAndString) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonOIDAndString{
		Type:  jsonOID(o.OID),
		Value: o.Value,
	})
}

// UnmarshalJSON parses a JSON-encoded OID and string and stores the result
// in the object.
func (o *OIDAndString) UnmarshalJSON(b []byte) error {
	var jsonObj *jsonOIDAndString
	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	// Store the result in the object.
	*o = OIDAndString{
		OID:   asn1.ObjectIdentifier(jsonObj.Type),
		Value: jsonObj.Value,
	}

	return nil
}

// AttributeTypeAndValue converts an OIDAndString object into a
// pkix.AttributeTypeAndValue object.
func (o OIDAndString) AttributeTypeAndValue() pkix.AttributeTypeAndValue {
	return pkix.AttributeTypeAndValue{
		Type:  o.OID,
		Value: o.Value,
	}
}

// Equal checks if two subject alternative names lists are equivalent.
func (s *SAN) Equal(other *SAN) bool {
	// Check for nil in both objects.
	if s == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check equality of DNS names.
	if len(s.DNSNames) != len(other.DNSNames) {
		return false
	}

	for i := range s.DNSNames {
		if s.DNSNames[i] != other.DNSNames[i] {
			return false
		}
	}

	// Check equality of email addresses.
	if len(s.Emails) != len(other.Emails) {
		return false
	}

	for i := range s.Emails {
		if s.Emails[i] != other.Emails[i] {
			return false
		}
	}

	// Check equality of IP addresses.
	if len(s.IPAddresses) != len(other.IPAddresses) {
		return false
	}

	for i := range s.IPAddresses {
		if !s.IPAddresses[i].Equal(other.IPAddresses[i]) {
			return false
		}
	}

	// Check equality of URIs.
	if len(s.URIs) != len(other.URIs) {
		return false
	}

	for i := range s.URIs {
		if s.URIs[i].String() != other.URIs[i].String() {
			return false
		}
	}

	// Check equality of other names.
	if len(s.OtherNames) != len(other.OtherNames) {
		return false
	}

	for i := range s.OtherNames {
		if !s.OtherNames[i].Equal(other.OtherNames[i]) {
			return false
		}
	}

	return true
}

// MarshalJSON returns the JSON encoding of a subject alternative names list.
func (s *SAN) MarshalJSON() ([]byte, error) {
	// Convert IP addresses.
	var ips = make([]string, 0, len(s.IPAddresses))
	for _, ip := range s.IPAddresses {
		ips = append(ips, ip.String())
	}

	// Convert URIs.
	var uris = make([]string, 0, len(s.URIs))
	for _, uri := range s.URIs {
		uris = append(uris, uri.String())
	}

	return json.Marshal(jsonSAN{
		DNSNames:    s.DNSNames,
		Emails:      s.Emails,
		IPAddresses: ips,
		URIs:        uris,
		OtherNames:  s.OtherNames,
	})
}

// UnmarshalJSON parses a JSON-encoded subject alternative names list and
// stores the result in the object.
func (s *SAN) UnmarshalJSON(b []byte) error {
	var jsonsan jsonSAN
	var err = json.Unmarshal(b, &jsonsan)
	if err != nil {
		return err
	}

	// Convert IP addresses.
	var ips = make([]net.IP, 0, len(jsonsan.IPAddresses))
	for _, ip := range jsonsan.IPAddresses {
		ips = append(ips, net.ParseIP(ip))
	}

	// Convert URIs.
	var uris = make([]*url.URL, 0, len(jsonsan.URIs))
	for _, strURI := range jsonsan.URIs {
		var uri, err = url.Parse(strURI)
		if err != nil {
			return err
		}

		uris = append(uris, uri)
	}

	// Store result in object.
	*s = SAN{
		DNSNames:    jsonsan.DNSNames,
		Emails:      jsonsan.Emails,
		IPAddresses: ips,
		URIs:        uris,
		OtherNames:  jsonsan.OtherNames,
	}

	return nil
}

// Equal checks if two subject directory attributes lists are equivalent.
func (d *DA) Equal(other *DA) bool {
	// Check for nil in both objects.
	if d == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check equality of country of citizenship.
	if len(d.CountryOfCitizenship) != len(other.CountryOfCitizenship) {
		return false
	}

	for i := range d.CountryOfCitizenship {
		if d.CountryOfCitizenship[i] != other.CountryOfCitizenship[i] {
			return false
		}
	}

	// Check equality of country of residence.
	if len(d.CountryOfResidence) != len(other.CountryOfResidence) {
		return false
	}

	for i := range d.CountryOfResidence {
		if d.CountryOfResidence[i] != other.CountryOfResidence[i] {
			return false
		}
	}

	// Check equality of extra attributes.
	if len(d.ExtraAttributes) != len(other.ExtraAttributes) {
		return false
	}

	for i := range d.ExtraAttributes {
		if !d.ExtraAttributes[i].Equal(other.ExtraAttributes[i]) {
			return false
		}
	}

	// Check equality of other fields.
	return d.Gender == other.Gender &&
		d.DateOfBirth.Equal(other.DateOfBirth) &&
		d.PlaceOfBirth == other.PlaceOfBirth
}

// MarshalJSON returns the JSON encoding of a subject directory attributes
// list.
func (d *DA) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonDA{
		Gender:               d.Gender,
		DateOfBirth:          d.DateOfBirth.Format(dobLayout),
		PlaceOfBirth:         d.PlaceOfBirth,
		CountryOfCitizenship: d.CountryOfCitizenship,
		CountryOfResidence:   d.CountryOfResidence,
		ExtraAttributes:      d.ExtraAttributes,
	})
}

// UnmarshalJSON parses a JSON-encoded subject directory attributes list and
// stores the result in the object.
func (d *DA) UnmarshalJSON(b []byte) error {
	var jsonda jsonDA
	var err = json.Unmarshal(b, &jsonda)
	if err != nil {
		return err
	}

	// Parse the DateOfBirth field.
	var dob time.Time
	dob, err = time.Parse(dobLayout, jsonda.DateOfBirth)
	if err != nil {
		return err
	}

	// Store the result in the object.
	*d = DA{
		Gender:               jsonda.Gender,
		DateOfBirth:          time.Date(dob.Year(), dob.Month(), dob.Day(), 12, 0, 0, 0, dob.Location()),
		PlaceOfBirth:         jsonda.PlaceOfBirth,
		CountryOfCitizenship: jsonda.CountryOfCitizenship,
		CountryOfResidence:   jsonda.CountryOfResidence,
		ExtraAttributes:      jsonda.ExtraAttributes,
	}

	return nil
}

// Equal checks if two qualified statements lists are equivalent.
func (q *QualifiedStatements) Equal(other *QualifiedStatements) bool {
	// Check for nil in both objects.
	if q == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check equality of PKI disclosure statements.
	if len(q.QCPDs) != len(other.QCPDs) {
		return false
	}

	for key, value := range q.QCPDs {
		if cmp, ok := other.QCPDs[key]; !ok || value != cmp {
			return false
		}
	}

	// Check equality of other fields.
	return q.Semantics.Equal(other.Semantics) &&
		q.QCCompliance == other.QCCompliance &&
		q.QCSSCDCompliance == other.QCSSCDCompliance &&
		q.QCType.Equal(other.QCType) &&
		q.QCRetentionPeriod == other.QCRetentionPeriod
}

// MarshalJSON returns the JSON encoding of a qualified statements list.
func (q *QualifiedStatements) MarshalJSON() ([]byte, error) {
	var raw json.RawMessage

	// Marshal the PKI disclosure statements if any are present.
	if len(q.QCPDs) > 0 {
		raw = json.RawMessage(`{`)

		// Build sorted list of keys. This is not necessary for HVCA, but
		// ensures a predictable order in the JSON encoding which facilitates
		// testing. Performance impact is negligible.
		var keys = make([]string, 0, len(q.QCPDs))
		for key := range q.QCPDs {
			keys = append(keys, key)
		}
		sort.Strings(keys)

		// Manually encode JSON for each key-value.
		for i, key := range keys {
			var item string

			if i+1 == len(keys) {
				// Close object encoding if this is the last key.
				item = fmt.Sprintf(`"%s":"%s"}`, key, q.QCPDs[key])
			} else {
				// Otherwise add a trailing comma.
				item = fmt.Sprintf(`"%s":"%s",`, key, q.QCPDs[key])
			}

			raw = append(raw, json.RawMessage(item)...)
		}
	}

	return json.Marshal(jsonQS{
		Semantics:         q.Semantics,
		QCCompliance:      q.QCCompliance,
		QCSSCDCompliance:  q.QCSSCDCompliance,
		QCType:            jsonOID(q.QCType),
		QCRetentionPeriod: q.QCRetentionPeriod,
		QCPDs:             raw,
	})
}

// UnmarshalJSON parses a JSON-encoded qualified statements list and stores
// the result in the object.
func (q *QualifiedStatements) UnmarshalJSON(b []byte) error {
	var jsonqs jsonQS
	var err = json.Unmarshal(b, &jsonqs)
	if err != nil {
		return err
	}

	// Unmarshal the PKI disclosure statements if any are present.
	var pds map[string]string
	if len(jsonqs.QCPDs) > 0 {
		if err = json.Unmarshal(jsonqs.QCPDs, &pds); err != nil {
			// Unmarshalling to a map[string]string appears to never trigger
			// an error, but retain the error check just in case.
			return err
		}
	}

	// Store the result in the object.
	*q = QualifiedStatements{
		Semantics:         jsonqs.Semantics,
		QCCompliance:      jsonqs.QCCompliance,
		QCSSCDCompliance:  jsonqs.QCSSCDCompliance,
		QCType:            asn1.ObjectIdentifier(jsonqs.QCType),
		QCRetentionPeriod: jsonqs.QCRetentionPeriod,
		QCPDs:             pds,
	}

	return nil
}

// Equal checks if two semantics objects are equivalent.
func (s Semantics) Equal(other Semantics) bool {
	// Check equality of name authorities.
	if len(s.NameAuthorities) != len(other.NameAuthorities) {
		return false
	}

	for i := range s.NameAuthorities {
		if s.NameAuthorities[i] != other.NameAuthorities[i] {
			return false
		}
	}

	// Check equality of OID.
	return s.OID.Equal(other.OID)
}

// MarshalJSON returns the JSON encoding of a semantics object.
func (s Semantics) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSemantics{
		OID:             jsonOID(s.OID),
		NameAuthorities: s.NameAuthorities,
	})
}

// UnmarshalJSON parses a JSON-encoded semantics object and stores the result
// in the object.
func (s *Semantics) UnmarshalJSON(b []byte) error {
	var jsonObj = jsonSemantics{}
	if err := json.Unmarshal(b, &jsonObj); err != nil {
		return err
	}

	// Store result in object.
	*s = Semantics{
		OID:             asn1.ObjectIdentifier(jsonObj.OID),
		NameAuthorities: jsonObj.NameAuthorities,
	}

	return nil
}

// Equal checks if two MS template extensions are equivalent.
func (m *MSExtension) Equal(other *MSExtension) bool {
	// Check for nil in both objects.
	if m == nil {
		return other == nil
	}

	if other == nil {
		return false
	}

	// Check for equality of fields.
	return m.OID.Equal(other.OID) &&
		m.MajorVersion == other.MajorVersion &&
		m.MinorVersion == other.MinorVersion
}

// MarshalJSON returns the JSON encoding of a MS template extension.
func (m *MSExtension) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonMSExtension{
		OID:          jsonOID(m.OID),
		MajorVersion: m.MajorVersion,
		MinorVersion: m.MinorVersion,
	})
}

// UnmarshalJSON parses a JSON-encoded MS template extension and stores the
// result in the object.
func (m *MSExtension) UnmarshalJSON(b []byte) error {
	var jsonext *jsonMSExtension
	if err := json.Unmarshal(b, &jsonext); err != nil {
		return err
	}

	// Store the result in the object.
	*m = MSExtension{
		OID:          asn1.ObjectIdentifier(jsonext.OID),
		MajorVersion: jsonext.MajorVersion,
		MinorVersion: jsonext.MinorVersion,
	}

	return nil
}

// publicKeyBytesAndString key extracts and returns the raw DER bytes and a
// PEM-encoded string representation of a public key.
func publicKeyBytesAndString(key interface{}) ([]byte, string, error) {
	var keyBytes, err = x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, "", fmt.Errorf("type was: %T: %v", key, err)
	}

	var keyString string
	keyString, err = pki.PublicKeyToPEMString(key)
	if err != nil {
		return nil, "", fmt.Errorf("failed to encode public key: %w", err)
	}

	// Remove trailing newline from string, if present.
	if keyString[len(keyString)-1] == '\n' {
		keyString = keyString[:len(keyString)-1]
	}

	return keyBytes, keyString, nil
}
