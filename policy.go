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
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/globalsign/hvclient/internal/oids"
)

// Policy is a certificate request validation policy.
type Policy struct {
	Validity            *ValidityPolicy            `json:"validity,omitempty"`
	SubjectDN           *SubjectDNPolicy           `json:"subject_dn,omitempty"`
	SAN                 *SANPolicy                 `json:"san,omitempty"`
	EKUs                *EKUPolicy                 `json:"extended_key_usages,omitempty"`
	SubjectDA           *SubjectDAPolicy           `json:"subject_da,omitempty"`
	QualifiedStatements *QualifiedStatementsPolicy `json:"qualified_statements,omitempty"`
	MSExtensionTemplate *MSExtensionTemplatePolicy `json:"ms_extension_template,omitempty"`
	SignaturePolicy     *SignaturePolicy           `json:"signature,omitempty"`
	PublicKey           *PublicKeyPolicy           `json:"public_key,omitempty"`
	PublicKeySignature  Presence                   `json:"public_key_signature"`
	CustomExtensions    []CustomExtensionsPolicy   `json:"custom_extensions,omitempty"`
}

// ValidityPolicy is a validity field in a validation policy.
type ValidityPolicy struct {
	SecondsMin            int64 `json:"secondsmin"`
	SecondsMax            int64 `json:"secondsmax"`
	NotBeforeNegativeSkew int64 `json:"not_before_negative_skew"`
	NotBeforePositiveSkew int64 `json:"not_before_positive_skew"`
	IssuerExpiry          int64 `json:"issuer_expiry"`
}

// SubjectDNPolicy is a subject distinguished name field in a validation policy.
type SubjectDNPolicy struct {
	CommonName               *StringPolicy        `json:"common_name,omitempty"`
	GivenName                *StringPolicy        `json:"given_name,omitempty"`
	Surname                  *StringPolicy        `json:"surname,omitempty"`
	Organization             *StringPolicy        `json:"organization,omitempty"`
	OrganizationalUnit       *ListPolicy          `json:"organizational_unit,omitempty"`
	OrganizationalIdentifier *StringPolicy        `json:"organization_identifier,omitempty"`
	Country                  *StringPolicy        `json:"country,omitempty"`
	State                    *StringPolicy        `json:"state,omitempty"`
	Locality                 *StringPolicy        `json:"locality,omitempty"`
	StreetAddress            *StringPolicy        `json:"street_address,omitempty"`
	PostalCode               *StringPolicy        `json:"postal_code,omitempty"`
	Email                    *StringPolicy        `json:"email,omitempty"`
	JOILocality              *StringPolicy        `json:"jurisdiction_of_incorporation_locality_name,omitempty"`
	JOIState                 *StringPolicy        `json:"jurisdiction_of_incorporation_state_or_province_name,omitempty"`
	JOICountry               *StringPolicy        `json:"jurisdiction_of_incorporation_country_name,omitempty"`
	BusinessCategory         *StringPolicy        `json:"business_category,omitempty"`
	SerialNumber             *StringPolicy        `json:"serial_number,omitempty"`
	ExtraAttributes          []TypeAndValuePolicy `json:"-"`
}

// SANPolicy is the subject alternative names field in a validation policy.
type SANPolicy struct {
	DNSNames    *ListPolicy
	Emails      *ListPolicy
	IPAddresses *ListPolicy
	URIs        *ListPolicy
	OtherNames  []TypeAndValuePolicy
}

// jsonSANPolicy is used internally for JSON marshalling/unmarshalling.
type jsonSANPolicy struct {
	DNSNames    *ListPolicy          `json:"dns_names"`
	Emails      *ListPolicy          `json:"emails"`
	IPAddresses *ListPolicy          `json:"ip_addresses"`
	URIs        *ListPolicy          `json:"uris"`
	OtherNames  typeAndValuePolicies `json:"other_names"`
}

// EKUPolicy is the extended key usages field in a validation
// policy.
type EKUPolicy struct {
	EKUs     ListPolicy `json:"ekus"`
	Critical bool       `json:"critical"`
}

// SubjectDAPolicy is the subject directory attributes field in a validation
// policy.
type SubjectDAPolicy struct {
	Gender               *StringPolicy        `json:"gender,omitempty"`
	DateOfBirth          Presence             `json:"date_of_birth,omitempty"`
	PlaceOfBirth         *StringPolicy        `json:"place_of_birth,omitempty"`
	CountryOfCitizenship *ListPolicy          `json:"country_of_citizenship,omitempty"`
	CountryOfResidence   *ListPolicy          `json:"country_of_residence,omitempty"`
	ExtraAttributes      []TypeAndValuePolicy `json:"extra_attributes,omitempty"`
}

// jsonSubjectDAPolicy is used internally for JSON marshalling/unmarshalling.
type jsonSubjectDAPolicy struct {
	Gender               *StringPolicy        `json:"gender,omitempty"`
	DateOfBirth          Presence             `json:"date_of_birth,omitempty"`
	PlaceOfBirth         *StringPolicy        `json:"place_of_birth,omitempty"`
	CountryOfCitizenship *ListPolicy          `json:"country_of_citizenship,omitempty"`
	CountryOfResidence   *ListPolicy          `json:"country_of_residence,omitempty"`
	ExtraAttributes      typeAndValuePolicies `json:"extra_attributes,omitempty"`
}

// QualifiedStatementsPolicy is the qualified statements field in a validation
// policy.
type QualifiedStatementsPolicy struct {
	Semantics             *SemanticsPolicy       `json:"semantics"`
	ETSIQCCompliance      OptionalStaticPresence `json:"etsi_qc_compliance"`
	ETSIQCSSCDCompliance  OptionalStaticPresence `json:"etsi_qc_sscd_compliance"`
	ETSIQCType            *StringPolicy          `json:"etsi_qc_type"`
	ETSIQCRetentionPeriod *IntegerPolicy         `json:"etsi_qc_retention_period"`
	ETSIQCPDs             *ETSIPDsPolicy         `json:"etsi_qc_pds"`
}

// SemanticsPolicy is the semantics field in the qualified statements field
// in a validation policy.
type SemanticsPolicy struct {
	Identifier      *StringPolicy `json:"identifier"`
	NameAuthorities *ListPolicy   `json:"name_authorities"`
}

// ETSIPDsPolicy is the PKI disclosure statements field in the qualified
// statements field in a validation policy.
type ETSIPDsPolicy struct {
	Presence Presence          `json:"presence"`
	Policies map[string]string `json:"policies"`
}

// MSExtensionTemplatePolicy is the Microsoft template extension field in a
// validation policy.
type MSExtensionTemplatePolicy struct {
	Critical     bool           `json:"critical"`
	TemplateID   *StringPolicy  `json:"template_id,omitempty"`
	MajorVersion *IntegerPolicy `json:"major_version,omitempty"`
	MinorVersion *IntegerPolicy `json:"minor_version,omitempty"`
}

// CustomExtensionsPolicy is the custom extensions field in a validation policy.
type CustomExtensionsPolicy struct {
	OID         asn1.ObjectIdentifier `json:"-"`
	Presence    Presence              `json:"presence"`
	Critical    bool                  `json:"critical"`
	ValueType   ValueType             `json:"value_type"`
	ValueFormat string                `json:"value_format,omitempty"`
}

// SignaturePolicy is the signature field in a validation policy.
type SignaturePolicy struct {
	Algorithm     *AlgorithmPolicy `json:"algorithm"`
	HashAlgorithm *AlgorithmPolicy `json:"hash_algorithm"`
}

// AlgorithmPolicy is a list of algorithm names and their presence value entry
// in a validation policy.
type AlgorithmPolicy struct {
	Presence Presence `json:"presence"`
	List     []string `json:"list"`
}

// PublicKeyPolicy is the public key field in a validation policy.
type PublicKeyPolicy struct {
	KeyType        KeyType   `json:"key_type"`
	AllowedLengths []int     `json:"allowed_lengths"`
	KeyFormat      KeyFormat `json:"key_format"`
}

// StringPolicy is a string value entry in a validation policy.
type StringPolicy struct {
	Presence Presence `json:"presence"`
	Format   string   `json:"format"`
}

// IntegerPolicy is an integer value entry in a validation policy.
type IntegerPolicy struct {
	Presence Presence `json:"presence"`
	Min      int      `json:"min"`
	Max      int      `json:"max"`
}

// ListPolicy is a list value entry in a validation policy.
type ListPolicy struct {
	Static   bool     `json:"static"`
	List     []string `json:"list"`
	MinCount int      `json:"mincount"`
	MaxCount int      `json:"maxcount"`
}

// TypeAndValuePolicy is a type and value entry in a validation policy.
type TypeAndValuePolicy struct {
	OID         asn1.ObjectIdentifier `json:"-"`
	Static      bool                  `json:"static"`
	ValueType   ValueType             `json:"value_type"`
	ValueFormat string                `json:"value_format"`
	MinCount    int                   `json:"mincount"`
	MaxCount    int                   `json:"maxcount"`
}

// typeAndValuePolicies is used internally for JSON marshalling/unmarshalling.
type typeAndValuePolicies []TypeAndValuePolicy

// customExtensionsPolicies is used internally for JSON marshalling/unmarshalling.
type customExtensionsPolicies []CustomExtensionsPolicy

// ValueType is a value_type field in a validation policy.
type ValueType int

// Presence is the presence field in a validation policy.
type Presence int

// KeyType is the type of a public key.
type KeyType int

// KeyFormat is the allowed format of a public key.
type KeyFormat int

// OptionalStaticPresence denotes whether a static boolean is optional, or
// true, or false.
type OptionalStaticPresence int

// ValueType value constants.
const (
	IA5String ValueType = iota + 1
	PrintableString
	UTF8String
	Integer
	DER
	Nil
)

// Presence value constants.
const (
	Optional Presence = iota + 1
	Required
	Forbidden
	Static
)

// Key format value constants.
const (
	PKCS8 KeyFormat = iota + 1
	PKCS10
)

// Key type value constants.
const (
	RSA KeyType = iota + 1
	ECDSA
)

// Optional static presence values.
const (
	StaticOptional OptionalStaticPresence = iota + 1
	StaticTrue
	StaticFalse
)

// valueTypeDescriptions maps value type values to their string descriptions.
var valueTypeDescriptions = []string{
	IA5String:       "IA5STRING",
	PrintableString: "PRINTABLESTRING",
	UTF8String:      "UTF8STRING",
	Integer:         "INTEGER",
	DER:             "DER",
	Nil:             "NIL",
}

// valueTypeValues maps value type string descriptions to their values.
var valueTypeValues = map[string]ValueType{
	"IA5STRING":       IA5String,
	"PRINTABLESTRING": PrintableString,
	"UTF8STRING":      UTF8String,
	"INTEGER":         Integer,
	"DER":             DER,
	"NIL":             Nil,
}

// presenceDescriptions maps presence values to their string descriptions.
var presenceDescriptions = []string{
	Optional:  "OPTIONAL",
	Required:  "REQUIRED",
	Forbidden: "FORBIDDEN",
	Static:    "STATIC",
}

// presenceValues maps presence string descriptions to their values.
var presenceValues = map[string]Presence{
	"OPTIONAL":  Optional,
	"REQUIRED":  Required,
	"FORBIDDEN": Forbidden,
	"STATIC":    Static,
}

// keyTypeDescriptions maps key type values to their string descriptions.
var keyTypeDescriptions = []string{
	RSA:   "RSA",
	ECDSA: "ECDSA",
}

// keyTypeValues maps key type string descriptions to their values.
var keyTypeValues = map[string]KeyType{
	"RSA":   RSA,
	"ECDSA": ECDSA,
}

// keyFormatDescriptions maps key format values to their string descriptions.
var keyFormatDescriptions = []string{
	PKCS8:  "PKCS8",
	PKCS10: "PKCS10",
}

// keyFormatValues maps key format string descriptions to their values.
var keyFormatValues = map[string]KeyFormat{
	"PKCS8":  PKCS8,
	"PKCS10": PKCS10,
}

// optionalStaticPresenceDescriptions maps QC compliance values to their string
// descriptions.
var optionalStaticPresenceDescriptions = []string{
	StaticOptional: "OPTIONAL",
	StaticTrue:     "STATIC_TRUE",
	StaticFalse:    "STATIC_FALSE",
}

// optionalStaticPresenceValuess maps optional static presence value string
// descriptions to their values.
var optionalStaticPresenceValues = map[string]OptionalStaticPresence{
	"OPTIONAL":     StaticOptional,
	"STATIC_TRUE":  StaticTrue,
	"STATIC_FALSE": StaticFalse,
}

// MarshalJSON returns the JSON encoding of a validation policy.
func (p Policy) MarshalJSON() ([]byte, error) {
	// These types allow us to unmarshal the policy without repeating a bunch
	// of fields. `noRecur` prevents this function from being called in
	// infinite recursion. Without it, if we were to use SubjectDNPolicy
	// directly, this function would be called until a stack overflow occured.
	type noRecur Policy
	type jsonPolicy struct {
		noRecur
		CustomExtensions customExtensionsPolicies `json:"custom_extensions"`
	}

	var data jsonPolicy
	data.noRecur = noRecur(p)
	data.CustomExtensions = customExtensionsPolicies(p.CustomExtensions)

	return json.Marshal(data)
}

// UnmarshalJSON parses a JSON-encoded validation policy and stores the result
// in the object.
func (p *Policy) UnmarshalJSON(b []byte) error {
	// These types allow us to unmarshal the policy without repeating a bunch
	// of fields. `noRecur` prevents this function from being called in
	// infinite recursion. Without it, if we were to use SubjectDNPolicy
	// directly, this function would be called until a stack overflow occured.
	type noRecur Policy
	type jsonPolicy struct {
		noRecur
		CustomExtensions customExtensionsPolicies `json:"custom_extensions"`
	}

	var data jsonPolicy
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*p = Policy(data.noRecur)
	p.CustomExtensions = []CustomExtensionsPolicy(data.CustomExtensions)

	return nil
}

// MarshalJSON returns the JSON encoding of a subject distinguished name
// policy.
func (p SubjectDNPolicy) MarshalJSON() ([]byte, error) {
	// These types allow us to unmarshal the policy without repeating a bunch
	// of fields. `noRecur` prevents this function from being called in
	// infinite recursion. Without it, if we were to use SubjectDNPolicy
	// directly, this function would be called until a stack overflow occured.
	type noRecur SubjectDNPolicy
	type jsonPolicy struct {
		noRecur
		ExtraAttributes typeAndValuePolicies `json:"extra_attributes"`
	}

	var data jsonPolicy
	data.noRecur = noRecur(p)
	data.ExtraAttributes = typeAndValuePolicies(p.ExtraAttributes)

	return json.Marshal(data)
}

// UnmarshalJSON parses a JSON-encoded subject distinguished name policy and
// stores the result in the object.
func (p *SubjectDNPolicy) UnmarshalJSON(b []byte) error {
	// These types allow us to unmarshal the policy without repeating a bunch
	// of fields. `noRecur` prevents this function from being called in
	// infinite recursion. Without it, if we were to use SubjectDNPolicy
	// directly, this function would be called until a stack overflow occured.
	type noRecur SubjectDNPolicy
	type jsonPolicy struct {
		noRecur
		ExtraAttributes typeAndValuePolicies `json:"extra_attributes"`
	}

	var data jsonPolicy
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*p = SubjectDNPolicy(data.noRecur)
	p.ExtraAttributes = []TypeAndValuePolicy(data.ExtraAttributes)

	return nil
}

// MarshalJSON returns the JSON encoding of a subject alternative names
// policy.
func (p SANPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSANPolicy{
		DNSNames:    p.DNSNames,
		Emails:      p.Emails,
		IPAddresses: p.IPAddresses,
		URIs:        p.URIs,
		OtherNames:  typeAndValuePolicies(p.OtherNames),
	})
}

// UnmarshalJSON parses a JSON-encoded subject alternative names policy and
// stores the result in the object.
func (p *SANPolicy) UnmarshalJSON(b []byte) error {
	var data jsonSANPolicy
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*p = SANPolicy{
		DNSNames:    data.DNSNames,
		Emails:      data.Emails,
		IPAddresses: data.IPAddresses,
		URIs:        data.URIs,
		OtherNames:  []TypeAndValuePolicy(data.OtherNames),
	}

	return nil
}

// MarshalJSON returns the JSON encoding of a subject directory attributes
// policy.
func (p SubjectDAPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonSubjectDAPolicy{
		Gender:               p.Gender,
		DateOfBirth:          p.DateOfBirth,
		PlaceOfBirth:         p.PlaceOfBirth,
		CountryOfCitizenship: p.CountryOfCitizenship,
		CountryOfResidence:   p.CountryOfResidence,
		ExtraAttributes:      typeAndValuePolicies(p.ExtraAttributes),
	})
}

// UnmarshalJSON parses a JSON-encoded subject directory attributes names
// policy and stores the result in the object.
func (p *SubjectDAPolicy) UnmarshalJSON(b []byte) error {
	var data jsonSubjectDAPolicy
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*p = SubjectDAPolicy{
		Gender:               data.Gender,
		DateOfBirth:          data.DateOfBirth,
		PlaceOfBirth:         data.PlaceOfBirth,
		CountryOfCitizenship: data.CountryOfCitizenship,
		CountryOfResidence:   data.CountryOfResidence,
		ExtraAttributes:      []TypeAndValuePolicy(data.ExtraAttributes),
	}

	return nil
}

// MarshalJSON returns the JSON encoding of a list of type and value policies.
func (p typeAndValuePolicies) MarshalJSON() ([]byte, error) {
	var result = []byte("{")

	for i, val := range p {
		if i != 0 {
			result = append(result, byte(','))
		}

		result = append(result, []byte(fmt.Sprintf(`"%s":`, val.OID.String()))...)

		var this, err = json.Marshal(val)
		if err != nil {
			return nil, err
		}

		result = append(result, this...)
	}

	result = append(result, byte('}'))

	return result, nil
}

// UnmarshalJSON parses a JSON-encoded list of type and value policies and
// and stores the result in the object.
func (p *typeAndValuePolicies) UnmarshalJSON(b []byte) error {
	var data map[string]TypeAndValuePolicy
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var result typeAndValuePolicies

	for key, value := range data {
		var oid, err = oids.StringToOID(key)
		if err != nil {
			return err
		}

		result = append(result, TypeAndValuePolicy{
			OID:         oid,
			Static:      value.Static,
			ValueType:   value.ValueType,
			ValueFormat: value.ValueFormat,
			MinCount:    value.MinCount,
			MaxCount:    value.MaxCount,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].OID.String() < result[j].OID.String()
	})

	*p = result

	return nil
}

// MarshalJSON returns the JSON encoding of a list of custom extensions
// policies.
func (p customExtensionsPolicies) MarshalJSON() ([]byte, error) {
	var result = []byte("{")

	for i, ext := range p {
		if i != 0 {
			result = append(result, byte(','))
		}

		result = append(result, []byte(fmt.Sprintf(`"%s":`, ext.OID.String()))...)

		var this, err = json.Marshal(ext)
		if err != nil {
			return nil, err
		}

		result = append(result, this...)
	}

	result = append(result, byte('}'))

	return result, nil
}

// UnmarshalJSON parses a JSON-encoded list of custom extensions policies
// and stores the result in the object.
func (p *customExtensionsPolicies) UnmarshalJSON(b []byte) error {
	var data map[string]CustomExtensionsPolicy
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var result customExtensionsPolicies

	for key, value := range data {
		var oid, err = oids.StringToOID(key)
		if err != nil {
			return err
		}

		result = append(result, CustomExtensionsPolicy{
			OID:         oid,
			Presence:    value.Presence,
			Critical:    value.Critical,
			ValueType:   value.ValueType,
			ValueFormat: value.ValueFormat,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].OID.String() < result[j].OID.String()
	})

	*p = result

	return nil
}

// isValid checks if a value is within a valid range.
func (v ValueType) isValid() bool {
	return v >= IA5String && v <= Nil
}

// String returns a description of the value type value.
func (v ValueType) String() string {
	if !v.isValid() {
		return "UNKNOWN VALUE_TYPE VALUE"
	}

	return valueTypeDescriptions[v]
}

// MarshalJSON returns the JSON encoding of a value type value.
func (v ValueType) MarshalJSON() ([]byte, error) {
	if !v.isValid() {
		return nil, fmt.Errorf("invalid value_type value: %d", v)
	}

	return json.Marshal(v.String())
}

// UnmarshalJSON parses a JSON-encoded value type value and stores the result
// in the object.
func (v *ValueType) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var value, ok = valueTypeValues[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("unknown value_type value %q", data)
	}

	*v = value

	return nil
}

// isValid checks if a value is within a valid range.
func (p Presence) isValid() bool {
	return p >= Optional && p <= Static
}

// String returns a description of the presence value.
func (p Presence) String() string {
	if !p.isValid() {
		return "UNKNOWN PRESENCE VALUE"
	}

	return presenceDescriptions[p]
}

// MarshalJSON returns the JSON encoding of a presence value.
func (p Presence) MarshalJSON() ([]byte, error) {
	if !p.isValid() {
		return nil, fmt.Errorf("invalid presence value: %d", p)
	}

	return json.Marshal(p.String())
}

// UnmarshalJSON parses a JSON-encoded presence value and stores the result in
// the object.
func (p *Presence) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var value, ok = presenceValues[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("unknown presence value %q", data)
	}

	*p = value

	return nil
}

// isValid checks if a value is within a valid range.
func (t KeyType) isValid() bool {
	return t >= RSA && t <= ECDSA
}

// String returns a description of the key type value.
func (t KeyType) String() string {
	if !t.isValid() {
		return "UNKNOWN KEY TYPE VALUE"
	}

	return keyTypeDescriptions[t]
}

// MarshalJSON returns the JSON encoding of a key type value.
func (t KeyType) MarshalJSON() ([]byte, error) {
	if !t.isValid() {
		return nil, fmt.Errorf("invalid key type value: %d", t)
	}

	return json.Marshal(t.String())
}

// UnmarshalJSON parses a JSON-encoded key type value and stores the result in
// the object.
func (t *KeyType) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var value, ok = keyTypeValues[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("unknown key type value %q", data)
	}

	*t = value

	return nil
}

// isValid checks if a value is within a valid range.
func (f KeyFormat) isValid() bool {
	return f >= PKCS8 && f <= PKCS10
}

// String returns a description of the key format value.
func (f KeyFormat) String() string {
	if !f.isValid() {
		return "UNKNOWN KEY FORMAT VALUE"
	}

	return keyFormatDescriptions[f]
}

// MarshalJSON returns the JSON encoding of a key format value.
func (f KeyFormat) MarshalJSON() ([]byte, error) {
	if !f.isValid() {
		return nil, fmt.Errorf("invalid key format value: %d", f)
	}

	return json.Marshal(f.String())
}

// UnmarshalJSON parses a JSON-encoded key format value and stores the result in
// the object.
func (f *KeyFormat) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var value, ok = keyFormatValues[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("unknown key format value %q", data)
	}

	*f = value

	return nil
}

// isValid checks if a value is within a valid range.
func (v OptionalStaticPresence) isValid() bool {
	return v >= StaticOptional && v <= StaticFalse
}

// String returns a description of the optional static presence value.
func (v OptionalStaticPresence) String() string {
	if !v.isValid() {
		return "UNKNOWN OPTIONAL STATIC PRESENCE VALUE"
	}

	return optionalStaticPresenceDescriptions[v]
}

// MarshalJSON returns the JSON encoding of an optional static presence value.
func (v OptionalStaticPresence) MarshalJSON() ([]byte, error) {
	if !v.isValid() {
		return nil, fmt.Errorf("invalid optional static presence value: %d", v)
	}

	return json.Marshal(v.String())
}

// UnmarshalJSON parses a JSON-encoded optional static presence value and
// stores the result in the object.
func (v *OptionalStaticPresence) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var value, ok = optionalStaticPresenceValues[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("unknown optional static presence value %q", data)
	}

	*v = value

	return nil
}
