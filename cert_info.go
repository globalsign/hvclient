/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// CertStatus is the issued/revoked status of a certificate.
type CertStatus int

// CertInfo contains a certificate and associated information as returned
// by an HVCA GET /certificates/{certificate} API call.
type CertInfo struct {
	PEM       string            // The PEM-encoded certificate
	X509      *x509.Certificate // The parsed certificate
	Status    CertStatus        // Issued or revoked
	UpdatedAt time.Time         // When the certificate was last updated
}

// jsonCertInfo is used internally for JSON marshalling/unmarshalling.
type jsonCertInfo struct {
	PEM       string     `json:"certificate"`
	Status    CertStatus `json:"status"`
	UpdatedAt int64      `json:"updated_at"`
}

// Certificate status values.
const (
	StatusIssued CertStatus = iota + 1
	StatusRevoked
)

// certStatusNames maps certificate status values to their string descriptions.
var certStatusNames = [...]string{
	StatusIssued:  "ISSUED",
	StatusRevoked: "REVOKED",
}

// certStatusCodes maps certificate status string descriptions to their values.
var certStatusCodes = map[string]CertStatus{
	"ISSUED":  StatusIssued,
	"REVOKED": StatusRevoked,
}

// isValid checks if a certificate status value is within a valid range.
func (s CertStatus) isValid() bool {
	return s >= StatusIssued && s <= StatusRevoked
}

// String returns a description of the certificate status.
func (s CertStatus) String() string {
	if !s.isValid() {
		return "ERROR: UNKNOWN STATUS"
	}

	return certStatusNames[s]
}

// MarshalJSON returns the JSON encoding of a certificate status value.
func (s CertStatus) MarshalJSON() ([]byte, error) {
	if !s.isValid() {
		return nil, fmt.Errorf("invalid certificate status value: %d", s)
	}

	return json.Marshal(s.String())
}

// UnmarshalJSON parses a JSON-encoded certificate status value and stores the
// result in the object.
func (s *CertStatus) UnmarshalJSON(b []byte) error {
	var data string
	var err error

	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}

	var ok bool
	var result CertStatus
	if result, ok = certStatusCodes[strings.ToUpper(data)]; !ok {
		return fmt.Errorf("invalid certificate status value: %s", data)
	}

	*s = result

	return nil
}

// Equal checks if two certificate metadata objects are equivalent.
func (s CertInfo) Equal(other CertInfo) bool {
	return s.PEM == other.PEM &&
		s.Status == other.Status &&
		s.UpdatedAt.Equal(other.UpdatedAt)
}

// MarshalJSON returns the JSON encoding of certificate metadata.
func (s CertInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonCertInfo{
		PEM:       s.PEM,
		Status:    s.Status,
		UpdatedAt: s.UpdatedAt.Unix(),
	})
}

// UnmarshalJSON parses JSON-encoded certificate metadata and stores the
// result in the object.
func (s *CertInfo) UnmarshalJSON(b []byte) error {
	var data *jsonCertInfo
	var err error

	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}

	var block *pem.Block
	var rest []byte
	block, _ = pem.Decode([]byte(data.PEM))

	if block == nil || len(block.Bytes) == 0 || len(rest) != 0 {
		return errors.New("bad PEM data")
	}

	var cert *x509.Certificate
	if cert, err = x509.ParseCertificate(block.Bytes); err != nil {
		return err
	}

	*s = CertInfo{
		PEM:       data.PEM,
		X509:      cert,
		Status:    data.Status,
		UpdatedAt: time.Unix(data.UpdatedAt, 0),
	}

	return nil
}
