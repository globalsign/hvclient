/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package oids

import (
	"encoding/asn1"
	"strconv"
	"strings"
)

// Common object identifiers.
var (
	OIDKeyUsage                      = asn1.ObjectIdentifier{2, 5, 29, 15}
	OIDExtendedKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 37}
	OIDSubjectEmail                  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
	OIDSubjectJOILocality            = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 1}
	OIDSubjectJOIState               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 2}
	OIDSubjectJOICountry             = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 60, 2, 1, 3}
	OIDSubjectBusinessCategory       = asn1.ObjectIdentifier{2, 5, 4, 15}
	OIDSubjectDA                     = asn1.ObjectIdentifier{2, 5, 29, 9}
	OIDSubjectDADateOfBirth          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 1}
	OIDSubjectDAPlaceOfBirth         = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 2}
	OIDSubjectDAGender               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 3}
	OIDSubjectDACountryOfCitizenship = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 4}
	OIDSubjectDACountryOfResidence   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 9, 5}
)

// StringToOID converts a string representation of an OID to an
// asn1.ObjectIdentifier object.
func StringToOID(s string) (asn1.ObjectIdentifier, error) {
	var oid = asn1.ObjectIdentifier{}

	for _, n := range strings.Split(strings.TrimSpace(s), ".") {
		var value int
		var err error

		if value, err = strconv.Atoi(n); err != nil {
			return nil, err
		}

		oid = append(oid, value)
	}

	return oid, nil
}
