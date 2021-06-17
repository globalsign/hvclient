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
		var value, err = strconv.Atoi(n)
		if err != nil {
			return nil, err
		}

		oid = append(oid, value)
	}

	return oid, nil
}
