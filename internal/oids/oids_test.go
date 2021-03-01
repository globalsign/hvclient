/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package oids_test

import (
	"encoding/asn1"
	"reflect"
	"testing"

	"github.com/globalsign/hvclient/internal/oids"
)

func TestStringToOID(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value string
		want  asn1.ObjectIdentifier
	}{
		{
			"1",
			asn1.ObjectIdentifier{1},
		},
		{
			"1.2.3.4",
			asn1.ObjectIdentifier{1, 2, 3, 4},
		},
		{
			"     5.6.7    ",
			asn1.ObjectIdentifier{5, 6, 7},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got asn1.ObjectIdentifier
			var err error

			if got, err = oids.StringToOID(tc.value); err != nil {
				t.Fatalf("couldn't convert string to OID: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringToOIDFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"",
		"not an oid",
		"1.2.not_a_digit",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := oids.StringToOID(tc); err == nil {
				t.Fatalf("unexpectedly converted string to OID: %v", got)
			}
		})
	}
}
