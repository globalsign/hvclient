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

package oids_test

import (
	"encoding/asn1"
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
			value: "1",
			want:  asn1.ObjectIdentifier{1},
		},
		{
			value: "1.2.3.4",
			want:  asn1.ObjectIdentifier{1, 2, 3, 4},
		},
		{
			value: "     5.6.7    ",
			want:  asn1.ObjectIdentifier{5, 6, 7},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got, err = oids.StringToOID(tc.value)
			if err != nil {
				t.Fatalf("couldn't convert string to OID: %v", err)
			}

			if !got.Equal(tc.want) {
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
