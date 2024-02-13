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
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestCheckOneValue(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		values []string
		want   bool
	}{
		{
			values: []string{},
			want:   false,
		},
		{
			values: []string{"value"},
			want:   true,
		},
		{
			values: []string{"value", ""},
			want:   true,
		},
		{
			values: []string{"value", "another value"},
			want:   false,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(fmt.Sprintf("%v", tc.values), func(t *testing.T) {
			t.Parallel()

			if got := checkOneValue(tc.values...); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCheckAllEmpty(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		values []string
		want   bool
	}{
		{
			values: []string{},
			want:   true,
		},
		{
			values: []string{""},
			want:   true,
		},
		{
			values: []string{"", ""},
			want:   true,
		},
		{
			values: []string{"value"},
			want:   false,
		},
		{
			values: []string{"value", ""},
			want:   false,
		},
		{
			values: []string{"", "value"},
			want:   false,
		},
		{
			values: []string{"value", "another value"},
			want:   false,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(fmt.Sprintf("%v", tc.values), func(t *testing.T) {
			t.Parallel()

			if got := checkAllEmpty(tc.values...); got != tc.want {
				t.Errorf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestStringToOIDs(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value string
		want  []asn1.ObjectIdentifier
	}{
		{
			value: "1",
			want: []asn1.ObjectIdentifier{
				{1},
			},
		},
		{
			value: "  1.2.3,  4.5.6 ",
			want: []asn1.ObjectIdentifier{
				{1, 2, 3},
				{4, 5, 6},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got, err = stringToOIDs(tc.value)
			if err != nil {
				t.Fatalf("couldn't convert string to OIDs: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringToOIDsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"",
		"not an oid",
		"1.2.not_a_digit",
		"1.2.not_a_digit, 1.2.3",
		"1.2.3, 4.5.not_a_digit",
		"1.2.3,",
		",1.2.3",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := stringToOIDs(tc); err == nil {
				t.Fatalf("unexpectedly converted strings to OIDs: %v", got)
			}
		})
	}
}

func TestStringToIPs(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value string
		want  []net.IP
	}{
		{
			value: "10.0.0.1",
			want: []net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			value: " 192.168.1.1  ,  192.168.1.2 ",
			want: []net.IP{
				net.ParseIP("192.168.1.1"),
				net.ParseIP("192.168.1.2"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got, err = stringToIPs(tc.value)
			if err != nil {
				t.Fatalf("couldn't convert string to IP addresses: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestStringToIPsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"",
		"not an IP address",
		"10.0.0.not_a_digit",
		"10.0.0.1,",
		",10.0.0.1",
		"10.0.0.1, not an IP address",
		"not an IP address, 10.0.0.1",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := stringToIPs(tc); err == nil {
				t.Fatalf("unexpectedly converted string to IP addresses: %v", got)
			}
		})
	}
}

func TestStringToURIs(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value string
		want  []*url.URL
	}{
		{
			value: "http://www.example.com",
			want: []*url.URL{
				testhelpers.MustParseURI(t, "http://www.example.com"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got, err = stringToURIs(tc.value)
			if err != nil {
				t.Fatalf("couldn't convert string to URIs: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringToURIsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"http://www.example.com,",
		",http://www.example.com",
		",",
		"http://www.example.com, $http://bad.uri",
		"$http://bad.uri, http://www.example.com",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := stringToURIs(tc); err == nil {
				t.Fatalf("unexpectedly converted string to URIs: %v", got)
			}
		})
	}
}

func TestStringToOIDAndStrings(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value string
		want  []hvclient.OIDAndString
	}{
		{
			value: "1.2.3.4=some value,5.6.7 =  some other value",
			want: []hvclient.OIDAndString{
				{
					OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
					Value: "some value",
				},
				{
					OID:   asn1.ObjectIdentifier{5, 6, 7},
					Value: "some other value",
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got, err = stringToOIDAndStrings(tc.value)
			if err != nil {
				t.Fatalf("couldn't convert string to OIDAndStrings: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringToOIDAndStringsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"not even close",
		",",
		"not an oid=a value",
		"1.2.3.4",
		"1.2.3.4=",
		"=a value",
		"1.2.3.4=a value=another value",
		"1.2.3.4=a value,",
		"1.2.3.4=a value,5.6.7",
		"1.2.3.4=a value,=another value",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := stringToOIDAndStrings(tc); err == nil {
				t.Fatalf("unexpectedly converted string to OIDAndStrings: %v", got)
			}
		})
	}
}
