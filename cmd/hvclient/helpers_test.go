/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package main

import (
	"encoding/asn1"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"testing"

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
			[]string{},
			false,
		},
		{
			[]string{"value"},
			true,
		},
		{
			[]string{"value", ""},
			true,
		},
		{
			[]string{"value", "another value"},
			false,
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
			[]string{},
			true,
		},
		{
			[]string{""},
			true,
		},
		{
			[]string{"", ""},
			true,
		},
		{
			[]string{"value"},
			false,
		},
		{
			[]string{"value", ""},
			false,
		},
		{
			[]string{"", "value"},
			false,
		},
		{
			[]string{"value", "another value"},
			false,
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
			"1",
			[]asn1.ObjectIdentifier{
				{1},
			},
		},
		{
			"  1.2.3,  4.5.6 ",
			[]asn1.ObjectIdentifier{
				{1, 2, 3},
				{4, 5, 6},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got []asn1.ObjectIdentifier
			var err error

			if got, err = stringToOIDs(tc.value); err != nil {
				t.Fatalf("couldn't convert string to OIDs: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
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
			"10.0.0.1",
			[]net.IP{
				net.ParseIP("10.0.0.1"),
			},
		},
		{
			" 192.168.1.1  ,  192.168.1.2 ",
			[]net.IP{
				net.ParseIP("192.168.1.1"),
				net.ParseIP("192.168.1.2"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got []net.IP
			var err error

			if got, err = stringToIPs(tc.value); err != nil {
				t.Fatalf("couldn't convert string to IP addresses: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
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
			"http://www.example.com",
			[]*url.URL{
				testhelpers.MustParseURI(t, "http://www.example.com"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.value, func(t *testing.T) {
			t.Parallel()

			var got []*url.URL
			var err error

			if got, err = stringToURIs(tc.value); err != nil {
				t.Fatalf("couldn't convert string to URIs: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
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
			"1.2.3.4=some value,5.6.7 =  some other value",
			[]hvclient.OIDAndString{
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

			var got []hvclient.OIDAndString
			var err error

			if got, err = stringToOIDAndStrings(tc.value); err != nil {
				t.Fatalf("couldn't convert string to OIDAndStrings: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
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
