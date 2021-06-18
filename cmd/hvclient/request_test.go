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
	"errors"
	"net"
	"net/url"
	"reflect"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

func TestGetRequestFromTemplate(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		want     hvclient.Request
	}{
		{
			"",
			hvclient.Request{},
		},
		{
			"testdata/test.tmpl",
			hvclient.Request{
				Subject: &hvclient.DN{
					Organization: "ACME Inc",
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.filename, func(t *testing.T) {
			t.Parallel()

			var got, err = getRequestFromTemplateOrNew(tc.filename)
			if err != nil {
				t.Fatalf("couldn't get request from template: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestGetRequestFromTemplateFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"no_such_file",
		"testdata/test_bad_json.tmpl",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if got, err := getRequestFromTemplateOrNew(tc); err == nil {
				t.Fatalf("unexpectedly got request from template: %v", got)
			}
		})
	}
}

func TestBuildValidity(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name                          string
		initial                       *hvclient.Validity
		notbefore, notafter, duration string
		want                          *hvclient.Validity
	}{
		{
			"InitialNilAndNoFields",
			nil,
			"",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Unix(0, 0),
			},
		},
		{
			"InitialEmptyAndNoFields",
			nil,
			"",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Unix(0, 0),
			},
		},
		{
			"InitialNilAndNotBeforeField",
			nil,
			"2019-02-18T17:47:35UTC",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Unix(0, 0),
			},
		},
		{
			"InitialNilAndNotAfterField",
			nil,
			"",
			"2319-05-18T17:47:35UTC",
			"",
			&hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Date(2319, 5, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialNilAndNotBeforeNotAfterFields",
			nil,
			"2019-05-18T17:47:35UTC",
			"2319-05-18T17:47:35UTC",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2319, 5, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialNilAndDurationField",
			nil,
			"",
			"",
			"30d",
			&hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Now().Add(time.Hour * 24 * 30),
			},
		},
		{
			"InitialNoNotAfter",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Unix(0, 0),
			},
		},
		{
			"InitialNoNotBefore",
			&hvclient.Validity{
				NotAfter: time.Date(2319, 2, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Now(),
				NotAfter:  time.Date(2319, 2, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialSetAndNoFields",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialSetAndNotBeforeField",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
			"2019-03-18T17:47:35UTC",
			"",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 3, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialSetAndNotAfterField",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"2019-04-18T17:47:35UTC",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 4, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialSetAndNotBeforeNotAfterField",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
			"2019-03-18T17:47:35UTC",
			"2019-04-18T17:47:35UTC",
			"",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 3, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 4, 18, 17, 47, 35, 0, time.UTC),
			},
		},
		{
			"InitialSetAndDurationField",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 5, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"30d",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 3, 20, 17, 47, 35, 0, time.UTC),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = buildValidity(tc.initial, tc.notbefore, tc.notafter, tc.duration)
			if err != nil {
				t.Fatalf("couldn't build validity: %v", err)
			}

			testValiditiesAlmostEqual(t, got, tc.want)
		})
	}
}

func TestBuildValidityFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name                          string
		initial                       *hvclient.Validity
		notbefore, notafter, duration string
	}{
		{
			"BadNotBefore",
			nil,
			"not a valid time",
			"",
			"",
		},
		{
			"BadNotAfter",
			nil,
			"",
			"not a valid time",
			"",
		},
		{
			"BadDuration",
			nil,
			"",
			"",
			"not a valid duration",
		},
		{
			"InitialNotBeforeLater",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 1, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"",
		},
		{
			"InitialNotBeforeSame",
			&hvclient.Validity{
				NotBefore: time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
				NotAfter:  time.Date(2019, 2, 18, 17, 47, 35, 0, time.UTC),
			},
			"",
			"",
			"",
		},
		{
			"FieldsNotBeforeLater",
			nil,
			"2019-02-18T17:47:35UTC",
			"2019-01-18T17:47:35UTC",
			"",
		},
		{
			"FieldsNotBeforeSame",
			nil,
			"2019-02-18T17:47:35UTC",
			"2019-02-18T17:47:35UTC",
			"",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := buildValidity(tc.initial, tc.notbefore, tc.notafter, tc.duration); err == nil {
				t.Fatalf("unexpectedly built validity: %v", got)
			}
		})
	}
}

func testValiditiesAlmostEqual(t *testing.T, first, second *hvclient.Validity) {
	t.Helper()

	if first == nil && second == nil {
		return
	}

	if (first == nil && second != nil) || (first != nil && second == nil) {
		t.Fatalf("got %v, want %v", first, second)
	}

	var epsilon = time.Second

	if !first.NotBefore.Round(epsilon).Equal(second.NotBefore.Round(epsilon)) {
		t.Fatalf("got %v, want %v", first, second)
	}

	if !first.NotAfter.Round(epsilon).Equal(second.NotAfter.Round(epsilon)) {
		t.Fatalf("got %v, want %v", first, second)
	}
}

func TestBuildDN(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		initial *hvclient.DN
		values  subjectValues
		want    *hvclient.DN
	}{
		{
			"InitialNilAndNoValues",
			nil,
			subjectValues{},
			nil,
		},
		{
			"InitialEmptyAndNoValues",
			&hvclient.DN{},
			subjectValues{},
			&hvclient.DN{},
		},
		{
			"InitialNilAndValuesSet",
			nil,
			subjectValues{
				commonName:         "Jane Doe",
				organization:       "ACME Inc",
				organizationalUnit: "Marketing, Sales",
				streetAddress:      "1 Acme Street",
				locality:           "Douglas",
				state:              "Isle of Man",
				country:            "IM",
			},
			&hvclient.DN{
				CommonName:         "Jane Doe",
				Organization:       "ACME Inc",
				OrganizationalUnit: []string{"Marketing", "Sales"},
				StreetAddress:      "1 Acme Street",
				Locality:           "Douglas",
				State:              "Isle of Man",
				Country:            "IM",
			},
		},
		{
			"InitialSetAndNoValues",
			&hvclient.DN{
				CommonName:         "John Doe",
				Organization:       "GMO GlobalSign",
				OrganizationalUnit: []string{"Operations", "Development"},
				StreetAddress:      "1 GlobalSign Road",
				Locality:           "London",
				State:              "London",
				Country:            "GB",
			},
			subjectValues{},
			&hvclient.DN{
				CommonName:         "John Doe",
				Organization:       "GMO GlobalSign",
				OrganizationalUnit: []string{"Operations", "Development"},
				StreetAddress:      "1 GlobalSign Road",
				Locality:           "London",
				State:              "London",
				Country:            "GB",
			},
		},
		{
			"OverrideAllValues",
			&hvclient.DN{
				CommonName:         "John Doe",
				Organization:       "GMO GlobalSign",
				OrganizationalUnit: []string{"Operations", "Development"},
				StreetAddress:      "1 GlobalSign Road",
				Locality:           "London",
				State:              "London",
				Country:            "GB",
			},
			subjectValues{
				commonName:         "Jane Doe",
				organization:       "ACME Inc",
				organizationalUnit: "Marketing, Sales",
				streetAddress:      "1 Acme Street",
				locality:           "Douglas",
				state:              "Isle of Man",
				country:            "IM",
			},
			&hvclient.DN{
				CommonName:         "Jane Doe",
				Organization:       "ACME Inc",
				OrganizationalUnit: []string{"Operations", "Development", "Marketing", "Sales"},
				StreetAddress:      "1 Acme Street",
				Locality:           "Douglas",
				State:              "Isle of Man",
				Country:            "IM",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = buildDN(tc.initial, tc.values)
			if err != nil {
				t.Fatalf("couldn't build DN: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildDNFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		initial *hvclient.DN
		values  subjectValues
	}{
		{
			"InitialNilAndValuesSet",
			nil,
			subjectValues{
				organizationalUnit: "Marketing, Sales, ",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := buildDN(tc.initial, tc.values); err == nil {
				t.Fatalf("unexpectedly built DN: %v", got)
			}
		})
	}
}

func TestBuildSAN(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name                        string
		initial                     *hvclient.SAN
		dnsnames, emails, ips, uris string
		want                        *hvclient.SAN
	}{
		{
			"InitialNilAndNoFields",
			nil,
			"",
			"",
			"",
			"",
			nil,
		},
		{
			"InitialNil",
			nil,
			"a.domain,another.domain",
			"a@email.com",
			"10.0.0.1, 192.168.1.1",
			"http://www.example.com, ftp://ftp.example.com",
			&hvclient.SAN{
				DNSNames: []string{"a.domain", "another.domain"},
				Emails:   []string{"a@email.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("192.168.1.1"),
				},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.example.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.example.com"),
				},
			},
		},
		{
			"InitialEmpty",
			&hvclient.SAN{},
			"some.domain",
			"",
			"",
			"http://www.fishing.com, ftp://ftp.fishing.com",
			&hvclient.SAN{
				DNSNames: []string{"some.domain"},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.fishing.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.fishing.com"),
				},
			},
		},
		{
			"NoValues",
			&hvclient.SAN{
				DNSNames: []string{"a.domain", "another.domain"},
				Emails:   []string{"a@email.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("192.168.1.1"),
				},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.example.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.example.com"),
				},
			},
			"",
			"",
			"",
			"",
			&hvclient.SAN{
				DNSNames: []string{"a.domain", "another.domain"},
				Emails:   []string{"a@email.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("192.168.1.1"),
				},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.example.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.example.com"),
				},
			},
		},
		{
			"Appending",
			&hvclient.SAN{
				DNSNames: []string{"a.domain", "another.domain"},
				Emails:   []string{"a@email.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("192.168.1.1"),
				},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.example.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.example.com"),
				},
			},
			"yet.another.domain",
			"b@email.com, c@email.com",
			"10.0.0.2, 192.168.1.2",
			"gopher://gopher.example.com",
			&hvclient.SAN{
				DNSNames: []string{"a.domain", "another.domain", "yet.another.domain"},
				Emails:   []string{"a@email.com", "b@email.com", "c@email.com"},
				IPAddresses: []net.IP{
					net.ParseIP("10.0.0.1"),
					net.ParseIP("192.168.1.1"),
					net.ParseIP("10.0.0.2"),
					net.ParseIP("192.168.1.2"),
				},
				URIs: []*url.URL{
					testhelpers.MustParseURI(t, "http://www.example.com"),
					testhelpers.MustParseURI(t, "ftp://ftp.example.com"),
					testhelpers.MustParseURI(t, "gopher://gopher.example.com"),
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = buildSAN(tc.initial, tc.dnsnames, tc.emails, tc.ips, tc.uris)
			if err != nil {
				t.Fatalf("couldn't build SAN: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildSANFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name                        string
		initial                     *hvclient.SAN
		dnsnames, emails, ips, uris string
	}{
		{
			"MissingDomain",
			nil,
			"a.domain,",
			"",
			"",
			"",
		},
		{
			"MissingEmail",
			nil,
			"",
			",a@email.com",
			"",
			"",
		},
		{
			"MissingIPAddress",
			nil,
			"",
			"",
			"10.0.0.1,",
			"",
		},
		{
			"MissingURI",
			nil,
			"",
			"",
			"",
			",http://www.example.com",
		},
		{
			"BadIPAddress",
			nil,
			"",
			"",
			"not an IP address",
			"",
		},
		{
			"BadURL",
			nil,
			"",
			"",
			"",
			"$http://www.example.com",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := buildSAN(tc.initial, tc.dnsnames, tc.emails, tc.ips, tc.uris); err == nil {
				t.Fatalf("unexpectedly built SAN: %v", got)
			}
		})
	}
}

func TestBuildEKUs(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		initial []asn1.ObjectIdentifier
		field   string
		want    []asn1.ObjectIdentifier
	}{
		{
			"InitialNilAndNoField",
			nil,
			"",
			nil,
		},
		{
			"InitialNil",
			nil,
			"1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
			},
		},
		{
			"InitialEmpty",
			[]asn1.ObjectIdentifier{},
			"1.3.6.1.5.5.7.3.1, 1.3.6.1.5.5.7.3.2",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
			},
		},
		{
			"NoField",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
			},
			"",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
			},
		},
		{
			"Append",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
			},
			"1.3.6.1.5.5.7.3.3, 1.3.6.1.5.5.7.3.4",
			[]asn1.ObjectIdentifier{
				{1, 3, 6, 1, 5, 5, 7, 3, 1},
				{1, 3, 6, 1, 5, 5, 7, 3, 2},
				{1, 3, 6, 1, 5, 5, 7, 3, 3},
				{1, 3, 6, 1, 5, 5, 7, 3, 4},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = buildEKUs(tc.initial, tc.field)
			if err != nil {
				t.Fatalf("couldn't build EKUs: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildEKUsFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		initial []asn1.ObjectIdentifier
		field   string
	}{
		{
			"MissingEKUTrailing",
			nil,
			"1.3.6.1.5.5.7.3.1,",
		},
		{
			"MissingEKULeading",
			nil,
			",1.3.6.1.5.5.7.3.1",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := buildEKUs(tc.initial, tc.field); err == nil {
				t.Fatalf("unexpectedly built EKUs: %v", got)
			}
		})
	}
}

func TestGetKeys(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name        string
		public      string
		private     string
		csr         string
		pfunc       func(string, bool) (string, error)
		wantpublic  interface{}
		wantprivate interface{}
		wantcsr     *x509.CertificateRequest
	}{
		{
			"RSAPublicKey",
			"testdata/rsa_pub.key",
			"",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
			testhelpers.MustGetPublicKeyFromFile(t, "testdata/rsa_pub.key"),
			nil,
			nil,
		},
		{
			"ECPublicKey",
			"testdata/ec_pub.key",
			"",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
			testhelpers.MustGetPublicKeyFromFile(t, "testdata/ec_pub.key"),
			nil,
			nil,
		},
		{
			"RSAPrivateKey",
			"",
			"testdata/rsa_priv.key",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
			nil,
			testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
			nil,
		},
		{
			"ECPrivateKey",
			"",
			"testdata/ec_priv.key",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
			nil,
			testhelpers.MustGetPrivateKeyFromFile(t, "testdata/ec_priv.key"),
			nil,
		},
		{
			"EncryptedRSAPrivateKey",
			"",
			"testdata/rsa_priv_enc.key",
			"",
			func(s string, b bool) (string, error) {
				return "strongpassword", nil
			},
			nil,
			testhelpers.MustGetPrivateKeyFromFileWithPassword(t, "testdata/rsa_priv_enc.key", "strongpassword"),
			nil,
		},
		{
			"EncryptedECPrivateKey",
			"",
			"testdata/ec_priv_enc.key",
			"",
			func(s string, b bool) (string, error) {
				return "somesecret", nil
			},
			nil,
			testhelpers.MustGetPrivateKeyFromFileWithPassword(t, "testdata/ec_priv_enc.key", "somesecret"),
			nil,
		},
		{
			"CSR",
			"",
			"",
			"testdata/request.p10",
			func(s string, b bool) (string, error) {
				return "", nil
			},
			nil,
			nil,
			testhelpers.MustGetCSRFromFile(t, "testdata/request.p10"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotpublic, gotprivate, gotcsr, err = getKeys(
				tc.public,
				tc.private,
				tc.csr,
				tc.pfunc,
			)
			if err != nil {
				t.Fatalf("couldn't get keys: %v", err)
			}

			if !reflect.DeepEqual(gotpublic, tc.wantpublic) {
				t.Errorf("public keys, got %v, want %v", gotpublic, tc.wantpublic)
			}

			if !reflect.DeepEqual(gotprivate, tc.wantprivate) {
				t.Errorf("private keys, got %v, want %v", gotprivate, tc.wantprivate)
			}

			if !reflect.DeepEqual(gotcsr, tc.wantcsr) {
				t.Errorf("CSRs, got %v, want %v", gotcsr, tc.wantcsr)
			}
		})
	}
}

func TestGetKeysFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		public  string
		private string
		csr     string
		pfunc   func(string, bool) (string, error)
	}{
		{
			"NoKeys",
			"",
			"",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
		{
			"PublicAndPrivateKeys",
			"testdata/rsa_pub.key",
			"testdata/rsa_priv.key",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
		{
			"PublicKeyAndCSR",
			"testdata/rsa_pub.key",
			"",
			"testdata/request.p10",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
		{
			"MissingPublicKeyFile",
			"no_such_file",
			"",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
		{
			"MissingPrivateKeyFile",
			"",
			"no_such_file",
			"",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
		{
			"BadPrivateKeyPassword",
			"",
			"testdata/rsa_priv_enc.key",
			"",
			func(s string, b bool) (string, error) {
				return "not_the_right_password", nil
			},
		},
		{
			"BadPrivateKeyPassword",
			"",
			"testdata/rsa_priv_enc.key",
			"",
			func(s string, b bool) (string, error) {
				return "strongpassword", errors.New("deliberately fail")
			},
		},
		{
			"MissingCSR",
			"",
			"",
			"no_such_file",
			func(s string, b bool) (string, error) {
				return "", nil
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, _, _, err := getKeys(
				tc.public,
				tc.private,
				tc.csr,
				tc.pfunc,
			); err == nil {
				t.Errorf("unexpectedly got keys")
			}
		})
	}
}

func TestBuildRequest(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		values *requestValues
		want   hvclient.Request
	}{
		{
			"one",
			&requestValues{
				template: "testdata/test_build.tmpl",
				validity: validityValues{
					notBefore: "2019-02-18T09:31:00UTC",
					notAfter:  "2019-05-18T09:31:00UTC",
				},
				subject: subjectValues{
					commonName:         "Jane Doe",
					organization:       "ACME Inc",
					organizationalUnit: "Marketing, Rat Control",
					streetAddress:      "1 Lizard Drive",
					locality:           "Penzance",
					state:              "Cornwall",
					country:            "GB",
				},
				san: sanValues{
					dnsNames: "lizard.acme.com",
					emails:   "jane@acme.com, ratter@acme.com",
					ips:      "192.168.1.42",
					uris:     "lizard.acme.com, rat.acme.com",
				},
				ekus:       "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2",
				privatekey: "testdata/rsa_priv.key",
			},
			hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Date(2019, 2, 18, 9, 31, 0, 0, time.UTC),
					NotAfter:  time.Date(2019, 5, 18, 9, 31, 0, 0, time.UTC),
				},
				Subject: &hvclient.DN{
					CommonName:         "Jane Doe",
					Organization:       "ACME Inc",
					OrganizationalUnit: []string{"Marketing", "Rat Control"},
					StreetAddress:      "1 Lizard Drive",
					Locality:           "Penzance",
					State:              "Cornwall",
					Country:            "GB",
				},
				SAN: &hvclient.SAN{
					DNSNames: []string{
						"template.domain.com",
						"lizard.acme.com",
					},
					Emails: []string{
						"template@domain.com",
						"jane@acme.com",
						"ratter@acme.com",
					},
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.1"),
						net.ParseIP("192.168.1.42"),
					},
					URIs: []*url.URL{
						testhelpers.MustParseURI(t, "www.template.domain.com"),
						testhelpers.MustParseURI(t, "lizard.acme.com"),
						testhelpers.MustParseURI(t, "rat.acme.com"),
					},
					OtherNames: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
							Value: "template@domain.com",
						},
					},
				},
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 4},
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
				CustomExtensions: []hvclient.OIDAndString{
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
						Value: "NIL",
					},
				},
				PrivateKey: testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
			},
		},
		{
			"publickey",
			&requestValues{
				validity: validityValues{
					notBefore: "2019-02-18T09:31:00UTC",
					notAfter:  "2019-05-18T09:31:00UTC",
				},
				subject: subjectValues{
					commonName: "Jane Doe",
				},
				publickey: "testdata/rsa_pub.key",
			},
			hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Date(2019, 2, 18, 9, 31, 0, 0, time.UTC),
					NotAfter:  time.Date(2019, 5, 18, 9, 31, 0, 0, time.UTC),
				},
				Subject: &hvclient.DN{
					CommonName: "Jane Doe",
				},
				PublicKey: testhelpers.MustGetPublicKeyFromFile(t, "testdata/rsa_pub.key"),
			},
		},
		{
			"gencsr",
			&requestValues{
				validity: validityValues{
					notBefore: "2019-02-18T09:31:00UTC",
					notAfter:  "2019-05-18T09:31:00UTC",
				},
				subject: subjectValues{
					commonName:         "Jane Doe",
					organization:       "ACME Inc",
					organizationalUnit: "Sales, Operations",
				},
				san: sanValues{
					emails: "jane@acme.com",
				},
				ekus:       "1.3.6.1.5.5.7.3.4",
				privatekey: "testdata/rsa_priv.key",
				gencsr:     true,
			},
			hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Date(2019, 2, 18, 9, 31, 0, 0, time.UTC),
					NotAfter:  time.Date(2019, 5, 18, 9, 31, 0, 0, time.UTC),
				},
				Subject: &hvclient.DN{
					CommonName:         "Jane Doe",
					Organization:       "ACME Inc",
					OrganizationalUnit: []string{"Sales", "Operations"},
				},
				SAN: &hvclient.SAN{
					Emails: []string{"jane@acme.com"},
				},
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 4},
				},
				CSR: testhelpers.MustGetCSRFromFile(t, "testdata/generated.p10"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var request, err = buildRequest(tc.values)
			if err != nil {
				t.Fatalf("couldn't build request: %v", err)
			}

			if !request.Equal(tc.want) {
				t.Errorf("got %v, want %v", request, tc.want)
			}

			if !reflect.DeepEqual(request.PublicKey, tc.want.PublicKey) {
				t.Errorf("public keys, got %v, want %v", request.PublicKey, tc.want.PublicKey)
			}

			if !reflect.DeepEqual(request.PrivateKey, tc.want.PrivateKey) {
				t.Errorf("private keys, got %v, want %v", request.PrivateKey, tc.want.PrivateKey)
			}

			if !reflect.DeepEqual(request.CSR, tc.want.CSR) {
				t.Errorf("CSRs, got %v, want %v", request.CSR, tc.want.CSR)
			}
		})
	}
}

func TestBuildRequestFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		values *requestValues
	}{
		{
			"TemplateFileDoesntExist",
			&requestValues{
				template: "no_such_file",
			},
		},
		{
			"BadValidity",
			&requestValues{
				validity: validityValues{
					notBefore: "2019-02-18T10:31:00UTC",
					notAfter:  "2019-01-18T10:31:00UTC",
				},
			},
		},
		{
			"BadSubject",
			&requestValues{
				subject: subjectValues{
					organizationalUnit: ",",
				},
			},
		},
		{
			"BadSAN",
			&requestValues{
				san: sanValues{
					dnsNames: ",",
				},
			},
		},
		{
			"BadEKUs",
			&requestValues{
				ekus: ".",
			},
		},
		{
			"BadKey",
			&requestValues{
				privatekey: "no_such_file",
			},
		},
		{
			"GenCSRNoPrivateKey",
			&requestValues{
				publickey: "testdata/rsa_pub.key",
				gencsr:    true,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if request, err := buildRequest(tc.values); err == nil {
				t.Fatalf("unexpectedly built request: %v", request)
			}
		})
	}
}
