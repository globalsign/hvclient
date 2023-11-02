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

package hvclient_test

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

const testRequestCSRPEM = `-----BEGIN CERTIFICATE REQUEST-----
MIID1jCCAr4CAQAwgYwxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZMb25kb24xDzAN
BgNVBAcTBkxvbmRvbjEaMBgGA1UECRMRMSBHbG9iYWxTaWduIFJvYWQxFzAVBgNV
BAoTDkdNTyBHbG9iYWxTaWduMRMwEQYDVQQLEwpPcGVyYXRpb25zMREwDwYDVQQD
EwhKb2huIERvZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANNRyiSc
rpzY/vPy+3tjTxz0gsLBO+fbT+dn15vX7VgWj0wp0nTQfdYg8oBxDqB4KMsnQjip
cEyoVv46pyPfmjlXDyLqqWQodCbsvjc+vxReG5AN6FC4/vKnXVMeVDS45H1fnHib
wNPlAPYADfH4wIIB6ZinYBK9G+tK6e0o6aoDSumVFgezqiZdASSmUaO+NtaCLFr1
KtBDBy7dUHZTfNORCz5Sq9w2XuM5jWspXb2PG6+Mr2bvFS6zB2CfiTrLGtYQZqsO
99De+NM4LEMR/9AuOdi+cfDJ6jrXg+SkaiNCgBL7E5ZD72X7TWSaiJ/cu2f4mg5C
suess+3JScoR5/UCAwEAAaCCAQIwgf8GCSqGSIb3DQEJDjGB8TCB7jCBvAYDVR0R
BIG0MIGxgh10ZXN0LmRlbW8uaHZjYS5nbG9iYWxzaWduLmNvbYIedGVzdDIuZGVt
by5odmNhLmdsb2JhbHNpZ24uY29tgR5hZG1pbkBkZW1vLmh2Y2EuZ2xvYmFsc2ln
bi5jb22BIGNvbnRhY3RAZGVtby5odmNhLmdsb2JhbHNpZ24uY29thwTGKdaahiho
dHRwOi8vdGVzdC5kZW1vLmh2Y2EuZ2xvYmFsc2lnbi5jb20vdXJpMAsGA1UdDwQE
AwIDqDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcN
AQELBQADggEBAJyVtFN3ykzNtEwxjwOJZdM1n6kBtVqI++n7Pvo7Y3w1mUZ3VSae
6JBNjudfazHWqZZo1Djy2uZxzwvow2RjmcjxHDL4siO/dKopAtZOdH5eFn3efzZc
nXZ2JQpmu2lauhQNh052k54qmy8lk86yVr7KBYx67ZPZkpPJMy3a5cEnByr26LnX
uyrFCzayZxSHwj4u178+PgzNz4avQWv1jaCSDmgvs423N3z2DP0r30LfsVPvKsr4
W9S7IjDr8TSVRpRCjx7M7QooOgovrKk08khTO4NDXO4FcJLcSsvb38QfvUeg/7WV
L+9OFs/MYElfTUTFQd36X+378dgeOiZCKG4=
-----END CERTIFICATE REQUEST-----`

const testRequestRSAPrivateKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7s0nIwA4nzrc5az0iD6F710WI2BnabCVe1wNXUckq7RdWXts
hlQODZow+M6t7P2FLolYYyhT9vD5hFlMNBKYFqAAkauGlmx12luVyURRLW0ht9Pi
u41MaLnLCCMM7tQ/5lixMHkT86sX/wX8q32ZOuatyUgVQUV1hKXZCH12y9VK9U3p
QGoPgG15SbCo6yfUYvYLp7NmNEb55Gz4I1xf4PBaRvynr0dtwbFXQOQAfg+q29sm
+elYnAQLvtVVyYmfn+jqK9u1Ey+X2sNns3HWz9OSQt7e9lFIKMlospQPl4YuGhfc
ID/xC1gZLV5wlvghFJx/1QUW/yI3MZGXpIavjwIDAQABAoIBAAOSJcesNSyMYMk+
cNmotbACoFYfFuzJqzKRCdIfQjkfFVZFNjY8A4nIiHrv/EHS+K7ddujkrXy/1btY
6n7M2GFeOyPygKy3Knv9apv73YrkWuC41mcfkcjvHk4c2BCqM9pp8RxccyPtpwo1
OLYHxsbOtEKSRV8Yfs1g/YHW/nPF0VfygvAGF1J6oJlYf/ToSQm7WCiTHjM+SeTp
8HO4SYyf/no2SRtL3783SAhtc6bi8yWo6P265ii1/+jVhUEIRL0cHsZbQQbSHdsK
vFdNVuuNSH/5BjsUB9YZd++gokcxQF7CboGFLOoTkmy5EYFfrXIuv/vcrpBoDzIl
xxEBIGECgYEA+o/BI23uZywuzU0p4qSq7MWtlduhycN303Hd3uZ6Ltn8mT9JKYjQ
41XQ1yfwwXc+poRUpfYFMgClCTK54V15X7yxdajG1RKn7ynBrOFTthyJvxY64fPu
4xrz78R3CntLM+jW52poiXfupFyc792kRcZ/gynTO9uYxkO4vr/ovm0CgYEA8/wN
liO3YzeF9znjbiLl7mbZNQjcpC7aWM+ZMNZKWYo0xa2j/03purl0BvcgJ/NUJJMR
0+rXpBi3qgkfFsJkbHVHKKHmBAgRaKZnPv2QfGsjJnApKN5EYFFpUPAN5MOJdXzM
pEQH4Pq609L6Y9+uBrR2SEOTcVHfOgSUnJtseGsCgYBWMrJND/qeP9LyCgPI1sF+
pxrqnR5xnO9SLLAZiMyr5Y5C4kS3JzxFmTY5bqIizHUfMBM27QYoh5Q/L9ZGs7OX
vgCG68NLdhmT65eXdAUqd3Lj7C/hn9ulAZa9+6bAUl4yw317K14/PKU6oinTUzq6
Tml7pB3pT8ilHJMn/DmDmQKBgQDKwQWRZXD61KNRhhvH5NxrN7D9b7XcAsuUzkAh
45K5wi6Er/3/JgI8F+2h9DAWwxGDq2w/TYOSbLAEb7wUL8tAjl1qGNCLPSEqdE6M
fC9cFbSKNt8dhUgROtZoWnVRTGWo6uMtBxP9FJ+5dDR8Vt/J1qIM/4tBuqXlEvVl
B4wmrQKBgQDVLrduSvRvxvwMUEtwwIwaItIoUqznPahGchBUq5GC5KO6ZumIsPrO
AIMQ+A6CRfM6fosSlbPccCAaja9aetlkLLQci+DQ/M8NSx2z8SS14R0urYFa4vG5
YOjziV1PjgyXO6N/qLSTio3vKMB95TTG1ao+osOio2PTlbeiToSa1g==
-----END RSA PRIVATE KEY-----`

const testRequestECPrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIM43mvNlIrjLeb/RcLX+SZKbzdOPu4LVSEBDMo5Fdu5WoAoGCCqGSM49
AwEHoUQDQgAETKbxjrMcHuXVmdmy0d1xSSjfY86UQlrBHFcYT3SHReVZZ0MdTjg/
9PNUrWDpkZ75q4pZV5EpMgqrIdSIEqCiuA==
-----END EC PRIVATE KEY-----`

const testRequestFullJSON = `{
    "validity": {
        "not_before": 1477958400,
        "not_after": 1509494400
    },
    "subject_dn": {
        "country": "GB",
        "state": "London",
        "locality": "London",
        "street_address": "1 GlobalSign Road",
        "organization": "GMO GlobalSign",
        "organizational_unit": [
            "Operations",
            "Development"
        ],
        "common_name": "John Doe",
        "serial_number": "1",
        "email": "john.doe@demo.hvca.globalsign.com",
        "jurisdiction_of_incorporation_locality_name": "London",
        "jurisdiction_of_incorporation_state_or_province_name": "London",
        "jurisdiction_of_incorporation_country_name": "United Kingdom",
        "business_category": "Internet security",
        "extra_attributes": [
            {
                "type": "2.5.4.4",
                "value": "Surname"
            }
        ]
    },
    "san": {
        "dns_names": [
            "test.demo.hvca.globalsign.com",
            "test2.demo.hvca.globalsign.com"
        ],
        "emails": [
            "admin@demo.hvca.globalsign.com",
            "contact@demo.hvca.globalsign.com"
        ],
        "ip_addresses": [
            "198.41.214.154"
        ],
        "uris": [
            "http://test.demo.hvca.globalsign.com/uri"
        ],
        "other_names": [
            {
                "type": "1.3.6.1.4.1.311.20.2.3",
                "value": "upn@demo.hvca.globalsign.com"
            }
        ]
    },
    "extended_key_usages": [
        "1.3.6.1.5.5.7.3.1",
        "1.3.6.1.5.5.7.3.2"
    ],
    "subject_da": {
        "gender": "m",
        "date_of_birth": "1979-01-31",
        "place_of_birth": "London",
        "country_of_citizenship": [
            "GB",
            "US"
        ],
        "country_of_residence": [
            "US"
        ],
        "extra_attributes": [
            {
                "type": "2.5.29.9.1.1.1"
            },
            {
                "type": "2.5.29.9.1.1.2",
                "value": "custom subject da value"
            }
        ]
    },
    "qualified_statements": {
        "semantics": {
            "identifier": "1.1.1.1.1.1",
            "name_authorities": [
                "contact@ra1.hvsign.globalsign.com"
            ]
        },
        "etsi_qc_compliance": true,
        "etsi_qc_sscd_compliance": true,
        "etsi_qc_type": "0.4.0.1862.1.6.1",
        "etsi_qc_retention_period": 1,
        "etsi_qc_pds": {
            "EN": "https://demo.hvsign.globalsign.com/en/pds",
            "RU": "https://demo.hvsign.globalsign.com/ru/pds"
        }
    },
    "ms_extension_template": {
        "id": "1.2.3.4",
        "major_version": 3,
        "minor_version": 7
    },
    "custom_extensions": {
        "2.5.29.99.1": "NIL",
        "2.5.29.99.2": "SOME TEXT"
    }
}`

var testRequestFullRequest = hvclient.Request{
	Validity: &hvclient.Validity{
		NotBefore: time.Unix(1477958400, 0),
		NotAfter:  time.Unix(1509494400, 0),
	},
	Subject: &hvclient.DN{
		CommonName:    "John Doe",
		SerialNumber:  "1",
		Country:       "GB",
		State:         "London",
		Locality:      "London",
		StreetAddress: "1 GlobalSign Road",
		Organization:  "GMO GlobalSign",
		OrganizationalUnit: []string{
			"Operations",
			"Development",
		},
		Email:            "john.doe@demo.hvca.globalsign.com",
		JOILocality:      "London",
		JOIState:         "London",
		JOICountry:       "United Kingdom",
		BusinessCategory: "Internet security",
		ExtraAttributes: []hvclient.OIDAndString{
			{
				OID:   asn1.ObjectIdentifier{2, 5, 4, 4},
				Value: "Surname",
			},
		},
	},
	SAN: &hvclient.SAN{
		DNSNames: []string{
			"test.demo.hvca.globalsign.com",
			"test2.demo.hvca.globalsign.com",
		},
		Emails: []string{
			"admin@demo.hvca.globalsign.com",
			"contact@demo.hvca.globalsign.com",
		},
		IPAddresses: []net.IP{
			net.ParseIP("198.41.214.154"),
		},
		URIs: []*url.URL{
			mustParseURI("http://test.demo.hvca.globalsign.com/uri"),
		},
		OtherNames: []hvclient.OIDAndString{
			{
				OID:   asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3},
				Value: "upn@demo.hvca.globalsign.com",
			},
		},
	},
	EKUs: []asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
	},
	DA: &hvclient.DA{
		Gender:               "m",
		DateOfBirth:          time.Date(1979, 1, 31, 12, 0, 0, 0, time.UTC),
		PlaceOfBirth:         "London",
		CountryOfCitizenship: []string{"GB", "US"},
		CountryOfResidence:   []string{"US"},
		ExtraAttributes: []hvclient.OIDAndString{
			{
				OID: asn1.ObjectIdentifier{2, 5, 29, 9, 1, 1, 1},
			},
			{
				OID:   asn1.ObjectIdentifier{2, 5, 29, 9, 1, 1, 2},
				Value: "custom subject da value",
			},
		},
	},
	QualifiedStatements: &hvclient.QualifiedStatements{
		Semantics: hvclient.Semantics{
			OID:             asn1.ObjectIdentifier{1, 1, 1, 1, 1, 1},
			NameAuthorities: []string{"contact@ra1.hvsign.globalsign.com"},
		},
		QCCompliance:      true,
		QCSSCDCompliance:  true,
		QCType:            asn1.ObjectIdentifier{0, 4, 0, 1862, 1, 6, 1},
		QCRetentionPeriod: 1,
		QCPDs: map[string]string{
			"EN": "https://demo.hvsign.globalsign.com/en/pds",
			"RU": "https://demo.hvsign.globalsign.com/ru/pds",
		},
	},
	MSExtension: &hvclient.MSExtension{
		OID:          asn1.ObjectIdentifier{1, 2, 3, 4},
		MajorVersion: 3,
		MinorVersion: 7,
	},
	CustomExtensions: []hvclient.OIDAndString{
		{
			OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
			Value: "NIL",
		},
		{
			OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 2},
			Value: "SOME TEXT",
		},
	},
}

func TestRequestMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		req  hvclient.Request
		want string
	}{
		{
			name: "Full",
			req:  testRequestFullRequest,
			want: testRequestFullJSON,
		},
		{
			name: "CSR",
			req: hvclient.Request{
				CSR: testhelpers.MustParseCSR(t, testRequestCSRPEM),
			},
			want: `{
    "public_key": "-----BEGIN CERTIFICATE REQUEST-----\nMIID1jCCAr4CAQAwgYwxCzAJBgNVBAYTAkdCMQ8wDQYDVQQIEwZMb25kb24xDzAN\nBgNVBAcTBkxvbmRvbjEaMBgGA1UECRMRMSBHbG9iYWxTaWduIFJvYWQxFzAVBgNV\nBAoTDkdNTyBHbG9iYWxTaWduMRMwEQYDVQQLEwpPcGVyYXRpb25zMREwDwYDVQQD\nEwhKb2huIERvZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANNRyiSc\nrpzY/vPy+3tjTxz0gsLBO+fbT+dn15vX7VgWj0wp0nTQfdYg8oBxDqB4KMsnQjip\ncEyoVv46pyPfmjlXDyLqqWQodCbsvjc+vxReG5AN6FC4/vKnXVMeVDS45H1fnHib\nwNPlAPYADfH4wIIB6ZinYBK9G+tK6e0o6aoDSumVFgezqiZdASSmUaO+NtaCLFr1\nKtBDBy7dUHZTfNORCz5Sq9w2XuM5jWspXb2PG6+Mr2bvFS6zB2CfiTrLGtYQZqsO\n99De+NM4LEMR/9AuOdi+cfDJ6jrXg+SkaiNCgBL7E5ZD72X7TWSaiJ/cu2f4mg5C\nsuess+3JScoR5/UCAwEAAaCCAQIwgf8GCSqGSIb3DQEJDjGB8TCB7jCBvAYDVR0R\nBIG0MIGxgh10ZXN0LmRlbW8uaHZjYS5nbG9iYWxzaWduLmNvbYIedGVzdDIuZGVt\nby5odmNhLmdsb2JhbHNpZ24uY29tgR5hZG1pbkBkZW1vLmh2Y2EuZ2xvYmFsc2ln\nbi5jb22BIGNvbnRhY3RAZGVtby5odmNhLmdsb2JhbHNpZ24uY29thwTGKdaahiho\ndHRwOi8vdGVzdC5kZW1vLmh2Y2EuZ2xvYmFsc2lnbi5jb20vdXJpMAsGA1UdDwQE\nAwIDqDAgBgNVHSUBAf8EFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDQYJKoZIhvcN\nAQELBQADggEBAJyVtFN3ykzNtEwxjwOJZdM1n6kBtVqI++n7Pvo7Y3w1mUZ3VSae\n6JBNjudfazHWqZZo1Djy2uZxzwvow2RjmcjxHDL4siO/dKopAtZOdH5eFn3efzZc\nnXZ2JQpmu2lauhQNh052k54qmy8lk86yVr7KBYx67ZPZkpPJMy3a5cEnByr26LnX\nuyrFCzayZxSHwj4u178+PgzNz4avQWv1jaCSDmgvs423N3z2DP0r30LfsVPvKsr4\nW9S7IjDr8TSVRpRCjx7M7QooOgovrKk08khTO4NDXO4FcJLcSsvb38QfvUeg/7WV\nL+9OFs/MYElfTUTFQd36X+378dgeOiZCKG4=\n-----END CERTIFICATE REQUEST-----"
}`,
		},
		{
			name: "RSAPrivateKey",
			req: hvclient.Request{
				PrivateKey: testhelpers.MustParseRSAPrivateKey(t, testRequestRSAPrivateKeyPEM),
			},
			want: `{
    "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7s0nIwA4nzrc5az0iD6F\n710WI2BnabCVe1wNXUckq7RdWXtshlQODZow+M6t7P2FLolYYyhT9vD5hFlMNBKY\nFqAAkauGlmx12luVyURRLW0ht9Piu41MaLnLCCMM7tQ/5lixMHkT86sX/wX8q32Z\nOuatyUgVQUV1hKXZCH12y9VK9U3pQGoPgG15SbCo6yfUYvYLp7NmNEb55Gz4I1xf\n4PBaRvynr0dtwbFXQOQAfg+q29sm+elYnAQLvtVVyYmfn+jqK9u1Ey+X2sNns3HW\nz9OSQt7e9lFIKMlospQPl4YuGhfcID/xC1gZLV5wlvghFJx/1QUW/yI3MZGXpIav\njwIDAQAB\n-----END PUBLIC KEY-----",
    "public_key_signature": "rJy3l3t5ZcaN33b3cIAkVGVeef9B4hh+5m2Os5cJBkZGy6pcb+PXSZeqoRfNDUu4VhAt5vvloPe2Xo6qT4iEQ82qNl+exbpnV5ou/id6O8P2FYB2+tETDFjotMMlNYKiqPRBesVivbqhwUd91btOQHNd6t2qAWIcDioAZBwnjLJPNjPtK5In1Y1+CGvCLNdtRKB0g783mpxn7PzRAKUzimj9imPmo8cCWcgySvIK6fs8VoZU38dSgKuWCpEFfFaB5/EkXHcFC9BfJm3e4J69kZtnMJAbHwAXW23azcOuXIi8n4vZWoo4pQgZhSksXG8Ibx08hh65wZ+i6HqT5Zf71w=="
}`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.MarshalIndent(tc.req, "", "    ")
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if string(got) != tc.want {
				t.Errorf("not equal, got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestRequestMarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		req  hvclient.Request
	}{
		{
			name: "BadPublicKey",
			req: hvclient.Request{
				PublicKey: "not a public key",
			},
		},
		{
			name: "BadPrivateKey",
			req: hvclient.Request{
				PrivateKey: "not a private key",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := json.Marshal(tc.req); err == nil {
				t.Fatalf("unexpectedly marshalled JSON: %v", err)
			}
		})
	}
}

func TestRequestUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		json string
		want hvclient.Request
	}{
		{
			name: "Full",
			json: testRequestFullJSON,
			want: testRequestFullRequest,
		},
		{
			name: "Validity",
			json: `{"validity":{"not_before":1550000000,"not_after":1560000000}}`,
			want: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1550000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.Request
			var err = json.Unmarshal([]byte(tc.json), &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("not equal")
			}
		})
	}
}

func TestRequestUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		`{"validity":1234}`,
		`{"custom_extensions":{"not.numbers":"NIL"}}`,
		`{"san":{"uris":["$http://bad.url"]}}`,
		`{"san":{"other_names":[{"type":"a.b.c","value":"value"}]}}`,
		`{"subject_da":{"date_of_birth":"tuesday"}}`,
		`{"subject_da":{"date_of_birth":true}}`,
		`{"qualified_statements":{"semantics":{"identifier":true}}}`,
		`{"ms_extension_template":{"id":true}}`,
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var r *hvclient.Request
			if err := json.Unmarshal([]byte(tc), &r); err == nil {
				t.Fatalf("unexpectedly unmarshalled JSON")
			}
		})
	}
}

func TestRequestEqual(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		first, second hvclient.Request
	}{
		{
			name:   "BothNil",
			first:  hvclient.Request{},
			second: hvclient.Request{},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if !tc.first.Equal(tc.second) {
				t.Errorf("requests failed to compare equal")
			}
		})
	}
}

func TestRequestNotEqual(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		first, second hvclient.Request
	}{
		{
			name: "ValidityFirstNil",
			first: hvclient.Request{
				Validity: nil,
			},
			second: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1555000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
		},
		{
			name: "ValiditySecondNil",
			first: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1555000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
			second: hvclient.Request{
				Validity: nil,
			},
		},
		{
			name: "ValidityNotBefore",
			first: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1550000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
			second: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1555000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
		},
		{
			name: "ValidityNotAfter",
			first: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1550000000, 0),
					NotAfter:  time.Unix(1560000000, 0),
				},
			},
			second: hvclient.Request{
				Validity: &hvclient.Validity{
					NotBefore: time.Unix(1550000000, 0),
					NotAfter:  time.Unix(1565000000, 0),
				},
			},
		},
		{
			name: "SubjectFirstNil",
			first: hvclient.Request{
				Subject: nil,
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					CommonName: "John Doe",
				},
			},
		},
		{
			name: "SubjectSecondNil",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					CommonName: "John Doe",
				},
			},
			second: hvclient.Request{
				Subject: nil,
			},
		},
		{
			name: "SubjectCountry",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					Country: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					Country: "a different value",
				},
			},
		},
		{
			name: "SubjectState",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					State: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					State: "a different value",
				},
			},
		},
		{
			name: "SubjectLocality",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					Locality: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					Locality: "a different value",
				},
			},
		},
		{
			name: "SubjectSerialNumber",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					SerialNumber: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					SerialNumber: "a different value",
				},
			},
		},
		{
			name: "SubjectStreetAddress",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					StreetAddress: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					StreetAddress: "a different value",
				},
			},
		},
		{
			name: "SubjectOrganization",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					Organization: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					Organization: "a different value",
				},
			},
		},
		{
			name: "SubjectOrganizationalUnitLength",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					OrganizationalUnit: []string{"a value", "another value"},
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					OrganizationalUnit: []string{"a value"},
				},
			},
		},
		{
			name: "SubjectOrganizationalUnitValue",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					OrganizationalUnit: []string{"a value"},
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					OrganizationalUnit: []string{"a different value"},
				},
			},
		},
		{
			name: "SubjectCommonName",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					CommonName: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					CommonName: "a different value",
				},
			},
		},
		{
			name: "SubjectEmail",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					Email: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					Email: "a different value",
				},
			},
		},
		{
			name: "SubjectJOILocality",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					JOILocality: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					JOILocality: "a different value",
				},
			},
		},
		{
			name: "SubjectJOIState",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					JOIState: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					JOIState: "a different value",
				},
			},
		},
		{
			name: "SubjectJOICountry",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					JOICountry: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					JOICountry: "a different value",
				},
			},
		},
		{
			name: "SubjectBusinessCategory",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					BusinessCategory: "a value",
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					BusinessCategory: "a different value",
				},
			},
		},
		{
			name: "SubjectExtraAttributesLength",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
					},
				},
			},
		},
		{
			name: "SubjectExtraAttributesValue",
			first: hvclient.Request{
				Subject: &hvclient.DN{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
					},
				},
			},
			second: hvclient.Request{
				Subject: &hvclient.DN{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
		},
		{
			name:  "SANDNSNamesFirstNil",
			first: hvclient.Request{},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a value"},
				},
			},
		},
		{
			name: "SANDNSNamesSecondNil",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a value"},
				},
			},
			second: hvclient.Request{},
		},
		{
			name: "SANDNSNamesLength",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a value", "another value"},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a value"},
				},
			},
		},
		{
			name: "SANDNSNamesValue",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a value"},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					DNSNames: []string{"a different value"},
				},
			},
		},
		{
			name: "SANEmailsLength",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					Emails: []string{"a value", "another value"},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					Emails: []string{"a value"},
				},
			},
		},
		{
			name: "SANEmailsValue",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					Emails: []string{"a value"},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					Emails: []string{"a different value"},
				},
			},
		},
		{
			name: "SANIPAddressesLength",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.1"),
						net.ParseIP("10.0.0.2"),
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.1"),
					},
				},
			},
		},
		{
			name: "SANIPAddressesValue",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.1"),
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					IPAddresses: []net.IP{
						net.ParseIP("10.0.0.2"),
					},
				},
			},
		},
		{
			name: "SANURIsLength",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					URIs: []*url.URL{
						mustParseURI("http://that.com"),
						mustParseURI("http://this.com"),
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					URIs: []*url.URL{
						mustParseURI("http://that.com"),
					},
				},
			},
		},
		{
			name: "SANURIsValue",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					URIs: []*url.URL{
						mustParseURI("http://that.com"),
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					URIs: []*url.URL{
						mustParseURI("http://this.com"),
					},
				},
			},
		},
		{
			name: "SANOtherNamesLength",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					OtherNames: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "a value",
						},
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					OtherNames: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "a value",
						},
					},
				},
			},
		},
		{
			name: "SANOtherNamesValue",
			first: hvclient.Request{
				SAN: &hvclient.SAN{
					OtherNames: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "a value",
						},
					},
				},
			},
			second: hvclient.Request{
				SAN: &hvclient.SAN{
					OtherNames: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
		},
		{
			name:  "DAFirstNil",
			first: hvclient.Request{},
			second: hvclient.Request{
				DA: &hvclient.DA{
					Gender: "f",
				},
			},
		},
		{
			name: "DASecondNil",
			first: hvclient.Request{
				DA: &hvclient.DA{
					Gender: "f",
				},
			},
			second: hvclient.Request{},
		},
		{
			name: "DAGender",
			first: hvclient.Request{
				DA: &hvclient.DA{
					Gender: "m",
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					Gender: "f",
				},
			},
		},
		{
			name: "DADateOfBirth",
			first: hvclient.Request{
				DA: &hvclient.DA{
					DateOfBirth: time.Date(1875, 10, 12, 12, 0, 0, 0, time.UTC),
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					DateOfBirth: time.Date(1947, 12, 1, 12, 0, 0, 0, time.UTC),
				},
			},
		},
		{
			name: "DAPlaceOfBirth",
			first: hvclient.Request{
				DA: &hvclient.DA{
					PlaceOfBirth: "London",
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					PlaceOfBirth: "Paris",
				},
			},
		},
		{
			name: "DACountryOfCitizenshipLength",
			first: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfCitizenship: []string{"UK", "FR"},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfCitizenship: []string{"UK"},
				},
			},
		},
		{
			name: "DACountryOfCitizenshipValue",
			first: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfCitizenship: []string{"UK"},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfCitizenship: []string{"FR"},
				},
			},
		},
		{
			name: "DACountryOfResidenceLength",
			first: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfResidence: []string{"UK", "FR"},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfResidence: []string{"UK"},
				},
			},
		},
		{
			name: "DACountryOfResidenceValue",
			first: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfResidence: []string{"UK"},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					CountryOfResidence: []string{"FR"},
				},
			},
		},
		{
			name: "DAExtraAttributesLength",
			first: hvclient.Request{
				DA: &hvclient.DA{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
					},
				},
			},
		},
		{
			name: "DAExtraAttributesValue",
			first: hvclient.Request{
				DA: &hvclient.DA{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 4},
							Value: "value",
						},
					},
				},
			},
			second: hvclient.Request{
				DA: &hvclient.DA{
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{1, 2, 3, 5},
							Value: "a different value",
						},
					},
				},
			},
		},
		{
			name:  "QualifiedStatementsFirstNil",
			first: hvclient.Request{},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCCompliance: true,
				},
			},
		},
		{
			name: "QualifiedStatementsSecondNil",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCCompliance: true,
				},
			},
			second: hvclient.Request{},
		},
		{
			name: "QualifiedStatementsQCCompliance",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCCompliance: true,
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCCompliance: false,
				},
			},
		},
		{
			name: "QualifiedStatementsQCSSCDCompliance",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCSSCDCompliance: true,
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCSSCDCompliance: false,
				},
			},
		},
		{
			name: "QualifiedStatementsQCType",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCType: asn1.ObjectIdentifier{1, 2, 3, 4},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCType: asn1.ObjectIdentifier{1, 2, 3, 5},
				},
			},
		},
		{
			name: "QualifiedStatementsQCRetentionPeriod",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCRetentionPeriod: 1,
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCRetentionPeriod: 2,
				},
			},
		},
		{
			name: "QualifiedStatementsQCPDsLength",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCPDs: map[string]string{
						"EN": "a value",
						"RU": "another value",
					},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCPDs: map[string]string{
						"EN": "a value",
					},
				},
			},
		},
		{
			name: "QualifiedStatementsQCPDsValue",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCPDs: map[string]string{
						"EN": "a value",
					},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					QCPDs: map[string]string{
						"EN": "a different value",
					},
				},
			},
		},
		{
			name: "QualifiedStatementsSemanticsOID",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						OID: asn1.ObjectIdentifier{1, 2, 3, 4},
					},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						OID: asn1.ObjectIdentifier{1, 2, 3, 5},
					},
				},
			},
		},
		{
			name: "QualifiedStatementsSemanticsNameAuthoritiesLength",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						NameAuthorities: []string{"value", "another value"},
					},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						NameAuthorities: []string{"value"},
					},
				},
			},
		},
		{
			name: "QualifiedStatementsSemanticsNameAuthoritiesValue",
			first: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						NameAuthorities: []string{"value"},
					},
				},
			},
			second: hvclient.Request{
				QualifiedStatements: &hvclient.QualifiedStatements{
					Semantics: hvclient.Semantics{
						NameAuthorities: []string{"a different value"},
					},
				},
			},
		},
		{
			name:  "MSExtensionFirstNil",
			first: hvclient.Request{},
			second: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					OID: asn1.ObjectIdentifier{1, 2, 3, 4},
				},
			},
		},
		{
			name: "MSExtensionSecondNil",
			first: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					OID: asn1.ObjectIdentifier{1, 2, 3, 4},
				},
			},
			second: hvclient.Request{},
		},
		{
			name: "MSExtensionOID",
			first: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					OID: asn1.ObjectIdentifier{1, 2, 3, 4},
				},
			},
			second: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					OID: asn1.ObjectIdentifier{1, 2, 3, 5},
				},
			},
		},
		{
			name: "MSExtensionMinorVersion",
			first: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					MinorVersion: 1,
				},
			},
			second: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					MinorVersion: 2,
				},
			},
		},
		{
			name: "MSExtensionMajorVersion",
			first: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					MajorVersion: 1,
				},
			},
			second: hvclient.Request{
				MSExtension: &hvclient.MSExtension{
					MajorVersion: 2,
				},
			},
		},
		{
			name: "EKUDifferentLength",
			first: hvclient.Request{
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
			},
			second: hvclient.Request{
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
				},
			},
		},
		{
			name: "EKUDifferentValue",
			first: hvclient.Request{
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
				},
			},
			second: hvclient.Request{
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
			},
		},
		{
			name: "CustomExtensionsDifferentLength",
			first: hvclient.Request{
				CustomExtensions: []hvclient.OIDAndString{
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
						Value: "NIL",
					},
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 2},
						Value: "SOME TEXT",
					},
				},
			},
			second: hvclient.Request{
				CustomExtensions: []hvclient.OIDAndString{
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
						Value: "NIL",
					},
				},
			},
		},
		{
			name: "CustomExtensionsDifferentValue",
			first: hvclient.Request{
				CustomExtensions: []hvclient.OIDAndString{
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 1},
						Value: "NIL",
					},
				},
			},
			second: hvclient.Request{
				CustomExtensions: []hvclient.OIDAndString{
					{
						OID:   asn1.ObjectIdentifier{2, 5, 29, 99, 2},
						Value: "NIL",
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.first.Equal(tc.second) {
				t.Errorf("requests incorrectly compared equal")
			}
		})
	}
}

func TestRequestPKCS10(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		request hvclient.Request
	}{
		{
			name: "Full",
			request: hvclient.Request{
				Subject: &hvclient.DN{
					CommonName:         "John Doe",
					Organization:       "ACME Inc",
					OrganizationalUnit: []string{"Maintenance", "Bird Control"},
					StreetAddress:      "42 Crow Avenue",
					Locality:           "Llandrindod Wells",
					State:              "Powys",
					Country:            "GB",
					JOILocality:        "Llandrindod Wells",
					JOIState:           "Powys",
					JOICountry:         "United Kingdom",
					Email:              "jdoe@acme.com",
					BusinessCategory:   "Retail",
					ExtraAttributes: []hvclient.OIDAndString{
						{
							OID:   asn1.ObjectIdentifier{2, 5, 4, 4},
							Value: "Doe",
						},
						{
							OID:   asn1.ObjectIdentifier{2, 5, 4, 5},
							Value: "12345678",
						},
					},
				},
				SAN: &hvclient.SAN{
					DNSNames:    []string{"domain1.acme.com", "domain2.acme.com"},
					Emails:      []string{"jdoe@acme.com"},
					IPAddresses: []net.IP{net.ParseIP("192.168.1.1")},
					URIs:        []*url.URL{testhelpers.MustParseURI(t, "http://badger.acme.com")},
				},
				DA: &hvclient.DA{
					Gender:       "M",
					PlaceOfBirth: "Bridgend",
				},
				EKUs: []asn1.ObjectIdentifier{
					{1, 3, 6, 1, 5, 5, 7, 3, 1},
					{1, 3, 6, 1, 5, 5, 7, 3, 2},
				},
				PrivateKey: testhelpers.MustGetPrivateKeyFromFile(t, "testdata/rsa_priv.key"),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = tc.request.PKCS10()
			if err != nil {
				t.Fatalf("couldn't build PKCS10 request: %v", err)
			}

			if err = got.CheckSignature(); err != nil {
				t.Errorf("signature check failed: %v", err)
			}
		})
	}
}

func mustParseURI(uri string) *url.URL {
	var parsed, err = url.Parse(uri)
	if err != nil {
		panic(fmt.Sprintf("couldn't parse URI: %v", err))
	}

	return parsed
}
