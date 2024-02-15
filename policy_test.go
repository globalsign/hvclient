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
	"bufio"
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/globalsign/hvclient"
)

var testPolicyFullJSON = `{
  "validity": {
    "secondsmin": 3600,
    "secondsmax": 86400,
    "not_before_negative_skew": 120,
    "not_before_positive_skew": 3600,
    "issuer_expiry": 1735732800
  },
  "subject_dn": {
    "common_name": {
      "presence": "REQUIRED",
      "format": "^[A-Za-z][A-Za-z -]+$"
    },
    "given_name": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z][A-Za-z -]+$"
    },
    "surname": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z][A-Za-z -]+$"
    },
    "organization": {
      "presence": "STATIC",
      "format": "GMO GlobalSign"
    },
    "organizational_unit": {
      "static": false,
      "list": [
        "^[A-Za-z][A-Za-z \\-]+$"
      ],
      "mincount": 1,
      "maxcount": 3
    },
    "organization_identifier": {
      "presence": "OPTIONAL",
      "format": "^.*$"
    },
    "country": {
      "presence": "STATIC",
      "format": "GB"
    },
    "state": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z][A-Za-z \\-]+$"
    },
    "locality": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z][A-Za-z \\-]+$"
    },
    "street_address": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z0-9][A-Za-z0-9 \\-]+$"
    },
    "postal_code": {
      "presence": "OPTIONAL",
      "format": "^[0-9]{5}$"
    },
    "email": {
      "presence": "FORBIDDEN",
      "format": "^\\w[-._\\w]*\\w@\\w[-._\\w]*\\w.\\w{2,3}"
    },
    "jurisdiction_of_incorporation_locality_name": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z \\-]*$"
    },
    "jurisdiction_of_incorporation_state_or_province_name": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z \\-]*$"
    },
    "jurisdiction_of_incorporation_country_name": {
      "presence": "FORBIDDEN",
      "format": "^[A-Za-z \\-]*$"
    },
    "business_category": {
      "presence": "FORBIDDEN",
      "format": "^[A-Za-z \\-]*$"
    },
    "serial_number": {
      "presence": "FORBIDDEN",
      "format": "^.*$"
    },
    "extra_attributes": {
      "1.3.6.1.5.5.7.48.1.5": {
        "static": true,
        "value_type": "PRINTABLESTRING",
        "value_format": "static attribute",
        "mincount": 1,
        "maxcount": 1
      },
      "1.3.6.1.5.5.7.48.1.6": {
        "static": false,
        "value_type": "UTF8STRING",
        "value_format": "^[A-Za-z \\\\-]*$",
        "mincount": 0,
        "maxcount": 3
      }
    }
  },
  "san": {
    "dns_names": {
      "static": false,
      "list": [],
      "mincount": 0,
      "maxcount": 0
    },
    "emails": {
      "static": false,
      "list": [
        "^\\w[-._\\w]*\\w@\\w[-._\\w]*\\w.\\w{2,3}$"
      ],
      "mincount": 0,
      "maxcount": 1
    },
    "ip_addresses": {
      "static": false,
      "list": [],
      "mincount": 0,
      "maxcount": 0
    },
    "uris": {
      "static": false,
      "list": [],
      "mincount": 0,
      "maxcount": 0
    },
    "other_names": {
      "1.3.6.1.5.5.7.48.1.5": {
        "static": false,
        "value_type": "UTF8STRING",
        "value_format": "^[A-Za-z.-]@demo.globalsign.com",
        "mincount": 0,
        "maxcount": 1
      }
    }
  },
  "extended_key_usages": {
    "ekus": {
      "static": false,
      "list": [
        "^1.3.6.1.5.5.7.3.[1-3]$"
      ],
      "mincount": 1,
      "maxcount": 3
    },
    "critical": true
  },
  "subject_da": {
    "gender": {
      "presence": "OPTIONAL",
      "format": "^[MmFf]$"
    },
    "date_of_birth": "OPTIONAL",
    "place_of_birth": {
      "presence": "OPTIONAL",
      "format": "^[A-Za-z \\\\-]*$"
    },
    "country_of_citizenship": {
      "static": true,
      "list": [
        "GB",
        "US"
      ],
      "mincount": 2,
      "maxcount": 2
    },
    "country_of_residence": {
      "static": false,
      "list": [
        "GB",
        "US"
      ],
      "mincount": 0,
      "maxcount": 2
    },
    "extra_attributes": {
      "1.3.6.1.5.5.7.48.1.5": {
        "static": true,
        "value_type": "PRINTABLESTRING",
        "value_format": "static attribute",
        "mincount": 1,
        "maxcount": 1
      },
      "1.3.6.1.5.5.7.48.1.6": {
        "static": false,
        "value_type": "UTF8STRING",
        "value_format": "^[A-Za-z \\\\-]*$",
        "mincount": 1,
        "maxcount": 3
      }
    }
  },
  "qualified_statements": {
    "semantics": {
      "identifier": {
        "presence": "STATIC",
        "format": "1.1.1.1.1.1"
      },
      "name_authorities": {
        "static": true,
        "list": [
          "contact@ra1.hvsign.globalsign.com"
        ],
        "mincount": 1,
        "maxcount": 1
      }
    },
    "etsi_qc_compliance": "STATIC_TRUE",
    "etsi_qc_sscd_compliance": "OPTIONAL",
    "etsi_qc_type": {
      "presence": "REQUIRED",
      "format": "^0.4.0.1862.1.6.[1-3]$"
    },
    "etsi_qc_retention_period": {
      "presence": "OPTIONAL",
      "min": 1,
      "max": 3
    },
    "etsi_qc_pds": {
      "presence": "STATIC",
      "policies": {
        "EN": "https://etsi.pds.demo.globalsign.com/en/pds"
      }
    }
  },
  "ms_extension_template": {
    "critical": true,
    "template_id": {
      "presence": "REQUIRED",
      "format": "^1.2.3.4.123.4.5.[1-3]$"
    },
    "major_version": {
      "presence": "REQUIRED",
      "min": 1,
      "max": 10
    },
    "minor_version": {
      "presence": "OPTIONAL",
      "min": 1,
      "max": 10
    }
  },
  "signature": {
    "algorithm": {
      "presence": "STATIC",
      "list": [
        "RSA-PSS"
      ]
    },
    "hash_algorithm": {
      "presence": "REQUIRED",
      "list": [
        "SHA-256",
        "SHA-512"
      ]
    }
  },
  "public_key": {
    "key_type": "RSA",
    "allowed_lengths": [
      2048,
      4096
    ],
    "key_format": "PKCS8"
  },
  "public_key_signature": "REQUIRED",
  "custom_extensions": {
    "1.3.6.1.5.5.7.48.1.5": {
      "presence": "STATIC",
      "critical": false,
      "value_type": "NIL"
    },
    "1.3.6.1.5.5.7.48.1.6": {
      "presence": "STATIC",
      "critical": true,
      "value_type": "DER",
      "value_format": "^([A-Fa-f0-9]{2})+$"
    }
  }
}`

var testFullPolicy = hvclient.Policy{
	Validity: &hvclient.ValidityPolicy{
		SecondsMin:            3600,
		SecondsMax:            86400,
		NotBeforeNegativeSkew: 120,
		NotBeforePositiveSkew: 3600,
		IssuerExpiry:          1735732800,
	},
	SubjectDN: &hvclient.SubjectDNPolicy{
		CommonName: &hvclient.StringPolicy{
			Presence: hvclient.Required,
			Format:   "^[A-Za-z][A-Za-z -]+$",
		},
		GivenName: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z][A-Za-z -]+$",
		},
		Surname: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z][A-Za-z -]+$",
		},
		Organization: &hvclient.StringPolicy{
			Presence: hvclient.Static,
			Format:   "GMO GlobalSign",
		},
		OrganizationalUnit: &hvclient.ListPolicy{
			Static: false,
			List: []string{
				"^[A-Za-z][A-Za-z \\-]+$",
			},
			MinCount: 1,
			MaxCount: 3,
		},
		OrganizationalIdentifier: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^.*$",
		},
		State: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z][A-Za-z \\-]+$",
		},
		Country: &hvclient.StringPolicy{
			Presence: hvclient.Static,
			Format:   "GB",
		},
		Locality: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z][A-Za-z \\-]+$",
		},
		StreetAddress: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z0-9][A-Za-z0-9 \\-]+$",
		},
		PostalCode: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[0-9]{5}$",
		},
		Email: &hvclient.StringPolicy{
			Presence: hvclient.Forbidden,
			Format:   "^\\w[-._\\w]*\\w@\\w[-._\\w]*\\w.\\w{2,3}",
		},
		JOILocality: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z \\-]*$",
		},
		JOIState: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z \\-]*$",
		},
		JOICountry: &hvclient.StringPolicy{
			Presence: hvclient.Forbidden,
			Format:   "^[A-Za-z \\-]*$",
		},
		BusinessCategory: &hvclient.StringPolicy{
			Presence: hvclient.Forbidden,
			Format:   "^[A-Za-z \\-]*$",
		},
		SerialNumber: &hvclient.StringPolicy{
			Presence: hvclient.Forbidden,
			Format:   "^.*$",
		},
		ExtraAttributes: []hvclient.TypeAndValuePolicy{
			{
				OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
				Static:      true,
				ValueType:   hvclient.PrintableString,
				ValueFormat: "static attribute",
				MinCount:    1,
				MaxCount:    1,
			},
			{
				OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6},
				Static:      false,
				ValueType:   hvclient.UTF8String,
				ValueFormat: "^[A-Za-z \\\\-]*$",
				MinCount:    0,
				MaxCount:    3,
			},
		},
	},
	SAN: &hvclient.SANPolicy{
		DNSNames: &hvclient.ListPolicy{
			Static:   false,
			List:     []string{},
			MinCount: 0,
			MaxCount: 0,
		},
		Emails: &hvclient.ListPolicy{
			Static: false,
			List: []string{
				"^\\w[-._\\w]*\\w@\\w[-._\\w]*\\w.\\w{2,3}$",
			},
			MinCount: 0,
			MaxCount: 1,
		},
		IPAddresses: &hvclient.ListPolicy{
			Static:   false,
			List:     []string{},
			MinCount: 0,
			MaxCount: 0,
		},
		URIs: &hvclient.ListPolicy{
			Static:   false,
			List:     []string{},
			MinCount: 0,
			MaxCount: 0,
		},
		OtherNames: []hvclient.TypeAndValuePolicy{
			{
				OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
				Static:      false,
				ValueType:   hvclient.UTF8String,
				ValueFormat: "^[A-Za-z.-]@demo.globalsign.com",
				MinCount:    0,
				MaxCount:    1,
			},
		},
	},
	SubjectDA: &hvclient.SubjectDAPolicy{
		Gender: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[MmFf]$",
		},
		DateOfBirth: hvclient.Optional,
		PlaceOfBirth: &hvclient.StringPolicy{
			Presence: hvclient.Optional,
			Format:   "^[A-Za-z \\\\-]*$",
		},
		CountryOfCitizenship: &hvclient.ListPolicy{
			Static: true,
			List: []string{
				"GB",
				"US",
			},
			MinCount: 2,
			MaxCount: 2,
		},
		CountryOfResidence: &hvclient.ListPolicy{
			Static: false,
			List: []string{
				"GB",
				"US",
			},
			MinCount: 0,
			MaxCount: 2,
		},
		ExtraAttributes: []hvclient.TypeAndValuePolicy{
			{
				OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
				Static:      true,
				ValueType:   hvclient.PrintableString,
				ValueFormat: "static attribute",
				MinCount:    1,
				MaxCount:    1,
			},
			{
				OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6},
				Static:      false,
				ValueType:   hvclient.UTF8String,
				ValueFormat: "^[A-Za-z \\\\-]*$",
				MinCount:    1,
				MaxCount:    3,
			},
		},
	},
	EKUs: &hvclient.EKUPolicy{
		EKUs: hvclient.ListPolicy{
			Static: false,
			List: []string{
				"^1.3.6.1.5.5.7.3.[1-3]$",
			},
			MinCount: 1,
			MaxCount: 3,
		},
		Critical: true,
	},
	QualifiedStatements: &hvclient.QualifiedStatementsPolicy{
		Semantics: &hvclient.SemanticsPolicy{
			Identifier: &hvclient.StringPolicy{
				Presence: hvclient.Static,
				Format:   "1.1.1.1.1.1",
			},
			NameAuthorities: &hvclient.ListPolicy{
				Static: true,
				List: []string{
					"contact@ra1.hvsign.globalsign.com",
				},
				MinCount: 1,
				MaxCount: 1,
			},
		},
		ETSIQCCompliance:     hvclient.StaticTrue,
		ETSIQCSSCDCompliance: hvclient.StaticOptional,
		ETSIQCType: &hvclient.StringPolicy{
			Presence: hvclient.Required,
			Format:   "^0.4.0.1862.1.6.[1-3]$",
		},
		ETSIQCRetentionPeriod: &hvclient.IntegerPolicy{
			Presence: hvclient.Optional,
			Min:      1,
			Max:      3,
		},
		ETSIQCPDs: &hvclient.ETSIPDsPolicy{
			Presence: hvclient.Static,
			Policies: map[string]string{
				"EN": "https://etsi.pds.demo.globalsign.com/en/pds",
			},
		},
	},
	MSExtensionTemplate: &hvclient.MSExtensionTemplatePolicy{
		Critical: true,
		TemplateID: &hvclient.StringPolicy{
			Presence: hvclient.Required,
			Format:   "^1.2.3.4.123.4.5.[1-3]$",
		},
		MajorVersion: &hvclient.IntegerPolicy{
			Presence: hvclient.Required,
			Min:      1,
			Max:      10,
		},
		MinorVersion: &hvclient.IntegerPolicy{
			Presence: hvclient.Optional,
			Min:      1,
			Max:      10,
		},
	},
	SignaturePolicy: &hvclient.SignaturePolicy{
		Algorithm: &hvclient.AlgorithmPolicy{
			Presence: hvclient.Static,
			List: []string{
				"RSA-PSS",
			},
		},
		HashAlgorithm: &hvclient.AlgorithmPolicy{
			Presence: hvclient.Required,
			List: []string{
				"SHA-256",
				"SHA-512",
			},
		},
	},
	PublicKey: &hvclient.PublicKeyPolicy{
		KeyType:        hvclient.RSA,
		AllowedLengths: []int{2048, 4096},
		KeyFormat:      hvclient.PKCS8,
	},
	PublicKeySignature: hvclient.Required,
	CustomExtensions: []hvclient.CustomExtensionsPolicy{
		{
			OID:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
			Presence:  hvclient.Static,
			Critical:  false,
			ValueType: hvclient.Nil,
		},
		{
			OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 6},
			Presence:    hvclient.Static,
			Critical:    true,
			ValueType:   hvclient.DER,
			ValueFormat: "^([A-Fa-f0-9]{2})+$",
		},
	},
}

func TestPolicyMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value hvclient.Policy
		want  []byte
	}{
		{
			name:  "Full",
			value: testFullPolicy,
			want:  []byte(testPolicyFullJSON),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.MarshalIndent(tc.value, "", "  ")
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				var gotscanner = bufio.NewScanner(bytes.NewReader(got))
				var wantscanner = bufio.NewScanner(bytes.NewReader(tc.want))

				var line int

				for gotscanner.Scan() {
					line++

					var gotline = gotscanner.Text()
					if !wantscanner.Scan() {
						t.Fatalf("got line %d %q, want no line %d", line, gotline, line)
					}

					var wantline = wantscanner.Text()
					if gotline != wantline {
						t.Fatalf("line %d, got %q, want %q", line, gotline, wantline)
					}
				}
			}
		})
	}
}

func TestPolicyMarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		policy hvclient.Policy
	}{
		{
			name: "BadPresence",
			policy: hvclient.Policy{
				PublicKeySignature: hvclient.Presence(0),
			},
		},
		{
			name: "BadKeyType",
			policy: hvclient.Policy{
				PublicKey: &hvclient.PublicKeyPolicy{
					KeyType: hvclient.KeyType(0),
				},
			},
		},
		{
			name: "BadKeyFormat",
			policy: hvclient.Policy{
				PublicKey: &hvclient.PublicKeyPolicy{
					KeyType:   hvclient.RSA,
					KeyFormat: hvclient.KeyFormat(0),
				},
			},
		},
		{
			name: "BadValueType",
			policy: hvclient.Policy{
				CustomExtensions: []hvclient.CustomExtensionsPolicy{
					{
						OID:       asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
						Presence:  hvclient.Static,
						Critical:  false,
						ValueType: hvclient.ValueType(0),
					},
				},
			},
		},
		{
			name: "BadOptionalStaticValueType",
			policy: hvclient.Policy{
				QualifiedStatements: &hvclient.QualifiedStatementsPolicy{
					Semantics: &hvclient.SemanticsPolicy{
						Identifier: &hvclient.StringPolicy{
							Presence: hvclient.Static,
							Format:   "1.1.1.1.1.1",
						},
						NameAuthorities: &hvclient.ListPolicy{
							Static: true,
							List: []string{
								"contact@ra1.hvsign.globalsign.com",
							},
							MinCount: 1,
							MaxCount: 1,
						},
					},
					ETSIQCCompliance:     hvclient.OptionalStaticPresence(0),
					ETSIQCSSCDCompliance: hvclient.StaticOptional,
					ETSIQCType: &hvclient.StringPolicy{
						Presence: hvclient.Required,
						Format:   "^0.4.0.1862.1.6.[1-3]$",
					},
					ETSIQCRetentionPeriod: &hvclient.IntegerPolicy{
						Presence: hvclient.Optional,
						Min:      1,
						Max:      3,
					},
					ETSIQCPDs: &hvclient.ETSIPDsPolicy{
						Presence: hvclient.Static,
						Policies: map[string]string{
							"EN": "https://etsi.pds.demo.globalsign.com/en/pds",
						},
					},
				},
			},
		},
		{
			name: "BadTypeAndValue",
			policy: hvclient.Policy{
				SubjectDN: &hvclient.SubjectDNPolicy{
					ExtraAttributes: []hvclient.TypeAndValuePolicy{
						{
							OID:         asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
							Static:      true,
							ValueType:   hvclient.ValueType(0),
							ValueFormat: "static attribute",
							MinCount:    1,
							MaxCount:    1,
						},
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := json.Marshal(tc.policy); err == nil {
				t.Fatalf("unexpectedly marshalled JSON: %s", string(got))
			}
		})
	}
}

func TestPolicyUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
		want  hvclient.Policy
	}{
		{
			name:  "OK",
			value: []byte(testPolicyFullJSON),
			want:  testFullPolicy,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hvclient.Policy
			var err = json.Unmarshal(tc.value, &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !cmp.Equal(got, tc.want) {
				t.Errorf("unexpected result\ngot:  %+#v\nwant: %+#v", got, tc.want)
			}
		})
	}
}

func TestPolicyUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		value []byte
	}{
		{
			name:  "BadQCComplianceValue",
			value: []byte(`{"qualified_statements":{"etsi_qc_compliance":"BAD VALUE"}}`),
		},
		{
			name:  "BadQCComplianceType",
			value: []byte(`{"qualified_statements":{"etsi_qc_compliance":999999}}`),
		},
		{
			name:  "BadKeyFormatValue",
			value: []byte(`{"public_key":{"key_format":"BAD FORMAT"}}`),
		},
		{
			name:  "BadKeyFormatType",
			value: []byte(`{"public_key":{"key_format":99999}}`),
		},
		{
			name:  "BadKeyTypeValue",
			value: []byte(`{"public_key":{"key_type":"SKELETON"}}`),
		},
		{
			name:  "BadKeyTypeType",
			value: []byte(`{"public_key":{"key_type":99999}}`),
		},
		{
			name:  "BadPresenceValue",
			value: []byte(`{"subject_dn":{"common_name":{"presence":"NOT ON GOOD LIST"}}}`),
		},
		{
			name:  "BadPresenceType",
			value: []byte(`{"subject_dn":{"common_name":{"presence":999999}}}`),
		},
		{
			name:  "BadValueTypeValue",
			value: []byte(`{"custom_extensions":{"1.2.3.4":{"value_type":"BAD VALUE TYPE"}}}`),
		},
		{
			name:  "BadValueTypeType",
			value: []byte(`{"custom_extensions":{"1.2.3.4":{"value_type":999999}}}`),
		},
		{
			name:  "BadOIDValueCustomExtension",
			value: []byte(`{"custom_extensions":{"NOT AN OID":{"value_type":"NIL"}}}`),
		},
		{
			name:  "BadOIDValueTypeAndValue",
			value: []byte(`{"subject_dn":{"extra_attributes":{"NOT AN OID":{"static":true,"value_type":"NIL"}}}}`),
		},
		{
			name:  "BadTypeAndValue",
			value: []byte(`{"subject_dn":{"extra_attributes":{"NOT AN OID":{"static":1234,"value_type":"NIL"}}}}`),
		},
		{
			name:  "BadSANURL",
			value: []byte(`{"san":{"uris":["$http://bad.uri/"]}}`),
		},
		{
			name:  "BadSubjectDA",
			value: []byte(`{"subject_da":{"gender":123}}`),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hvclient.Policy
			var err = json.Unmarshal(tc.value, &got)
			if err == nil {
				t.Fatalf("unexpectedly unmarshalled JSON: %v", got)
			}
		})
	}
}

func TestValueTypeString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value hvclient.ValueType
		want  string
	}{
		{hvclient.ValueType(0), "UNKNOWN VALUE_TYPE VALUE"},
		{hvclient.IA5String, "IA5STRING"},
		{hvclient.PrintableString, "PRINTABLESTRING"},
		{hvclient.UTF8String, "UTF8STRING"},
		{hvclient.Integer, "INTEGER"},
		{hvclient.DER, "DER"},
		{hvclient.Nil, "NIL"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPresenceString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value hvclient.Presence
		want  string
	}{
		{hvclient.Presence(0), "UNKNOWN PRESENCE VALUE"},
		{hvclient.Optional, "OPTIONAL"},
		{hvclient.Static, "STATIC"},
		{hvclient.Required, "REQUIRED"},
		{hvclient.Forbidden, "FORBIDDEN"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestKeyTypeString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value hvclient.KeyType
		want  string
	}{
		{hvclient.KeyType(0), "UNKNOWN KEY TYPE VALUE"},
		{hvclient.RSA, "RSA"},
		{hvclient.ECDSA, "ECDSA"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestKeyFormatString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value hvclient.KeyFormat
		want  string
	}{
		{hvclient.KeyFormat(0), "UNKNOWN KEY FORMAT VALUE"},
		{hvclient.PKCS8, "PKCS8"},
		{hvclient.PKCS10, "PKCS10"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestOptionalStaticPresenceString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		value hvclient.OptionalStaticPresence
		want  string
	}{
		{hvclient.OptionalStaticPresence(0), "UNKNOWN OPTIONAL STATIC PRESENCE VALUE"},
		{hvclient.StaticOptional, "OPTIONAL"},
		{hvclient.StaticTrue, "STATIC_TRUE"},
		{hvclient.StaticFalse, "STATIC_FALSE"},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.want, func(t *testing.T) {
			t.Parallel()

			if got := tc.value.String(); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
