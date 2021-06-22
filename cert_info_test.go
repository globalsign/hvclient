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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
	"github.com/globalsign/hvclient/internal/testhelpers"
)

const testPEM = `-----BEGIN CERTIFICATE-----
MIIEfDCCA2SgAwIBAgIQAQFUXN5AxSVL5HP1tk0wtTANBgkqhkiG9w0BAQsFADBS
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEoMCYGA1UE
AxMfR2xvYmFsU2lnbiBOb24tUHVibGljIEhWQ0EgRGVtbzAeFw0xOTAyMjMwMDA2
MjJaFw0xOTA1MjQwMDA2MjJaMEExCzAJBgNVBAYTAlVTMR8wHQYDVQQKDBZHbG9i
YWxTaWduIEVuZ2luZWVyaW5nMREwDwYDVQQDDAhKb2huIERvZTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBALNRZ4p8qQMf5+Dh8aWj3jCyQH4ZR2uHPMI5
EbpoT0VIZXCk+3+L5YEWjTv3YzlGT1dZDtYfKrY0c53xWb4DWx9aBhm0ascE9Kp5
gsoaebb+63KD7IAQElR+7dfuSwAFNBkhkxMEzQ7yIIdbFd7sO77p6mY4BSpxtzjQ
FcjWBvzK/ai5+9s3tw52Ucq75I5ddnXcjAkZTrM0DCKb2aADxQDchObvZjJjFEAk
CX7+dW+/1WaiUqlfrwlZGU27QNmpxt8ycqGgcguvhDK1zfLtZXgt0B7ilFNfAf+I
xQmmtdjAXrXqWt7+A0klPnOdzu+Jl86xW3PCAsQ4KtSA9BL9s08CAwEAAaOCAV0w
ggFZMAkGA1UdEwQCMAAwHwYDVR0jBBgwFoAUZ0sH6Qnx8XsyzL2FHE4nDc6hzGww
HQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBQWquFPQ0LI
IdhTFRosF9c2muLajTAOBgNVHQ8BAf8EBAMCA6gwgZYGCCsGAQUFBwEBBIGJMIGG
MDwGCCsGAQUFBzABhjBodHRwOi8vb2NzcC5nbG9iYWxzaWduLmNvbS9jYS9nc25w
aHZjYWRlbW9zaGEyZzMwRgYIKwYBBQUHMAKGOmh0dHA6Ly9zZWN1cmUuZ2xvYmFs
c2lnbi5jb20vY2FjZXJ0L2dzbnBodmNhZGVtb3NoYTJnMy5jcnQwRAYDVR0fBD0w
OzA5oDegNYYzaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9jYS9nc25waHZjYWRl
bW9zaGEyZzMuY3JsMA0GCSqGSIb3DQEBCwUAA4IBAQA9u+JNLBTwqUBj7X1BxUyG
QuHRyOeiVzY4YRNWplW3tkwzizX0UZruLoMyJ9DQqNNWYGALrynaEKDcVnVZnzRf
BLX1C08WVb37EHYeu/wyh3bhu3sSRmbjuYxduyDDdhye3urbHUkMDjCjGuE6r45l
pzODa/yMds7Dt/s0GzE6kGGqeAXcZiT9CNiTKfgSykGPQmI5MSVxWRu6eXZKQ9M1
awPX0kDyz7BCnA7g6TgOMSLpIpmS+sk0gPbn0L8aSbsr+rVXeuvflMvX6s+83O90
C5KcdB2n5alI+o4AXFf5Gv4L4isofggpTtUNioHZvXCJE0jpuhgZmcGUWvJe6GfH
-----END CERTIFICATE-----`

func TestCertInfoEqual(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name   string
		first  hvclient.CertInfo
		second hvclient.CertInfo
		want   bool
	}{
		{
			name: "All/Equal",
			first: hvclient.CertInfo{
				PEM:       "some PEM",
				X509:      testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Date(2021, 6, 21, 18, 43, 30, 0, time.UTC),
			},
			second: hvclient.CertInfo{
				PEM:       "some PEM",
				X509:      testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Date(2021, 6, 21, 18, 43, 30, 0, time.UTC),
			},
			want: true,
		},
		{
			name: "PEM",
			first: hvclient.CertInfo{
				PEM: "some PEM",
			},
			second: hvclient.CertInfo{
				PEM: "some other PEM",
			},
			want: false,
		},
		{
			name: "X509/Value",
			first: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
			},
			second: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
			},
			want: true,
		},
		{
			name: "X509/Inequal",
			first: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
			},
			second: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_ica_cert.pem"),
			},
			want: false,
		},
		{
			name: "X509/FirstNil",
			first: hvclient.CertInfo{
				X509: nil,
			},
			second: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
			},
			want: false,
		},
		{
			name: "X509/SecondNil",
			first: hvclient.CertInfo{
				X509: testhelpers.MustGetCertFromFile(t, "testdata/test_cert.pem"),
			},
			second: hvclient.CertInfo{
				X509: nil,
			},
			want: false,
		},
		{
			name: "Status",
			first: hvclient.CertInfo{
				Status: hvclient.StatusIssued,
			},
			second: hvclient.CertInfo{
				Status: hvclient.StatusRevoked,
			},
			want: false,
		},
		{
			name: "UpdatedAt",
			first: hvclient.CertInfo{
				UpdatedAt: time.Date(2021, 6, 21, 18, 43, 30, 0, time.UTC),
			},
			second: hvclient.CertInfo{
				UpdatedAt: time.Date(2021, 7, 21, 18, 43, 30, 0, time.UTC),
			},
			want: false,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.first.Equal(tc.second); got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func TestCertInfoMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		info hvclient.CertInfo
		want []byte
		err  error
	}{
		{
			name: "Issued",
			info: hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Unix(1477958400, 0),
			},
			want: []byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
		{
			name: "Revoked",
			info: hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusRevoked,
				UpdatedAt: time.Unix(1477958400, 0),
			},
			want: []byte(fmt.Sprintf(`{"certificate":"%s","status":"REVOKED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
		{
			name: "BadStatus",
			info: hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.CertStatus(0),
				UpdatedAt: time.Unix(1477958400, 0),
			},
			err: errors.New("invalid status"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.Marshal(tc.info)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestCertInfoUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		data []byte
		want hvclient.CertInfo
		err  error
	}{
		{
			name: "Issued",
			data: []byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			want: hvclient.CertInfo{
				PEM:       testPEM,
				X509:      testhelpers.MustParseCert(t, testPEM),
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Unix(1477958400, 0),
			},
		},
		{
			name: "Revoked",
			data: []byte(fmt.Sprintf(`{"certificate":"%s","status":"REVOKED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			want: hvclient.CertInfo{
				PEM:       testPEM,
				X509:      testhelpers.MustParseCert(t, testPEM),
				Status:    hvclient.StatusRevoked,
				UpdatedAt: time.Unix(1477958400, 0),
			},
		},
		{
			name: "BadStatusValue",
			data: []byte(fmt.Sprintf(`{"certificate":"%s","status":"BAD STATUS","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			err: errors.New("bad status value"),
		},
		{
			name: "BadStatusType",
			data: []byte(fmt.Sprintf(`{"certificate":"%s","status":1234,"updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			err: errors.New("bad status type"),
		},
		{
			name: "BadPEM",
			data: []byte(`{"certificate":"BAD PEM","status":"ISSUED","updated_at":1477958400}`),
			err:  errors.New("invalid PEM"),
		},
		{
			name: "EmptyPEM",
			data: []byte(`{"certificate":"","status":"ISSUED","updated_at":1477958400}`),
			err:  errors.New("missing PEM"),
		},
		{
			name: "InvalidCertificate",
			data: []byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(strings.Replace(testPEM, "\n", "\\n", -1), "M", "N", -1))),
			err: errors.New("invalid certificate"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hvclient.CertInfo
			var err = json.Unmarshal(tc.data, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertStatusStringInvalidValue(t *testing.T) {
	t.Parallel()

	var want = "ERROR: UNKNOWN STATUS"
	if got := hvclient.CertStatus(0).String(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
