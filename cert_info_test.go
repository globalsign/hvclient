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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
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

func TestCertInfoMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		info hvclient.CertInfo
		want []byte
	}{
		{
			"One",
			hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Unix(1477958400, 0),
			},
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
		{
			"Two",
			hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusRevoked,
				UpdatedAt: time.Unix(1477958400, 0),
			},
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"REVOKED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.Marshal(tc.info)
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestCertInfoMarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		info hvclient.CertInfo
	}{
		{
			"One",
			hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.CertStatus(0),
				UpdatedAt: time.Unix(1477958400, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := json.Marshal(tc.info); err == nil {
				t.Fatalf("unexpectedly marshalled JSON: %v", got)
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
	}{
		{
			"One",
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusIssued,
				UpdatedAt: time.Unix(1477958400, 0),
			},
		},
		{
			"Two",
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"REVOKED","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
			hvclient.CertInfo{
				PEM:       testPEM,
				Status:    hvclient.StatusRevoked,
				UpdatedAt: time.Unix(1477958400, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hvclient.CertInfo
			var err = json.Unmarshal(tc.data, &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertInfoUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		data []byte
	}{
		{
			"BadStatusValue",
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"BAD STATUS","updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
		{
			"BadStatusType",
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":1234,"updated_at":1477958400}`,
				strings.Replace(testPEM, "\n", "\\n", -1))),
		},
		{
			"BadPEM",
			[]byte(`{"certificate":"BAD PEM","status":"ISSUED","updated_at":1477958400}`),
		},
		{
			"EmptyPEM",
			[]byte(`{"certificate":"","status":"ISSUED","updated_at":1477958400}`),
		},
		{
			"InvalidPEM",
			[]byte(fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1477958400}`,
				strings.Replace(strings.Replace(testPEM, "\n", "\\n", -1), "M", "N", -1))),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got hvclient.CertInfo

			if err := json.Unmarshal(tc.data, &got); err == nil {
				t.Fatalf("unexpectedly unmarshalled JSON: %v", got)
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
