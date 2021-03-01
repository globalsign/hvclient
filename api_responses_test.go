/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
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

func TestHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name, want string
		add        []string
	}{
		{
			"Location",
			"Here",
			[]string{"Here", "There", "Everywhere"},
		},
		{
			"Things",
			"Curtains",
			[]string{"Curtains"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got string
			var err error

			if got, err = headerFromResponse(response, tc.name); err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			"Location",
			[]string{},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := headerFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpected got header value %q", got)
			}
		})
	}
}

func TestBasePathHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name, want string
		add        []string
	}{
		{
			"Location",
			"Here",
			[]string{"/path/to/Here", "/path/to/There"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got string
			var err error

			if got, err = basePathHeaderFromResponse(response, tc.name); err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBasePathHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			"Location",
			[]string{},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := basePathHeaderFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpectedly got header value %q", got)
			}
		})
	}
}

func TestIntegerHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		want int64
		add  []string
	}{
		{
			"Total-Count",
			5,
			[]string{"5", "gasoline"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got int64
			var err error

			if got, err = intHeaderFromResponse(response, tc.name); err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIntegerHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			"Location",
			[]string{},
		},
		{
			"Total-Count",
			[]string{"armchair", "7"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := intHeaderFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpectedly got header value %d", got)
			}
		})
	}
}

func TestCounter(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want int64
	}{
		{
			"A",
			`{"value":5}`,
			5,
		},
		{
			"B",
			`{"value":99}`,
			99,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got int64
			var err error

			if got, err = counterFromResponse(response); err != nil {
				t.Fatalf("couldn't get cert info: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestCounterFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJSON",
			`{"bad json`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := counterFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got counter: %d", got)
			}
		})
	}
}

func TestStringSlice(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want []string
	}{
		{
			"A",
			`["first","second","third"]`,
			[]string{"first", "second", "third"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got []string
			var err error

			if got, err = stringSliceFromResponse(response); err != nil {
				t.Fatalf("couldn't get string slice: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStringSliceFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJSON",
			`{"bad json`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := stringSliceFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got string slice: %v", got)
			}
		})
	}
}

func TestCertInfo(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want CertInfo
	}{
		{
			"A",
			fmt.Sprintf(`{"certificate":"%s","status":"ISSUED","updated_at":1550284892}`,
				strings.Replace(testPEM, "\n", "\\n", -1)),
			CertInfo{
				PEM:       testPEM,
				Status:    StatusIssued,
				UpdatedAt: time.Unix(1550284892, 0),
			},
		},
		{
			"B",
			fmt.Sprintf(`{"certificate":"%s","status":"REVOKED","updated_at":1550284892}`,
				strings.Replace(testPEM, "\n", "\\n", -1)),
			CertInfo{
				PEM:       testPEM,
				Status:    StatusRevoked,
				UpdatedAt: time.Unix(1550284892, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got *CertInfo
			var err error

			if got, err = certInfoFromResponse(response); err != nil {
				t.Fatalf("couldn't get cert info: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCertInfoFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJSON",
			`{"bad json`,
		},
		{
			"BadStatus",
			`{"certificate":"more data","status":"VAPORIZED","updated_at":1550284892}`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := certInfoFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got cert info: %v", got)
			}
		})
	}
}

func TestCertMetas(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name      string
		body      string
		count     string
		wantcount int64
	}{
		{
			"One",
			`[{"serial_number":"1","not_before":1,"not_after":2}]`,
			"1",
			1,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", tc.count)

			var got []CertMeta
			var count int64
			var err error

			if got, count, err = certMetasFromResponse(response); err != nil {
				t.Fatalf("couldn't get cert info: %v", err)
			}

			if int64(len(got)) != tc.wantcount {
				t.Errorf("got length %d, want %d", int64(len(got)), tc.wantcount)
			}

			if count != tc.wantcount {
				t.Errorf("got %d, want %d", count, tc.wantcount)
			}
		})
	}
}

func TestCertMetasFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		body  string
		count string
	}{
		{
			"BadJSON",
			`{"bad json`,
			"0",
		},
		{
			"BadCount",
			`[{"serial_number":"1","not_before":1,"not_after":2}]`,
			"indeterminate",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", tc.count)

			if got, _, err := certMetasFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got cert metas: %v", got)
			}
		})
	}
}

func TestPolicy(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want Policy
	}{
		{
			"A",
			`{"validity":{"secondsmin":10,"secondsmax":20}}`,
			Policy{
				Validity: &ValidityPolicy{
					SecondsMin: 10,
					SecondsMax: 20,
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got *Policy
			var err error

			if got, err = policyFromResponse(response); err != nil {
				t.Fatalf("couldn't get policy: %v", err)
			}

			if !reflect.DeepEqual(got.Validity, tc.want.Validity) {
				t.Errorf("got %v, want %v", got.Validity, tc.want.Validity)
			}
		})
	}
}

func TestPolicyFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJSON",
			`{"bad json`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := policyFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got policy: %v", got)
			}
		})
	}
}

func TestClaimsFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		body  string
		count string
		want  []Claim
	}{
		{
			"One",
			"[]",
			"0",
			[]Claim{},
		},
		{
			"Two",
			`[
			    {
                    "id": "1234",
                    "status": "VERIFIED",
                    "domain": "example.com",
                    "created_at": 1477958400,
                    "expires_at": 1477958600,
                    "assert_by": 1477958500,
                    "log":[
                        {
                            "status":"SUCCESS",
                            "description":"All is well",
                            "timestamp":1477958400
                        }
                    ]
                }
            ]`,
			"1",
			[]Claim{
				{
					ID:        "1234",
					Status:    StatusVerified,
					Domain:    "example.com",
					CreatedAt: time.Unix(1477958400, 0),
					ExpiresAt: time.Unix(1477958600, 0),
					AssertBy:  time.Unix(1477958500, 0),
					Log: []ClaimLogEntry{
						ClaimLogEntry{
							Status:      VerificationSuccess,
							Description: "All is well",
							TimeStamp:   time.Unix(1477958400, 0),
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

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", tc.count)

			var got []Claim
			var count int64
			var err error

			if got, count, err = claimsFromResponse(response); err != nil {
				t.Fatalf("couldn't get claims: %v", err)
			}

			if len(got) != len(tc.want) {
				t.Errorf("got length %d, want %d", len(got), len(tc.want))
			}

			if count != int64(len(tc.want)) {
				t.Errorf("got %d, want %d", count, len(tc.want))
			}
		})
	}
}

func TestClaimsFromResponseFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJson",
			`[{"id":false}]`,
		},
		{
			"BadCount",
			`[]`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", "not a count")

			if got, _, err := claimsFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got claims: %v", got)
			}
		})
	}
}

func TestClaimFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want Claim
	}{
		{
			"One",
			`{
                "id": "1234",
                "status": "VERIFIED",
                "domain": "example.com",
                "created_at": 1477958400,
                "expires_at": 1477958600,
                "assert_by": 1477958500,
                "log":[
                    {
                        "status":"SUCCESS",
                        "description":"All is well",
                        "timestamp":1477958400
                    }
                ]
            }`,
			Claim{
				ID:        "1234",
				Status:    StatusVerified,
				Domain:    "example.com",
				CreatedAt: time.Unix(1477958400, 0),
				ExpiresAt: time.Unix(1477958600, 0),
				AssertBy:  time.Unix(1477958500, 0),
				Log: []ClaimLogEntry{
					ClaimLogEntry{
						Status:      VerificationSuccess,
						Description: "All is well",
						TimeStamp:   time.Unix(1477958400, 0),
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got *Claim
			var err error

			if got, err = claimFromResponse(response); err != nil {
				t.Fatalf("couldn't get claim: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClaimFromResponseFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJson",
			`[{"id":false}]`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := claimFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got claim: %v", got)
			}
		})
	}
}

func TestClaimAssertionInfoFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name     string
		body     string
		location string
		want     ClaimAssertionInfo
	}{
		{
			"One",
			`{"token":"1234","assert_by":1477958500}`,
			"/path/to/claim",
			ClaimAssertionInfo{
				Token:    "1234",
				AssertBy: time.Unix(1477958500, 0),
				ID:       "claim",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Location", tc.location)

			var got *ClaimAssertionInfo
			var err error

			if got, err = claimAssertionInfoFromResponse(response); err != nil {
				t.Fatalf("couldn't get claim assertion info: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestClaimAssertionInfoFromResponseFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJson",
			`[{"token":false}]`,
		},
		{
			"NoLocation",
			`{"token":"1234","assert_by":1477958500}`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := claimAssertionInfoFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got claim assertion info: %v", got)
			}
		})
	}
}

func TestTokenFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
		want string
	}{
		{
			"One",
			`{"access_token":"1234"}`,
			"1234",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got string
			var err error

			if got, err = tokenFromResponse(response); err != nil {
				t.Fatalf("couldn't get token: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestTokenFromResponseFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		body string
	}{
		{
			"BadJson",
			`[{"access_token":false}]`,
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)
			recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := tokenFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got token: %v", got)
			}
		})
	}
}
