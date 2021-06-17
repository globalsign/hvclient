/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

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

			var got, err = headerFromResponse(response, tc.name)
			if err != nil {
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

			var got, err = basePathHeaderFromResponse(response, tc.name)
			if err != nil {
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

			var got, err = intHeaderFromResponse(response, tc.name)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got, err = counterFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := counterFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got counter: %d", got)
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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", tc.count)

			var got, count, err = certMetasFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got, err = policyFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Total-Count", tc.count)

			var got, count, err = claimsFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got, err = claimFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()
			response.Header.Add("Location", tc.location)

			var got, err = claimAssertionInfoFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			var got, err = tokenFromResponse(response)
			if err != nil {
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
			_, _ = recorder.Write([]byte(tc.body))

			var response = recorder.Result()

			if got, err := tokenFromResponse(response); err == nil {
				t.Fatalf("unexpectedly got token: %v", got)
			}
		})
	}
}
