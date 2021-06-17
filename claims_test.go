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
	"testing"
	"time"

	"github.com/globalsign/hvclient"
)

func TestClaimLogEntryMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		entry hvclient.ClaimLogEntry
		want  []byte
	}{
		{
			"StatusSuccess",
			hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationSuccess,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
			[]byte(`{"status":"SUCCESS","description":"All is well","timestamp":1477958400}`),
		},
		{
			"StatusError",
			hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationError,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
			[]byte(`{"status":"ERROR","description":"All is well","timestamp":1477958400}`),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.Marshal(tc.entry)
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestClaimLogEntryMarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		entry hvclient.ClaimLogEntry
	}{
		{
			"BadStatus",
			hvclient.ClaimLogEntry{
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got, err := json.Marshal(tc.entry); err == nil {
				t.Fatalf("unexpectedly marshalled JSON: %s", string(got))
			}
		})
	}
}

func TestClaimLogEntryUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		json string
		want hvclient.ClaimLogEntry
	}{
		{
			`{"status":"SUCCESS","description":"All is well","timestamp":1477958400}`,
			hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationSuccess,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
		},
		{
			`{"status":"ERROR","description":"All is well","timestamp":1477958400}`,
			hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationError,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.json, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimLogEntry
			var err = json.Unmarshal([]byte(tc.json), &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestClaimLogEntryUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		`{"status":1234}`,
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimLogEntry
			if err := json.Unmarshal([]byte(tc), &got); err == nil {
				t.Errorf("unexpectedly unmarshalled JSON")
			}
		})
	}
}

func TestClaimNotEqual(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name          string
		first, second hvclient.Claim
	}{
		{
			"LogLength",
			hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
					{Status: hvclient.VerificationError},
				},
			},
			hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
				},
			},
		},
		{
			"LogValue",
			hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
				},
			},
			hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationError},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.first.Equal(tc.second) {
				t.Errorf("incorrectly compared equal")
			}
		})
	}
}

func TestClaimMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		claim hvclient.Claim
		want  []byte
	}{
		{
			"One",
			hvclient.Claim{
				ID:        "1234",
				Status:    hvclient.StatusVerified,
				Domain:    "example.com",
				CreatedAt: time.Unix(1477958400, 0),
				ExpiresAt: time.Unix(1477958600, 0),
				AssertBy:  time.Unix(1477958500, 0),
				Log: []hvclient.ClaimLogEntry{
					hvclient.ClaimLogEntry{
						Status:      hvclient.VerificationSuccess,
						Description: "All is well",
						TimeStamp:   time.Unix(1477958400, 0),
					},
				},
			},
			[]byte(`{
    "id": "1234",
    "status": "VERIFIED",
    "domain": "example.com",
    "created_at": 1477958400,
    "expires_at": 1477958600,
    "assert_by": 1477958500,
    "log": [
        {
            "status": "SUCCESS",
            "description": "All is well",
            "timestamp": 1477958400
        }
    ]
}`),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.MarshalIndent(tc.claim, "", "    ")
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestClaimMarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		claim hvclient.Claim
	}{
		{
			"One",
			hvclient.Claim{
				ID:        "1234",
				Status:    hvclient.ClaimStatus(0),
				Domain:    "example.com",
				CreatedAt: time.Unix(1477958400, 0),
				ExpiresAt: time.Unix(1477958600, 0),
				AssertBy:  time.Unix(1477958500, 0),
				Log: []hvclient.ClaimLogEntry{
					hvclient.ClaimLogEntry{
						Status:      hvclient.VerificationSuccess,
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

			if got, err := json.Marshal(tc.claim); err == nil {
				t.Fatalf("unexpectedly marshalled JSON: %v", got)
			}
		})
	}
}

func TestClaimUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		json string
		want hvclient.Claim
	}{
		{
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
			hvclient.Claim{
				ID:        "1234",
				Status:    hvclient.StatusVerified,
				Domain:    "example.com",
				CreatedAt: time.Unix(1477958400, 0),
				ExpiresAt: time.Unix(1477958600, 0),
				AssertBy:  time.Unix(1477958500, 0),
				Log: []hvclient.ClaimLogEntry{
					hvclient.ClaimLogEntry{
						Status:      hvclient.VerificationSuccess,
						Description: "All is well",
						TimeStamp:   time.Unix(1477958400, 0),
					},
				},
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.json, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.Claim
			var err = json.Unmarshal([]byte(tc.json), &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestClaimUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		`{"id":1234}`,
		`{"status":"bad status value"}`,
		`{"status":1234}`,
		`{
            "id": "1234",
            "status": "VERIFIED",
            "domain": "example.com",
            "created_at": 1477958400,
            "expires_at": 1477958600,
            "assert_by": 1477958500,
            "log":[
                {
                    "status":"BAD VALUE",
                    "description":"All is well",
                    "timestamp":1477958400
                }
            ]
        }`,
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.Claim
			if err := json.Unmarshal([]byte(tc), &got); err == nil {
				t.Errorf("unexpectedly unmarshalled JSON")
			}
		})
	}
}

func TestClaimStatusStringInvalidValue(t *testing.T) {
	var want = "ERROR: UNKNOWN STATUS"

	if got := hvclient.ClaimStatus(0).String(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestClaimLogEntryStatusStringInvalidValue(t *testing.T) {
	var want = "ERROR: UNKNOWN STATUS"

	if got := hvclient.ClaimLogEntryStatus(0).String(); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestClaimAssertionInfoMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		entry hvclient.ClaimAssertionInfo
		want  []byte
	}{
		{
			"One",
			hvclient.ClaimAssertionInfo{
				Token:    "1234",
				AssertBy: time.Unix(1477958400, 0),
				ID:       "/path/to/claim",
			},
			[]byte(`{"token":"1234","assert_by":1477958400,"id":"/path/to/claim"}`),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.Marshal(tc.entry)
			if err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestClaimAssertionInfoUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		json []byte
		want hvclient.ClaimAssertionInfo
	}{
		{
			"One",
			[]byte(`{"token":"1234","assert_by":1477958400,"id":"/path/to/claim"}`),
			hvclient.ClaimAssertionInfo{
				Token:    "1234",
				AssertBy: time.Unix(1477958400, 0),
				ID:       "/path/to/claim",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimAssertionInfo
			var err = json.Unmarshal(tc.json, &got)
			if err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestClaimAssertionInfoUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		`{"token":1234}`,
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimAssertionInfo
			if err := json.Unmarshal([]byte(tc), &got); err == nil {
				t.Errorf("unexpectedly unmarshalled JSON")
			}
		})
	}
}
