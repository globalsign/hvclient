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
		err   error
	}{
		{
			name: "StatusSuccess",
			entry: hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationSuccess,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
			want: []byte(`{"status":"SUCCESS","description":"All is well","timestamp":1477958400}`),
		},
		{
			name: "StatusError",
			entry: hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationError,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
			want: []byte(`{"status":"ERROR","description":"All is well","timestamp":1477958400}`),
		},
		{
			name: "BadStatus",
			entry: hvclient.ClaimLogEntry{
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
			err: errors.New("bad status"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.Marshal(tc.entry)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestClaimLogEntryUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		json string
		want hvclient.ClaimLogEntry
		err  error
	}{
		{
			json: `{"status":"SUCCESS","description":"All is well","timestamp":1477958400}`,
			want: hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationSuccess,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
		},
		{
			json: `{"status":"ERROR","description":"All is well","timestamp":1477958400}`,
			want: hvclient.ClaimLogEntry{
				Status:      hvclient.VerificationError,
				Description: "All is well",
				TimeStamp:   time.Unix(1477958400, 0),
			},
		},
		{
			json: `{"status":1234}`,
			err:  errors.New("bad type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.json, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimLogEntry
			var err = json.Unmarshal([]byte(tc.json), &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
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
			name: "LogLength",
			first: hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
					{Status: hvclient.VerificationError},
				},
			},
			second: hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
				},
			},
		},
		{
			name: "LogValue",
			first: hvclient.Claim{
				Log: []hvclient.ClaimLogEntry{
					{Status: hvclient.VerificationSuccess},
				},
			},
			second: hvclient.Claim{
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
		err   error
	}{
		{
			name: "Good",
			claim: hvclient.Claim{
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
			want: []byte(`{
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
		{
			name: "BadValue",
			claim: hvclient.Claim{
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
			err: errors.New("bad value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = json.MarshalIndent(tc.claim, "", "    ")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("got %s, want %s", string(got), string(tc.want))
			}
		})
	}
}

func TestClaimUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		json string
		want hvclient.Claim
		err  error
	}{
		{
			name: "OK",
			json: `{
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
			want: hvclient.Claim{
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
		{
			name: "BadIDType",
			json: `{"id":1234}`,
			err:  errors.New("bad type"),
		},
		{
			name: "BadStatusType",
			json: `{"status":1234}`,
			err:  errors.New("bad type"),
		},
		{
			name: "BadStatusValue",
			json: `{"status":"bad status value"}`,
			err:  errors.New("bad value"),
		},
		{
			name: "BadLogStatusValue",
			json: `{
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
			err: errors.New("bad value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.json, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.Claim
			var err = json.Unmarshal([]byte(tc.json), &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
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
			name: "One",
			entry: hvclient.ClaimAssertionInfo{
				Token:    "1234",
				AssertBy: time.Unix(1477958400, 0),
				ID:       "/path/to/claim",
			},
			want: []byte(`{"token":"1234","assert_by":1477958400,"id":"/path/to/claim"}`),
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
		err  error
	}{
		{
			name: "OK",
			json: []byte(`{"token":"1234","assert_by":1477958400,"id":"/path/to/claim"}`),
			want: hvclient.ClaimAssertionInfo{
				Token:    "1234",
				AssertBy: time.Unix(1477958400, 0),
				ID:       "/path/to/claim",
			},
		},
		{
			name: "BadType",
			json: []byte(`{"token":1234}`),
			err:  errors.New("bad type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.ClaimAssertionInfo
			var err = json.Unmarshal(tc.json, &got)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}
