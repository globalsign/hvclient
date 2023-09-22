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

package hvclient

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ClaimStatus is the pending/verified status of a domain claim.
type ClaimStatus int

// ClaimLogEntry is a domain claim verification log entry.
type ClaimLogEntry struct {
	Status      ClaimLogEntryStatus
	Description string
	TimeStamp   time.Time
}

// jsonClaimLogEntry is used internally for JSON marshalling/unmarshalling.
type jsonClaimLogEntry struct {
	Status      ClaimLogEntryStatus `json:"status"`
	Description string              `json:"description"`
	TimeStamp   int64               `json:"timestamp"`
}

// ClaimLogEntryStatus is the success/error status of a domain claim
// verification log entry.
type ClaimLogEntryStatus int

// Claim is a domain claim.
type Claim struct {
	ID                     string
	Status                 ClaimStatus
	Token                  string
	Domain                 string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	AssertBy               time.Time
	LastVerifiedAt         time.Time
	LastVerificationMethod string
	Log                    []ClaimLogEntry
}

// jsonClaim is used internally for JSON marshalling/unmarshalling.
type jsonClaim struct {
	ID                     string          `json:"id"`
	Status                 ClaimStatus     `json:"status"`
	Token                  string          `json:"token"`
	Domain                 string          `json:"domain"`
	CreatedAt              int64           `json:"created_at"`
	ExpiresAt              int64           `json:"expires_at"`
	AssertBy               int64           `json:"assert_by"`
	LastVerifiedAt         int64           `json:"last_verified_at"`
	LastVerificationMethod string          `json:"last_verification_method"`
	Log                    []ClaimLogEntry `json:"log"`
}

// ClaimAssertionInfo contains information for making a domain claim.
type ClaimAssertionInfo struct {
	Token    string
	AssertBy time.Time
	ID       string
}

// jsonClaimAssertionInfo is used internally for JSON marshalling/unmarshalling.
type jsonClaimAssertionInfo struct {
	Token    string `json:"token"`
	AssertBy int64  `json:"assert_by"`
	ID       string `json:"id"`
}

// Domain claim status constants.
const (
	StatusPending ClaimStatus = iota + 1
	StatusVerified
)

// Claim log entry status constants.
const (
	VerificationSuccess ClaimLogEntryStatus = iota + 1
	VerificationError
	VerificationInfo
)

// claimStatusNames maps claim status values to their descriptions.
var claimStatusNames = [...]string{
	StatusPending:  "PENDING",
	StatusVerified: "VERIFIED",
}

// claimsStatusCodes maps claim status descriptions to their values.
var claimStatusCodes = map[string]ClaimStatus{
	"PENDING":  StatusPending,
	"VERIFIED": StatusVerified,
}

// claimLogEntryStatusNames maps domain claim verification log entry status
// values to their descriptions.
var claimLogEntryStatusNames = [...]string{
	VerificationSuccess: "SUCCESS",
	VerificationError:   "ERROR",
	VerificationInfo:    "INFO",
}

// claimLogEntryStatusCodes maps domain claim verification log entry status
// descriptions to their values.
var claimLogEntryStatusCodes = map[string]ClaimLogEntryStatus{
	"SUCCESS": VerificationSuccess,
	"ERROR":   VerificationError,
	"INFO":    VerificationInfo,
}

// isValid checks if a claims status value is within a valid range.
func (s ClaimStatus) isValid() bool {
	return s >= StatusPending && s <= StatusVerified
}

// String returns a description of the claim status.
func (s ClaimStatus) String() string {
	if !s.isValid() {
		return "ERROR: UNKNOWN STATUS"
	}

	return claimStatusNames[s]
}

// MarshalJSON returns the JSON encoding of a claim status value.
func (s ClaimStatus) MarshalJSON() ([]byte, error) {
	if !s.isValid() {
		return nil, fmt.Errorf("invalid claim status value: %d", s)
	}

	return json.Marshal(s.String())
}

// UnmarshalJSON parses a JSON-encoded claim status value and stores the
// result in the object.
func (s *ClaimStatus) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var result, ok = claimStatusCodes[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("invalid claim status value: %s", data)
	}

	*s = result

	return nil
}

// isValid checks if a claims status value is within a valid range.
func (s ClaimLogEntryStatus) isValid() bool {
	return s >= VerificationSuccess && s <= VerificationInfo
}

// String returns a description of the claim status.
func (s ClaimLogEntryStatus) String() string {
	if !s.isValid() {
		return "ERROR: UNKNOWN STATUS"
	}

	return claimLogEntryStatusNames[s]
}

// MarshalJSON returns the JSON encoding of a domain claim verification log
// entry status value.
func (s ClaimLogEntryStatus) MarshalJSON() ([]byte, error) {
	if !s.isValid() {
		return nil, fmt.Errorf("invalid claim log entry status value: %d", s)
	}

	return json.Marshal(s.String())
}

// UnmarshalJSON parses a JSON-encoded domain claim verification log entry
// status value and stores the result in the object.
func (s *ClaimLogEntryStatus) UnmarshalJSON(b []byte) error {
	var data string
	var err = json.Unmarshal(b, &data)
	if err != nil {
		return err
	}

	var result, ok = claimLogEntryStatusCodes[strings.ToUpper(data)]
	if !ok {
		return fmt.Errorf("invalid claim log entry status value: %s", data)
	}

	*s = result

	return nil
}

// Equal checks if two domain claims are equivalent.
func (c Claim) Equal(other Claim) bool {
	if len(c.Log) != len(other.Log) {
		return false
	}

	for i := range c.Log {
		if !c.Log[i].Equal(other.Log[i]) {
			return false
		}
	}

	return c.ID == other.ID &&
		c.Status == other.Status &&
		c.Domain == other.Domain &&
		c.Token == other.Token &&
		c.LastVerificationMethod == other.LastVerificationMethod &&
		c.CreatedAt.Equal(other.CreatedAt) &&
		c.ExpiresAt.Equal(other.ExpiresAt) &&
		c.AssertBy.Equal(other.AssertBy) &&
		c.LastVerifiedAt.Equal(other.LastVerifiedAt)

}

// MarshalJSON returns the JSON encoding of a domain claim and stores the
// result in the object.
func (c Claim) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonClaim{
		ID:                     c.ID,
		Status:                 c.Status,
		Domain:                 c.Domain,
		Token:                  c.Token,
		CreatedAt:              c.CreatedAt.Unix(),
		ExpiresAt:              c.ExpiresAt.Unix(),
		AssertBy:               c.AssertBy.Unix(),
		LastVerifiedAt:         c.LastVerifiedAt.Unix(),
		LastVerificationMethod: c.LastVerificationMethod,
		Log:                    c.Log,
	})
}

// UnmarshalJSON parses a JSON-encoded domain claim and stores the result in
// the object.
func (c *Claim) UnmarshalJSON(b []byte) error {
	var data jsonClaim
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*c = Claim{
		ID:                     data.ID,
		Status:                 data.Status,
		Domain:                 data.Domain,
		Token:                  data.Token,
		CreatedAt:              time.Unix(data.CreatedAt, 0).UTC(),
		ExpiresAt:              time.Unix(data.ExpiresAt, 0).UTC(),
		AssertBy:               time.Unix(data.AssertBy, 0).UTC(),
		LastVerifiedAt:         time.Unix(data.LastVerifiedAt, 0).UTC(),
		LastVerificationMethod: data.LastVerificationMethod,
		Log:                    data.Log,
	}

	return nil
}

// Equal checks if two domain claim verification log entries are
// equivalent.
func (l ClaimLogEntry) Equal(other ClaimLogEntry) bool {
	return l.Status == other.Status &&
		l.Description == other.Description &&
		l.TimeStamp.Equal(other.TimeStamp)
}

// MarshalJSON returns the JSON encoding of a domain claim verification log
// entry.
func (l ClaimLogEntry) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonClaimLogEntry{
		Status:      l.Status,
		Description: l.Description,
		TimeStamp:   l.TimeStamp.Unix(),
	})
}

// UnmarshalJSON parses a JSON-encoded domain claim verification log entry
// and stores the result in the object.
func (l *ClaimLogEntry) UnmarshalJSON(b []byte) error {
	var data jsonClaimLogEntry
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*l = ClaimLogEntry{
		Status:      data.Status,
		Description: data.Description,
		TimeStamp:   time.Unix(data.TimeStamp, 0).UTC(),
	}

	return nil
}

// Equal checks if two domain claim assertion info objects are equivalent.
func (c ClaimAssertionInfo) Equal(other ClaimAssertionInfo) bool {
	return c.Token == other.Token &&
		c.AssertBy.Equal(other.AssertBy) &&
		c.ID == other.ID
}

// MarshalJSON returns the JSON encoding of a domain claim assertion info
// object.
func (c ClaimAssertionInfo) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonClaimAssertionInfo{
		Token:    c.Token,
		AssertBy: c.AssertBy.Unix(),
		ID:       c.ID,
	})
}

// UnmarshalJSON parses a JSON-encoded domain claim assertion info object
// and stores the result in the object.
func (c *ClaimAssertionInfo) UnmarshalJSON(b []byte) error {
	var data jsonClaimAssertionInfo
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*c = ClaimAssertionInfo{
		Token:    data.Token,
		AssertBy: time.Unix(data.AssertBy, 0).UTC(),
		ID:       data.ID,
	}

	return nil
}
