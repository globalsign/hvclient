/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
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
	Status      ClaimLogEntryStatus // Success or error
	Description string              // Log entry description
	TimeStamp   time.Time           // Time of log entry
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

// Claim is a domain claim, as returned by a /claims/domains/{claimID}
// API call.
type Claim struct {
	ID        string          // Claim ID
	Status    ClaimStatus     // Pending or verified
	Domain    string          // The domain being claimed
	CreatedAt time.Time       // Time this claim was created
	ExpiresAt time.Time       // Time this claim expires
	AssertBy  time.Time       // Time by which this claim must be asserted
	Log       []ClaimLogEntry // List of verification log entries for the claim
}

// jsonClaim is used internally for JSON marshalling/unmarshalling.
type jsonClaim struct {
	ID        string          `json:"id"`
	Status    ClaimStatus     `json:"status"`
	Domain    string          `json:"domain"`
	CreatedAt int64           `json:"created_at"`
	ExpiresAt int64           `json:"expires_at"`
	AssertBy  int64           `json:"assert_by"`
	Log       []ClaimLogEntry `json:"log"`
}

// ClaimAssertionInfo is the response from a /claims/domains API call.
type ClaimAssertionInfo struct {
	Token    string    // Token to be used for the assertion
	AssertBy time.Time // Time by which this claim must be asserte
	ID       string    // ID of the claim
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
	var err error

	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}

	var ok bool
	var result ClaimStatus
	if result, ok = claimStatusCodes[strings.ToUpper(data)]; !ok {
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
	var err error

	if err = json.Unmarshal(b, &data); err != nil {
		return err
	}

	var ok bool
	var result ClaimLogEntryStatus
	if result, ok = claimLogEntryStatusCodes[strings.ToUpper(data)]; !ok {
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
		c.CreatedAt.Equal(other.CreatedAt) &&
		c.ExpiresAt.Equal(other.ExpiresAt) &&
		c.AssertBy.Equal(other.AssertBy)
}

// MarshalJSON returns the JSON encoding of a domain claim and stores the
// result in the object.
func (c Claim) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonClaim{
		ID:        c.ID,
		Status:    c.Status,
		Domain:    c.Domain,
		CreatedAt: c.CreatedAt.Unix(),
		ExpiresAt: c.ExpiresAt.Unix(),
		AssertBy:  c.AssertBy.Unix(),
		Log:       c.Log,
	})
}

// UnmarshalJSON parses a JSON-encoded domain claim and stores the result in
// the object.
func (c *Claim) UnmarshalJSON(b []byte) error {
	var data *jsonClaim

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*c = Claim{
		ID:        data.ID,
		Status:    data.Status,
		Domain:    data.Domain,
		CreatedAt: time.Unix(data.CreatedAt, 0),
		ExpiresAt: time.Unix(data.ExpiresAt, 0),
		AssertBy:  time.Unix(data.AssertBy, 0),
		Log:       data.Log,
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
	var data *jsonClaimLogEntry

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*l = ClaimLogEntry{
		Status:      data.Status,
		Description: data.Description,
		TimeStamp:   time.Unix(data.TimeStamp, 0),
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
	var data *jsonClaimAssertionInfo

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*c = ClaimAssertionInfo{
		Token:    data.Token,
		AssertBy: time.Unix(data.AssertBy, 0),
		ID:       data.ID,
	}

	return nil
}
