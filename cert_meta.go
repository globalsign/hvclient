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
	"time"
)

// CertMeta is the certificate metadata returned by one of the
// HVCA GET /stats API calls.
type CertMeta struct {
	SerialNumber string    // Certificate serial number
	NotBefore    time.Time // Certificate not valid before this time
	NotAfter     time.Time // Certificate not valid after this time
}

// jsonCertMeta is used internally for JSON marshalling/unmarshalling.
type jsonCertMeta struct {
	SerialNumber string `json:"serial_number"`
	NotBefore    int64  `json:"not_before"`
	NotAfter     int64  `json:"not_after"`
}

// Equal checks if two certificate metadata objects are equivalent.
func (c CertMeta) Equal(other CertMeta) bool {
	return c.SerialNumber == other.SerialNumber &&
		c.NotBefore.Equal(other.NotBefore) &&
		c.NotAfter.Equal(other.NotAfter)
}

// MarshalJSON returns the JSON encoding of a certificate metadata object.
func (c CertMeta) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonCertMeta{
		SerialNumber: c.SerialNumber,
		NotBefore:    c.NotBefore.Unix(),
		NotAfter:     c.NotAfter.Unix(),
	})
}

// UnmarshalJSON parses a JSON-encoded certificate metadata object and stores
// the result in the object.
func (c *CertMeta) UnmarshalJSON(b []byte) error {
	var data jsonCertMeta
	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	*c = CertMeta{
		SerialNumber: data.SerialNumber,
		NotBefore:    time.Unix(data.NotBefore, 0),
		NotAfter:     time.Unix(data.NotAfter, 0),
	}

	return nil
}
