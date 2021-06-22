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
	"math/big"
	"time"
)

// CertMeta contains certificate metadata.
type CertMeta struct {
	SerialNumber *big.Int  // Certificate serial number
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
	if (c.SerialNumber == nil) != (other.SerialNumber == nil) {
		return false
	}

	if c.SerialNumber != nil && c.SerialNumber.Cmp(other.SerialNumber) != 0 {
		return false
	}

	return c.NotBefore.Equal(other.NotBefore) &&
		c.NotAfter.Equal(other.NotAfter)
}

// MarshalJSON returns the JSON encoding of a certificate metadata object.
func (c CertMeta) MarshalJSON() ([]byte, error) {
	return json.Marshal(jsonCertMeta{
		SerialNumber: fmt.Sprintf("%X", c.SerialNumber),
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

	var sn, ok = big.NewInt(0).SetString(data.SerialNumber, 16)
	if !ok {
		return fmt.Errorf("invalid serial number: %s", data.SerialNumber)
	}

	*c = CertMeta{
		SerialNumber: sn,
		NotBefore:    time.Unix(data.NotBefore, 0).UTC(),
		NotAfter:     time.Unix(data.NotAfter, 0).UTC(),
	}

	return nil
}
