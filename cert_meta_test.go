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
	"math/big"
	"testing"
	"time"

	"github.com/globalsign/hvclient"
)

func TestCertMetaMarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name  string
		entry hvclient.CertMeta
		want  []byte
	}{
		{
			name: "OK",
			entry: hvclient.CertMeta{
				SerialNumber: big.NewInt(0x1234),
				NotBefore:    time.Unix(1477958400, 0),
				NotAfter:     time.Unix(1478958400, 0),
			},
			want: []byte(`{"serial_number":"1234","not_before":1477958400,"not_after":1478958400}`),
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

func TestCertMetaUnmarshalJSON(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		json []byte
		want hvclient.CertMeta
		err  error
	}{
		{
			name: "OK",
			json: []byte(`{"serial_number":"1234","not_before":1477958400,"not_after":1478958400}`),
			want: hvclient.CertMeta{
				SerialNumber: big.NewInt(0x1234),
				NotBefore:    time.Unix(1477958400, 0),
				NotAfter:     time.Unix(1478958400, 0),
			},
		},
		{
			name: "BadType",
			json: []byte(`{"serial_number":1234}`),
			err:  errors.New("bad type"),
		},
		{
			name: "BadValue",
			json: []byte(`{"serial_number":"not a number"}`),
			err:  errors.New("bad value"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.CertMeta
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
