/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient_test

import (
	"encoding/json"
	"reflect"
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
			"One",
			hvclient.CertMeta{
				SerialNumber: "1234",
				NotBefore:    time.Unix(1477958400, 0),
				NotAfter:     time.Unix(1478958400, 0),
			},
			[]byte(`{"serial_number":"1234","not_before":1477958400,"not_after":1478958400}`),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err error
			var got []byte

			if got, err = json.Marshal(tc.entry); err != nil {
				t.Fatalf("couldn't marshal JSON: %v", err)
			}

			if !reflect.DeepEqual(got, tc.want) {
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
	}{
		{
			"One",
			[]byte(`{"serial_number":"1234","not_before":1477958400,"not_after":1478958400}`),
			hvclient.CertMeta{
				SerialNumber: "1234",
				NotBefore:    time.Unix(1477958400, 0),
				NotAfter:     time.Unix(1478958400, 0),
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err error
			var got *hvclient.CertMeta

			if err = json.Unmarshal(tc.json, &got); err != nil {
				t.Fatalf("couldn't unmarshal JSON: %v", err)
			}

			if !got.Equal(tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestCertMetaUnmarshalJSONFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		`{"serial_number":1234}`,
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			var got *hvclient.CertMeta

			if err := json.Unmarshal([]byte(tc), &got); err == nil {
				t.Errorf("unexpectedly unmarshalled JSON")
			}
		})
	}
}
