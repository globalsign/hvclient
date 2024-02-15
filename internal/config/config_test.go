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

package config_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/globalsign/hvclient/internal/config"
)

func TestConfigNewFromFile(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		filename string
		want     config.Config
	}{
		{
			filename: "testdata/test.conf",
			want: config.Config{
				URL:           "https://emea.api.hvca.globalsign.com:8443/v2",
				APIKey:        "api key goes here",
				APISecret:     "api secret goes here",
				CertFile:      "/home/jdoe/fully/qualified/path/to/certfile.pem",
				KeyFile:       "/home/jdoe/fully/qualified/path/to/keyfile.pem",
				KeyPassphrase: "",
				Timeout:       30,
			},
		},
		{
			filename: "testdata/test_enc.conf",
			want: config.Config{
				URL:           "https://emea.api.hvca.globalsign.com:8443/v2",
				APIKey:        "api key goes here",
				APISecret:     "api secret goes here",
				CertFile:      "/home/jdoe/fully/qualified/path/to/certfile.pem",
				KeyFile:       "/home/jdoe/fully/qualified/path/to/keyfile.pem",
				KeyPassphrase: "mypassphrase",
				Timeout:       30,
			},
		},
		{
			filename: "testdata/test_insecure.conf",
			want: config.Config{
				URL:                "https://emea.api.hvca.globalsign.com:8443/v2",
				APIKey:             "api key goes here",
				APISecret:          "api secret goes here",
				CertFile:           "/home/jdoe/fully/qualified/path/to/certfile.pem",
				KeyFile:            "/home/jdoe/fully/qualified/path/to/keyfile.pem",
				KeyPassphrase:      "",
				InsecureSkipVerify: true,
				ExtraHeaders: map[string]string{
					"X-SSL-Client-Serial": "01C71933E117CBB601887D9738BB1690",
				},
				Timeout: 30,
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(filepath.Base(tc.filename), func(t *testing.T) {
			t.Parallel()

			var got, err = config.NewFromFile(tc.filename)
			if err != nil {
				t.Fatalf("couldn't get configuration from file: %v", err)
			}

			if !cmp.Equal(*got, tc.want) {
				t.Errorf("got %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestConfigNewFromFileError(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"there/is/no_such_file.conf",
		"testdata/malformed.conf",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(filepath.Base(tc), func(t *testing.T) {
			t.Parallel()

			var _, err = config.NewFromFile(tc)
			if err == nil {
				t.Errorf("unexpectedly got configuration from file")
			}
		})
	}
}
