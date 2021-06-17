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
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/globalsign/hvclient/internal/httputils"
)

var apiErrorTestCases = []struct {
	statusCode int
	body       string
	err        APIError
	str        string
}{
	{
		401,
		`{"description":"unauthorized"}`,
		APIError{
			StatusCode:  401,
			Description: "unauthorized",
		},
		"401: unauthorized",
	},
	{
		404,
		`{"description":"not found"}`,
		APIError{
			StatusCode:  404,
			Description: "not found",
		},
		"404: not found",
	},
	{
		422,
		`{"description":"json stopped`,
		APIError{
			StatusCode:  422,
			Description: "unknown API error",
		},
		"422: unknown API error",
	},
}

func TestAPIErrorNew(t *testing.T) {
	t.Parallel()

	for _, tc := range apiErrorTestCases {
		var tc = tc

		t.Run(fmt.Sprintf("%d %s", tc.statusCode, tc.body), func(t *testing.T) {
			t.Parallel()

			var resp = httptest.NewRecorder()
			resp.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeProblemJSON)
			resp.WriteHeader(tc.statusCode)
			_, _ = resp.Write([]byte(tc.body))

			if got := newAPIError(resp.Result()); got != tc.err {
				t.Errorf("got %v, want %v", got, tc.err)
			}
		})
	}
}

func TestAPIErrorString(t *testing.T) {
	t.Parallel()

	for _, tc := range apiErrorTestCases {
		var tc = tc

		t.Run(fmt.Sprintf("%d %s", tc.statusCode, tc.body), func(t *testing.T) {
			t.Parallel()

			var resp = httptest.NewRecorder()
			resp.Header().Set(httputils.ContentTypeHeader, httputils.ContentTypeProblemJSON)
			resp.WriteHeader(tc.statusCode)
			_, _ = resp.Write([]byte(tc.body))

			if got := newAPIError(resp.Result()).Error(); got != tc.str {
				t.Errorf("got %q, want %q", got, tc.str)
			}
		})
	}
}
