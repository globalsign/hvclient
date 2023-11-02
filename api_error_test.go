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
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/globalsign/hvclient/internal/httputils"
	"github.com/google/go-cmp/cmp"
)

// errReader implements io.Reader and always returns an error.
type errReader struct{}

func (e errReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("triggered error")
}

func TestAPIError(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *http.Response
		want APIError
	}{
		{
			name: "OK",
			in: &http.Response{
				Body: ioutil.NopCloser(strings.NewReader(`{"description":"custom message"}`)),
				Header: http.Header{
					httputils.ContentTypeHeader: []string{httputils.ContentTypeProblemJSON},
				},
				StatusCode: http.StatusBadRequest,
			},
			want: APIError{
				StatusCode:  http.StatusBadRequest,
				Description: "custom message",
			},
		},
		{
			name: "BadContentType",
			in: &http.Response{
				Body: ioutil.NopCloser(strings.NewReader(`{"description":"custom message"}`)),
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/plain"},
				},
				StatusCode: http.StatusUnauthorized,
			},
			want: APIError{
				StatusCode:  http.StatusUnauthorized,
				Description: "unknown API error",
			},
		},
		{
			name: "BadBody",
			in: &http.Response{
				Body: ioutil.NopCloser(errReader{}),
				Header: http.Header{
					httputils.ContentTypeHeader: []string{httputils.ContentTypeProblemJSON},
				},
				StatusCode: http.StatusNotFound,
			},
			want: APIError{
				StatusCode:  http.StatusNotFound,
				Description: "unknown API error",
			},
		},
		{
			name: "BadJSON",
			in: &http.Response{
				Body: ioutil.NopCloser(strings.NewReader(`{"description":"custom mess`)),
				Header: http.Header{
					httputils.ContentTypeHeader: []string{httputils.ContentTypeProblemJSON},
				},
				StatusCode: http.StatusServiceUnavailable,
			},
			want: APIError{
				StatusCode:  http.StatusServiceUnavailable,
				Description: "unknown API error",
			},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got = NewAPIError(tc.in)
			if !cmp.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAPIErrorString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   APIError
		want string
	}{
		{
			name: "OK",
			in: APIError{
				StatusCode:  http.StatusBadRequest,
				Description: "custom message",
			},
			want: "400: custom message",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.in.Error(); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
