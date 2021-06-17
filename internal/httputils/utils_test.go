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

package httputils_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/globalsign/hvclient/internal/httputils"
)

func TestVerifyRequestContentType(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		r    *http.Request
		ct   string
		err  error
	}{
		{
			name: "OK/NoParams",
			r: &http.Request{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/plain"},
				},
			},
			ct: "text/plain",
		},
		{
			name: "OK/Params",
			r: &http.Request{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/plain;charset=utf-8"},
				},
			},
			ct: "text/plain",
		},
		{
			name: "Bad/NoParams",
			r: &http.Request{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/html"},
				},
			},
			ct:  "text/plain",
			err: errors.New("no match"),
		},
		{
			name: "Bad/Params",
			r: &http.Request{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/html;charset=utf-8"},
				},
			},
			ct:  "text/plain",
			err: errors.New("no match"),
		},
		{
			name: "Bad/BadMediatype",
			r: &http.Request{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"invalid/content/type"},
				},
			},
			ct:  "text/plain",
			err: errors.New("invalid content type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err = httputils.VerifyRequestContentType(tc.r, tc.ct)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}
		})
	}
}

func TestVerifyResponseContentType(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		r    *http.Response
		ct   string
		err  error
	}{
		{
			name: "OK/NoParams",
			r: &http.Response{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/plain"},
				},
			},
			ct: "text/plain",
		},
		{
			name: "OK/Params",
			r: &http.Response{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/plain;charset=utf-8"},
				},
			},
			ct: "text/plain",
		},
		{
			name: "Bad/NoParams",
			r: &http.Response{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/html"},
				},
			},
			ct:  "text/plain",
			err: errors.New("no match"),
		},
		{
			name: "Bad/Params",
			r: &http.Response{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"text/html;charset=utf-8"},
				},
			},
			ct:  "text/plain",
			err: errors.New("no match"),
		},
		{
			name: "Bad/BadMediatype",
			r: &http.Response{
				Header: http.Header{
					httputils.ContentTypeHeader: []string{"invalid/content/type"},
				},
			},
			ct:  "text/plain",
			err: errors.New("invalid content type"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var err = httputils.VerifyResponseContentType(tc.r, tc.ct)
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}
		})
	}
}
