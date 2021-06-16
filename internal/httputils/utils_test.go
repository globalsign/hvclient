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
