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
	"net/http"
	"testing"
	"time"
)

func TestHeaderFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *http.Response
		want string
		err  error
	}{
		{
			name: "MultipleValues",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"Here", "There", "Everywhere"},
				},
			},
			want: "Here",
		},
		{
			name: "OneValue",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"Curtains"},
				},
			},
			want: "Curtains",
		},
		{
			name: "HeaderMissing",
			in: &http.Response{
				Header: http.Header{
					"Wrong-Name": []string{"Cuttlefish"},
				},
			},
			err: errors.New("no header in response"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = headerFromResponse(tc.in, "Test-Header")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBasePathHeaderFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *http.Response
		want string
		err  error
	}{
		{
			name: "MultipleValues",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"/path/to/Here", "path/to/There"},
				},
			},
			want: "Here",
		},
		{
			name: "OneValue",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"/show/me/the/money"},
				},
			},
			want: "money",
		},
		{
			name: "HeaderMissing",
			in: &http.Response{
				Header: http.Header{
					"Wrong-Name": []string{"/path/to/nowhere"},
				},
			},
			err: errors.New("no header in response"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = basePathHeaderFromResponse(tc.in, "Test-Header")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestIntHeaderFromResponse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		in   *http.Response
		want int64
		err  error
	}{
		{
			name: "MultipleValues",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"42", "21", "7"},
				},
			},
			want: 42,
		},
		{
			name: "OneValue",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"418"},
				},
			},
			want: 418,
		},
		{
			name: "BadValue",
			in: &http.Response{
				Header: http.Header{
					"Test-Header": []string{"not an integer"},
				},
			},
			want: 0,
			err:  errors.New("not an integer"),
		},
		{
			name: "HeaderMissing",
			in: &http.Response{
				Header: http.Header{
					"Wrong-Name": []string{"234"},
				},
			},
			err: errors.New("no header in response"),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got, err = intHeaderFromResponse(tc.in, "Test-Header")
			if (err == nil) != (tc.err == nil) {
				t.Fatalf("got error %v, want %v", err, tc.err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPaginationString(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name    string
		page    int
		perPage int
		from    time.Time
		to      time.Time
		want    string
	}{
		{
			name:    "All",
			page:    12,
			perPage: 50,
			from:    time.Date(2019, 1, 14, 5, 13, 22, 0, time.UTC),
			to:      time.Date(2019, 2, 14, 5, 13, 22, 0, time.UTC),
			want:    "?page=12&per_page=50&from=1547442802&to=1550121202",
		},
		{
			name: "NoPerPage",
			page: 12,
			from: time.Date(2019, 1, 14, 5, 13, 22, 0, time.UTC),
			to:   time.Date(2019, 2, 14, 5, 13, 22, 0, time.UTC),
			want: "?page=12&from=1547442802&to=1550121202",
		},
		{
			name:    "NoFrom",
			page:    12,
			perPage: 50,
			to:      time.Date(2019, 3, 17, 5, 13, 22, 0, time.UTC),
			want:    "?page=12&per_page=50&to=1552799602",
		},
		{
			name:    "NoTo",
			page:    12,
			perPage: 50,
			from:    time.Date(2019, 9, 30, 5, 13, 22, 0, time.UTC),
			want:    "?page=12&per_page=50&from=1569820402",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var got = paginationString(tc.page, tc.perPage, tc.from, tc.to)
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}
