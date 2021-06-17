/*
Copyright (C) GMO GlobalSign, Inc. 2019 - All Rights Reserved.

Unauthorized copying of this file, via any medium is strictly prohibited.
No distribution/modification of whole or part thereof is allowed.

Proprietary and confidential.
*/

package hvclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name, want string
		add        []string
	}{
		{
			name: "Location",
			add:  []string{"Here", "There", "Everywhere"},
			want: "Here",
		},
		{
			name: "Things",
			add:  []string{"Curtains"},
			want: "Curtains",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got, err = headerFromResponse(response, tc.name)
			if err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			name: "Location",
			add:  []string{},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := headerFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpected got header value %q", got)
			}
		})
	}
}

func TestBasePathHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name, want string
		add        []string
	}{
		{
			name: "Location",
			want: "Here",
			add:  []string{"/path/to/Here", "/path/to/There"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got, err = basePathHeaderFromResponse(response, tc.name)
			if err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

func TestBasePathHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			"Location",
			[]string{},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := basePathHeaderFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpectedly got header value %q", got)
			}
		})
	}
}

func TestIntegerHeader(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		want int64
		add  []string
	}{
		{
			"Total-Count",
			5,
			[]string{"5", "gasoline"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			var got, err = intHeaderFromResponse(response, tc.name)
			if err != nil {
				t.Fatalf("couldn't get header value: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestIntegerHeaderFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name string
		add  []string
	}{
		{
			"Location",
			[]string{},
		},
		{
			"Total-Count",
			[]string{"armchair", "7"},
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var recorder = httptest.NewRecorder()
			recorder.WriteHeader(http.StatusOK)

			var response = recorder.Result()

			for _, value := range tc.add {
				response.Header.Add(tc.name, value)
			}

			if got, err := intHeaderFromResponse(response, tc.name); err == nil {
				t.Fatalf("unexpectedly got header value %d", got)
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
			to:      time.Date(2019, 2, 14, 5, 13, 22, 0, time.UTC),
			want:    "?page=12&per_page=50&to=1550121202",
		},
		{
			name:    "NoTo",
			page:    12,
			perPage: 50,
			from:    time.Date(2019, 1, 14, 5, 13, 22, 0, time.UTC),
			want:    "?page=12&per_page=50&from=1547442802",
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
