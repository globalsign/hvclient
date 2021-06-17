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

package main

import (
	"testing"
	"time"
)

func TestParseTimeWindow(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name             string
		from, to, since  string
		wantfrom, wantto time.Time
	}{
		{
			name:     "FromAndTo",
			from:     "2010-01-01T06:00:00UTC",
			to:       "2010-01-11T06:00:00UTC",
			wantfrom: time.Date(2010, 1, 1, 6, 0, 0, 0, time.UTC),
			wantto:   time.Date(2010, 1, 11, 6, 0, 0, 0, time.UTC),
		},
		{
			name:     "FromOnly",
			from:     "2010-01-01T06:00:00UTC",
			wantfrom: time.Date(2010, 1, 1, 6, 0, 0, 0, time.UTC),
			wantto:   time.Now(),
		},
		{
			name:     "ToOnly",
			to:       "2010-01-01T06:00:00UTC",
			wantfrom: time.Date(2009, 12, 2, 6, 0, 0, 0, time.UTC),
			wantto:   time.Date(2010, 1, 1, 6, 0, 0, 0, time.UTC),
		},
		{
			name:     "Neither",
			wantfrom: time.Now().Add(time.Hour * 24 * -30),
			wantto:   time.Now(),
		},
		{
			name:     "Since",
			since:    "10d",
			wantfrom: time.Now().Add(time.Hour * 24 * -10),
			wantto:   time.Now(),
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var from, to, err = parseTimeWindow(tc.from, tc.to, tc.since)
			if err != nil {
				t.Fatalf("couldn't parse time window: %v", err)
			}

			if tc.from != "" {
				if !from.Equal(tc.wantfrom) {
					t.Errorf("got from %v, want %v", from, tc.wantfrom)
				}
			} else {
				if tc.wantfrom.Sub(from).Seconds() >= 1.0 {
					t.Errorf("got from %v, want %v", from, tc.wantfrom)
				}
			}

			if tc.to != "" {
				if !to.Equal(tc.wantto) {
					t.Errorf("got to %v, want %v", to, tc.wantto)
				}
			} else {
				if tc.wantto.Sub(to).Seconds() >= 1.0 {
					t.Errorf("got to %v, want %v", to, tc.wantto)
				}
			}
		})
	}
}

func TestParseTimeWindowFailure(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		name            string
		from, to, since string
	}{
		{
			name: "BadFrom",
			from: "not a time value",
			to:   "2010-01-11T06:00:00UTC",
		},
		{
			name: "BadTo",
			from: "2010-01-11T06:00:00UTC",
			to:   "not a time value",
		},
		{
			name:  "BadSince",
			since: "not a duration",
		},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, _, err := parseTimeWindow(tc.from, tc.to, tc.since); err == nil {
				t.Errorf("unexpectedly parsed time window: %v", err)
			}
		})
	}
}

func TestTimeParse(t *testing.T) {
	t.Parallel()

	var testcases = []struct {
		str  string
		want time.Duration
	}{
		{"1s", time.Second * 1},
		{"2S", time.Second * 2},
		{"3sec", time.Second * 3},
		{"4SEC", time.Second * 4},
		{"5secs", time.Second * 5},
		{"6SECS", time.Second * 6},
		{"7second", time.Second * 7},
		{"8SECOND", time.Second * 8},
		{"9seconds", time.Second * 9},
		{"10SECONDS", time.Second * 10},
		{"1m", time.Minute * 1},
		{"2M", time.Minute * 2},
		{"3min", time.Minute * 3},
		{"4MIN", time.Minute * 4},
		{"5mins", time.Minute * 5},
		{"6MINS", time.Minute * 6},
		{"7minute", time.Minute * 7},
		{"8MINUTE", time.Minute * 8},
		{"9minutes", time.Minute * 9},
		{"10MINUTES", time.Minute * 10},
		{"1h", time.Hour * 1},
		{"2H", time.Hour * 2},
		{"3hr", time.Hour * 3},
		{"4HR", time.Hour * 4},
		{"5hrs", time.Hour * 5},
		{"6HRS", time.Hour * 6},
		{"7hour", time.Hour * 7},
		{"8HOUR", time.Hour * 8},
		{"9hours", time.Hour * 9},
		{"10HOURS", time.Hour * 10},
		{"1d", time.Hour * 24 * 1},
		{"2D", time.Hour * 24 * 2},
		{"3day", time.Hour * 24 * 3},
		{"4DAY", time.Hour * 24 * 4},
		{"5days", time.Hour * 24 * 5},
		{"6DAYS", time.Hour * 24 * 6},
		{"1w", time.Hour * 24 * 7 * 1},
		{"2W", time.Hour * 24 * 7 * 2},
		{"3wk", time.Hour * 24 * 7 * 3},
		{"4WK", time.Hour * 24 * 7 * 4},
		{"5wks", time.Hour * 24 * 7 * 5},
		{"6WKS", time.Hour * 24 * 7 * 6},
		{"7week", time.Hour * 24 * 7 * 7},
		{"8WEEK", time.Hour * 24 * 7 * 8},
		{"9weeks", time.Hour * 24 * 7 * 9},
		{"10WEEKS", time.Hour * 24 * 7 * 10},
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc.str, func(t *testing.T) {
			t.Parallel()

			var got, err = parseDuration(tc.str)
			if err != nil {
				t.Fatalf("couldn't parse duration: %v", err)
			}

			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestTimeParseFailure(t *testing.T) {
	t.Parallel()

	var testcases = []string{
		"5",
		"s",
		"s5",
		"5x",
		"5 s",
		"word",
	}

	for _, tc := range testcases {
		var tc = tc

		t.Run(tc, func(t *testing.T) {
			t.Parallel()

			if _, err := parseDuration(tc); err == nil {
				t.Errorf("unexpectedly parsed duration")
			}
		})
	}
}
