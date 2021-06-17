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
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// parseTimeWindow takes two strings representing from- and to-times in
// 2006-01-02T15:04:05MST layout, and returns two time.Time objects
// representing those two times. If the strings are empty, then defaults
// representing a 30-day time period to the current moment are returned.
func parseTimeWindow(from, to, since string) (time.Time, time.Time, error) {
	var timeFrom, timeTo time.Time
	var err error

	// Set to-time to now if -to flag was not specified (since now is
	// the default) or if -since flag was specified (as the -since flag
	// always denotes a period of time up to the present time). Parsing
	// of command-line arguments will prevent both -to and -since from
	// being specified.

	if to != "" && since == "" {
		if timeTo, err = time.Parse(defaultTimeLayout, to); err != nil {
			return timeTo, timeFrom, fmt.Errorf("couldn't parse 'to' time string: %v", err)
		}
	} else {
		timeTo = time.Now()
	}

	if from != "" {
		// -from flag was specified, so calculate it.

		if timeFrom, err = time.Parse(defaultTimeLayout, from); err != nil {
			return timeTo, timeFrom, fmt.Errorf("couldn't parse 'from' time string: %v", err)
		}
	} else if since != "" {

		// -since flag was specified, so set from-time to the to-time less
		// the since duration.

		var duration time.Duration
		var err error
		if duration, err = parseDuration(since); err != nil {
			return timeTo, timeFrom, err
		}

		timeFrom = timeTo.Add(duration * -1)
	} else {
		// Neither was specified, so set from-time to a default period prior
		// to the to-time.

		timeFrom = timeTo.Add(time.Hour * 24 * -defaultTimeWindowDays)
	}

	return timeFrom, timeTo, nil
}

func parseDuration(d string) (time.Duration, error) {
	// Break string into duration value and units.

	var n string
	var unit string
	for i := 0; i < len(d); i++ {
		if !unicode.IsDigit(rune(d[i])) {
			n = d[:i]
			unit = d[i:]
			break
		}
	}

	// Parse duration value.

	var extent int64
	var err error

	if extent, err = strconv.ParseInt(n, 0, 64); err != nil {
		return 0, fmt.Errorf("invalid duration quantity: %s", n)
	}

	// Parse units.

	switch strings.ToUpper(unit) {
	case "S", "SEC", "SECS", "SECOND", "SECONDS":
		return time.Second * time.Duration(extent), nil
	case "M", "MIN", "MINS", "MINUTE", "MINUTES":
		return time.Minute * time.Duration(extent), nil
	case "H", "HR", "HRS", "HOUR", "HOURS":
		return time.Hour * time.Duration(extent), nil
	case "D", "DAY", "DAYS":
		return time.Hour * time.Duration(extent) * 24, nil
	case "W", "WK", "WKS", "WEEK", "WEEKS":
		return time.Hour * time.Duration(extent) * 24 * 7, nil
	}

	return 0, fmt.Errorf("invalid duration unit: %s", unit)
}
