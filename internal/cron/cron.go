// Package cron reads the five-field cron expressions a resource may carry (an SBOMAnalyzer's schedule) and says when they fire.
//
// The fields are minute, hour, day of month, month and day of week, in UTC. Each field is "*", a number, a range "a-b", a list
// "a,b,c" of those, or any of them with a step "/n". Day of week is 0 to 6 with 0 Sunday (7 is Sunday too); month names and day names
// are not read. As in Vixie cron, when both the day of month and the day of week are restricted, a day matches if either does.
// "@hourly", "@daily", "@weekly", "@monthly" and "@yearly" are accepted.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed expression.
type Schedule struct {
	minute, hour, dom, month, dow uint64 // a bit per allowed value
	domStar, dowStar              bool
}

var macros = map[string]string{
	"@hourly":  "0 * * * *",
	"@daily":   "0 0 * * *",
	"@weekly":  "0 0 * * 0",
	"@monthly": "0 0 1 * *",
	"@yearly":  "0 0 1 1 *",
}

type bounds struct {
	name     string
	min, max int
}

var fieldBounds = [5]bounds{{"minute", 0, 59}, {"hour", 0, 23}, {"day of month", 1, 31}, {"month", 1, 12}, {"day of week", 0, 7}}

// Parse reads an expression.
func Parse(expr string) (Schedule, error) {
	expr = strings.TrimSpace(expr)
	if m, ok := macros[expr]; ok {
		expr = m
	}
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return Schedule{}, fmt.Errorf("%q has %d fields; a schedule has five: minute hour day-of-month month day-of-week", expr, len(fields))
	}
	var bits [5]uint64
	var star [5]bool
	for i, f := range fields {
		b, s, err := parseField(f, fieldBounds[i])
		if err != nil {
			return Schedule{}, err
		}
		bits[i], star[i] = b, s
	}
	if bits[4]&(1<<7) != 0 { // 7 is Sunday
		bits[4] |= 1
	}
	bits[4] &^= 1 << 7
	return Schedule{minute: bits[0], hour: bits[1], dom: bits[2], month: bits[3], dow: bits[4], domStar: star[2], dowStar: star[4]}, nil
}

func parseField(f string, b bounds) (bits uint64, star bool, err error) {
	star = f == "*"
	for _, part := range strings.Split(f, ",") {
		step := 1
		if base, st, ok := strings.Cut(part, "/"); ok {
			n, perr := strconv.Atoi(st)
			if perr != nil || n < 1 {
				return 0, false, fmt.Errorf("%s: step %q is not a positive number", b.name, st)
			}
			part, step = base, n
			if part == "*" {
				star = false // "*/n" restricts the field
			}
		}
		lo, hi := b.min, b.max
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			a, z, _ := strings.Cut(part, "-")
			var e1, e2 error
			lo, e1 = strconv.Atoi(a)
			hi, e2 = strconv.Atoi(z)
			if e1 != nil || e2 != nil {
				return 0, false, fmt.Errorf("%s: %q is not a range of numbers", b.name, part)
			}
		default:
			n, perr := strconv.Atoi(part)
			if perr != nil {
				return 0, false, fmt.Errorf("%s: %q is not a number", b.name, part)
			}
			lo, hi = n, n
			if step != 1 { // "5/10" reads as "5-max/10"
				hi = b.max
			}
		}
		if lo < b.min || hi > b.max || lo > hi {
			return 0, false, fmt.Errorf("%s: %q is outside %d to %d", b.name, part, b.min, b.max)
		}
		for v := lo; v <= hi; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, star, nil
}

func (s Schedule) dayMatches(t time.Time) bool {
	domOK := s.dom&(1<<uint(t.Day())) != 0
	dowOK := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dowOK
	case s.dowStar:
		return domOK
	default:
		return domOK || dowOK
	}
}

// Next is the first time after t at which the schedule fires, to the minute, in UTC. It is the zero time when none comes within five years
// (a day of month that no month has, such as 31 February).
func (s Schedule) Next(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, time.UTC)
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, time.UTC)
			continue
		}
		if s.minute&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// Prev is the last time at or before t at which the schedule fired, or the zero time when it has not fired within the last five years.
// It is how a sweep asks "has the schedule fired since this was last done?": it has when Prev(now) is after that time.
func (s Schedule) Prev(t time.Time) time.Time {
	t = t.UTC().Truncate(time.Minute)
	var last time.Time
	// Look back a day, then a month, then five years, so that a schedule that fires every minute is not walked for years.
	for _, back := range []time.Duration{24 * time.Hour, 31 * 24 * time.Hour, 5 * 366 * 24 * time.Hour} {
		cur := s.Next(t.Add(-back - time.Minute))
		for !cur.IsZero() && !cur.After(t) {
			last = cur
			cur = s.Next(cur)
		}
		if !last.IsZero() {
			return last
		}
	}
	return last
}
