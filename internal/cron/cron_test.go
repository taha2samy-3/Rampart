package cron

import (
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04", s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestNext(t *testing.T) {
	cases := []struct{ expr, from, want string }{
		{"0 3 * * *", "2026-11-19 02:59", "2026-11-19 03:00"},
		{"0 3 * * *", "2026-11-19 03:00", "2026-11-20 03:00"}, // strictly after
		{"*/15 * * * *", "2026-11-19 10:07", "2026-11-19 10:15"},
		{"*/15 * * * *", "2026-11-19 10:45", "2026-11-19 11:00"},
		{"30 2 1 * *", "2026-11-19 00:00", "2026-12-01 02:30"},
		{"0 0 * * 0", "2026-11-19 00:00", "2026-11-22 00:00"},        // 2026-11-19 is a Thursday: next Sunday
		{"0 0 * * 7", "2026-11-19 00:00", "2026-11-22 00:00"},        // 7 is Sunday as well
		{"0 9-17/4 * * 1-5", "2026-11-20 17:00", "2026-11-23 09:00"}, // a Friday evening: Monday 09:00
		{"0 0 29 2 *", "2026-11-19 00:00", "2028-02-29 00:00"},
		{"5/20 * * * *", "2026-11-19 10:00", "2026-11-19 10:05"},
		{"@daily", "2026-11-19 10:00", "2026-11-20 00:00"},
		{"@hourly", "2026-11-19 10:00", "2026-11-19 11:00"},
		{"0 0 1 1 *", "2026-11-19 10:00", "2027-01-01 00:00"}, // @yearly
	}
	for _, c := range cases {
		s, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("%q: %v", c.expr, err)
		}
		if got := s.Next(at(c.from)); !got.Equal(at(c.want)) {
			t.Errorf("%q after %s: got %s, want %s", c.expr, c.from, got.Format("2006-01-02 15:04"), c.want)
		}
	}
}

func TestDayOfMonthOrDayOfWeek(t *testing.T) {
	// Both restricted: either matches, as in Vixie cron. The 13th, or any Friday.
	s, err := Parse("0 0 13 * 5")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Next(at("2026-11-09 00:00")); !got.Equal(at("2026-11-13 00:00")) { // Friday the 13th is both
		t.Errorf("got %s", got)
	}
	if got := s.Next(at("2026-11-13 00:00")); !got.Equal(at("2026-11-20 00:00")) { // the next Friday, not the next 13th
		t.Errorf("got %s", got)
	}
}

func TestNextNeverFires(t *testing.T) {
	s, err := Parse("0 0 31 2 *")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Next(at("2026-11-19 00:00")); !got.IsZero() {
		t.Errorf("31 February fired at %s", got)
	}
}

func TestPrev(t *testing.T) {
	cases := []struct{ expr, now, want string }{
		{"0 3 * * *", "2026-11-19 10:00", "2026-11-19 03:00"},
		{"0 3 * * *", "2026-11-19 03:00", "2026-11-19 03:00"}, // at, not before
		{"0 3 * * *", "2026-11-19 02:59", "2026-11-18 03:00"},
		{"0 0 1 * *", "2026-11-19 10:00", "2026-11-01 00:00"}, // found in the month look-back
	}
	for _, c := range cases {
		s, err := Parse(c.expr)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.Prev(at(c.now)); !got.Equal(at(c.want)) {
			t.Errorf("%q at %s: got %s, want %s", c.expr, c.now, got.Format("2006-01-02 15:04"), c.want)
		}
	}
	// Found only in the five-year look-back: the last 29 February before November 2026 is in 2024.
	s, _ := Parse("0 0 29 2 *")
	if got := s.Prev(at("2026-11-19 10:00")); !got.Equal(at("2024-02-29 00:00")) {
		t.Errorf("got %s", got)
	}
	// Every minute does not walk for years.
	every, _ := Parse("* * * * *")
	start := time.Now()
	if got := every.Prev(at("2026-11-19 10:00")); !got.Equal(at("2026-11-19 10:00")) {
		t.Errorf("got %s", got)
	}
	if time.Since(start) > time.Second {
		t.Errorf("every minute took %s", time.Since(start))
	}
}

func TestParseRefusesWhatItCannotRead(t *testing.T) {
	for expr, why := range map[string]string{
		"":            "no fields",
		"* * * *":     "four fields",
		"* * * * * *": "six fields",
		"60 * * * *":  "minute out of range",
		"* 24 * * *":  "hour out of range",
		"* * 0 * *":   "day of month starts at 1",
		"* * * 13 *":  "month out of range",
		"* * * * 8":   "day of week out of range",
		"*/0 * * * *": "step of zero",
		"a * * * *":   "not a number",
		"5-1 * * * *": "reversed range",
		"* * * jan *": "month names are not read",
		"* * * * mon": "day names are not read",
		"@sometimes":  "unknown macro",
		"1-x * * * *": "range with a non-number",
		"*/x * * * *": "step that is not a number",
	} {
		if _, err := Parse(expr); err == nil {
			t.Errorf("%q (%s) was accepted", expr, why)
		}
	}
}
