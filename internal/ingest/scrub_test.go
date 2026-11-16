package ingest

import (
	"io"
	"strings"
	"testing"
	"testing/iotest"
)

func TestScrubNUL(t *testing.T) {
	in := "a\x00b \\u0000 c \\u00 \\u0001 \\\\u0000 end"
	want := "a b \\ufffd c \\u00 \\u0001 \\\\ufffd end"
	for name, r := range map[string]io.Reader{
		"whole":     strings.NewReader(in),
		"one byte":  iotest.OneByteReader(strings.NewReader(in)), // an escape split over every boundary
		"half read": iotest.HalfReader(strings.NewReader(in)),
	} {
		got, err := io.ReadAll(scrubNUL(r))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(got) != want {
			t.Errorf("%s: got %q, want %q", name, got, want)
		}
		if len(got) != len(in) {
			t.Errorf("%s: the length must be kept: %d != %d", name, len(got), len(in))
		}
	}
}
