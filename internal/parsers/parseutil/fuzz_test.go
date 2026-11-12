package parseutil_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"rampart/internal/parsers/parseutil"
)

// Fuzz the shared walk: any input ends in a value or an error, never a panic or a hang.
func FuzzWalk(f *testing.F) {
	f.Add([]byte(`{"a":[1,{"b":null}],"c":"d"}`))
	f.Add([]byte(`[[[[`))
	f.Add([]byte(``))
	f.Fuzz(func(t *testing.T, data []byte) {
		dec := json.NewDecoder(bytes.NewReader(data))
		_ = parseutil.Object(dec, func(key string) error {
			if key == "x" {
				return parseutil.Array(dec, func() error { return parseutil.Skip(dec) })
			}
			return parseutil.Skip(dec)
		})
		_ = parseutil.CWEs(string(data))
	})
}
