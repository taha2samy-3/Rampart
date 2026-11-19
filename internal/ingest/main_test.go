package ingest

import (
	"os"
	"testing"

	"rampart/internal/parsertest"
)

// No parser is compiled in: the tests install the default manifests the way a deployment does, from a directory.
func TestMain(m *testing.M) {
	parsertest.SetEnv()
	os.Exit(m.Run())
}
