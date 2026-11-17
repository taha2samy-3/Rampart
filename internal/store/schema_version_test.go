package store

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// docs/21: a migration raises CurrentExpectedSchemaVersion and the chart's minSchemaVersion in the same commit. Both
// stayed at 42 through migrations 43 and 44, so the init container of a new pod would have let it start against a
// schema it could not read, whenever the migrate job was slow.
func TestSchemaVersionsFollowTheLatestMigration(t *testing.T) {
	files, err := filepath.Glob("migrations/*.sql")
	if err != nil || len(files) == 0 {
		t.Fatalf("migrations: %v %d", err, len(files))
	}
	var latest int64
	for _, f := range files {
		n, err := strconv.ParseInt(filepath.Base(f)[:5], 10, 64)
		if err != nil {
			t.Fatalf("%s: a migration is named NNNNN_name.sql", f)
		}
		latest = max(latest, n)
	}
	if CurrentExpectedSchemaVersion != latest {
		t.Errorf("CurrentExpectedSchemaVersion is %d, the latest migration is %d", CurrentExpectedSchemaVersion, latest)
	}
	values, err := os.ReadFile("../../deploy/helm/rampart/values.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*minSchemaVersion:\s*(\d+)`).FindSubmatch(values)
	if m == nil {
		t.Fatal("deploy/helm/rampart/values.yaml has no minSchemaVersion")
	}
	if got, _ := strconv.ParseInt(string(m[1]), 10, 64); got != latest {
		t.Errorf("the chart's minSchemaVersion is %d, the latest migration is %d", got, latest)
	}
}
