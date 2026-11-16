package sync_test

import (
	"testing"

	dtclient "rampart/internal/upstream/dependencytrack/client"
	dtsync "rampart/internal/upstream/dependencytrack/sync"
)

func proj(uuid, name string, bom int64, latest *bool) dtclient.Project {
	return dtclient.Project{UUID: uuid, Name: name, LastBomImport: bom, IsLatest: latest}
}

// With versions: latest, a DT whose projects carry no latest flag (the usual case: the flag is set only by an
// upload with isLatest=true) skipped the whole portfolio, even a project with a single version. The version with
// the newest BOM is read when DT names none; when DT names one, it wins.
func TestImplicitLatest(t *testing.T) {
	no, yes := false, true
	cases := []struct {
		name string
		p    dtclient.Project
		all  []dtclient.Project
		want bool
	}{
		{"a single version with no flag", proj("a", "svc", 10, &no), []dtclient.Project{proj("a", "svc", 10, &no)}, true},
		{"the newest BOM of several", proj("b", "svc", 20, &no), []dtclient.Project{proj("a", "svc", 10, &no), proj("b", "svc", 20, &no)}, true},
		{"an older version", proj("a", "svc", 10, &no), []dtclient.Project{proj("a", "svc", 10, &no), proj("b", "svc", 20, &no)}, false},
		{"DT flags another version", proj("b", "svc", 20, &no), []dtclient.Project{proj("a", "svc", 10, &yes), proj("b", "svc", 20, &no)}, false},
		{"a tie is broken by uuid, the same way each time", proj("a", "svc", 10, &no), []dtclient.Project{proj("b", "svc", 10, &no), proj("a", "svc", 10, &no)}, true},
		{"another name is not a version of it", proj("a", "svc", 10, &no), []dtclient.Project{proj("a", "svc", 10, &no), proj("z", "other", 99, &yes)}, true},
		{"an empty answer", proj("a", "svc", 10, &no), nil, false},
	}
	for _, c := range cases {
		if got := dtsync.ImplicitLatest(c.p, c.all); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
