package ingest

import (
	"testing"

	"github.com/google/uuid"
	"rampart/internal/auth"
)

// docs/51 step 1.2: only the triager role and higher may decide findings through the VEX inside an upload; a CI token never.
func TestVEXDecider(t *testing.T) {
	src := uuid.New()
	cases := []struct {
		c    *auth.ContextUser
		want string
	}{
		{&auth.ContextUser{Subject: "ci", Role: auth.RoleIngest}, ""},
		{&auth.ContextUser{Subject: "ci", Role: auth.RoleAdmin, ScanSourceID: &src}, ""}, // a source's token
		{&auth.ContextUser{Subject: "v", Role: auth.RoleViewer}, ""},
		{&auth.ContextUser{Subject: "sub-1", Email: "t@acme.example", Role: auth.RoleTriager}, "user:t@acme.example"},
		{&auth.ContextUser{Subject: "admin", Role: auth.RoleAdmin}, "user:admin"},
		{nil, ""},
	}
	for i, c := range cases {
		if got := vexDecider(c.c); got != c.want {
			t.Errorf("case %d: %q, want %q", i, got, c.want)
		}
	}
}
