package targets

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/config"
	"rampart/internal/domain"
	"rampart/internal/ingest"
)

func bootstrapFixture(t *testing.T) (*Runner, *ingest.MemoryStore, *bytes.Buffer, string) {
	t.Helper()
	st := ingest.NewMemoryStore()
	_ = st.CreateTenant(context.Background(), &domain.Tenant{ID: domain.NewID(), Slug: "default", DisplayName: "Default"})
	cfg := config.DefaultConfig()
	path := filepath.Join(t.TempDir(), "admin-password")
	cfg.Auth.BootstrapAdmin.PasswordFile = path
	logs := &bytes.Buffer{}
	return NewRunner(cfg, slog.New(slog.NewTextHandler(logs, nil))), st, logs, path
}

func TestBootstrapGeneratesAPasswordFileOnceAndNeverLogsIt(t *testing.T) {
	r, st, logs, path := bootstrapFixture(t)
	ctx := context.Background()
	if err := r.bootstrapLocalAdmin(ctx, st); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the password file must exist with mode 0600: %v %v", err, info)
	}
	b, _ := os.ReadFile(path)
	pw := strings.TrimSpace(string(b))
	if len(pw) < 24 {
		t.Fatalf("generated password too short: %d", len(pw))
	}
	tenant, _ := st.GetTenantBySlug(ctx, "default")
	admin, _ := st.GetLocalAdmin(ctx, tenant.ID, "admin")
	if admin == nil || !auth.VerifyPassword(pw, admin.PasswordHash) || strings.Contains(admin.PasswordHash, pw) {
		t.Fatalf("the stored hash must verify the file's password and never contain it: %+v", admin)
	}
	if role, member, _ := st.GetMemberRole(ctx, tenant.ID, admin.UserID); !member || role != auth.RoleAdmin {
		t.Errorf("the local administrator must be an admin of the tenant: %q %v", role, member)
	}
	if strings.Contains(logs.String(), pw) {
		t.Fatalf("the password leaked into the log:\n%s", logs.String())
	}

	// a second boot changes nothing: the file stays, the account stays (a later password change survives)
	if err := r.bootstrapLocalAdmin(ctx, st); err != nil {
		t.Fatal(err)
	}
	b2, _ := os.ReadFile(path)
	again, _ := st.GetLocalAdmin(ctx, tenant.ID, "admin")
	if string(b2) != string(b) || again.ID != admin.ID || again.PasswordHash != admin.PasswordHash {
		t.Error("restarting must not regenerate or overwrite anything")
	}
}

func TestBootstrapUsesAGivenPasswordAndRefusesAWeakOne(t *testing.T) {
	r, st, _, path := bootstrapFixture(t)
	ctx := context.Background()
	if err := os.WriteFile(path, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapLocalAdmin(ctx, st); err == nil {
		t.Fatal("a password shorter than 12 characters must be refused")
	}
	if err := os.WriteFile(path, []byte("a-long-enough-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := r.bootstrapLocalAdmin(ctx, st); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.GetTenantBySlug(ctx, "default")
	admin, _ := st.GetLocalAdmin(ctx, tenant.ID, "admin")
	if admin == nil || !auth.VerifyPassword("a-long-enough-secret", admin.PasswordHash) {
		t.Fatal("the given password must be the one that works (trailing newline ignored)")
	}
}

func TestBootstrapIsOffWithoutAPasswordFileAndFailsOnAMissingTenant(t *testing.T) {
	r, st, _, _ := bootstrapFixture(t)
	r.cfg.Auth.BootstrapAdmin.PasswordFile = ""
	if err := r.bootstrapLocalAdmin(context.Background(), st); err != nil {
		t.Fatal(err)
	}
	tenant, _ := st.GetTenantBySlug(context.Background(), "default")
	if a, _ := st.GetLocalAdmin(context.Background(), tenant.ID, "admin"); a != nil {
		t.Fatal("no password file means no local administrator")
	}
	r.cfg.Auth.BootstrapAdmin.PasswordFile = filepath.Join(t.TempDir(), "p")
	r.cfg.Auth.BootstrapAdmin.Tenant = "nope"
	if err := r.bootstrapLocalAdmin(context.Background(), st); err == nil {
		t.Fatal("an unknown tenant must be an error, not a silent skip")
	}
}
