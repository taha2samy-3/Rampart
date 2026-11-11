package auth_test

import (
	"strings"
	"testing"

	"rampart/internal/auth"
)

func TestPasswordHashFormatAndVerification(t *testing.T) {
	h, err := auth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("not a PHC argon2id string: %s", h)
	}
	if !auth.VerifyPassword("correct horse battery staple", h) {
		t.Error("the right password must verify")
	}
	for _, wrong := range []string{"", "correct horse battery stapl", "Correct horse battery staple", h} {
		if auth.VerifyPassword(wrong, h) {
			t.Errorf("%q must not verify", wrong)
		}
	}
	h2, _ := auth.HashPassword("correct horse battery staple")
	if h == h2 {
		t.Error("the salt must be random: the same password must hash differently")
	}
}

// A stored value must never make the server crash or burn memory: it is just "no match".
func TestVerifyPasswordToleratesGarbageAndHostileHashes(t *testing.T) {
	for name, h := range map[string]string{
		"empty":         "",
		"plain text":    "hunter2",
		"wrong algo":    "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaA",
		"truncated":     "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ",
		"bad base64":    "$argon2id$v=19$m=65536,t=3,p=2$!!!$!!!",
		"old version":   "$argon2id$v=16$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"huge memory":   "$argon2id$v=19$m=4194304,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"huge time":     "$argon2id$v=19$m=65536,t=4000000,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"zero threads":  "$argon2id$v=19$m=65536,t=3,p=0$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"empty hash":    "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$",
		"extra section": "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaA$extra",
	} {
		if auth.VerifyPassword("anything", h) {
			t.Errorf("%s: must not verify", name)
		}
	}
}

func TestGeneratedPasswords(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		p, err := auth.GeneratePassword(24)
		if err != nil || len(p) != 24 {
			t.Fatalf("%q %v", p, err)
		}
		if strings.ContainsAny(p, "0O1lI") {
			t.Fatalf("look-alike characters in %q", p)
		}
		if seen[p] {
			t.Fatal("duplicate generated password")
		}
		seen[p] = true
	}
	if _, err := auth.GeneratePassword(8); err == nil {
		t.Error("a generated password shorter than the minimum must be refused")
	}
}

func TestRateLimiter(t *testing.T) {
	l := auth.NewRateLimiter(3, 1e9) // 3 per second
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d must be allowed", i+1)
		}
	}
	if ok, wait := l.Allow("1.2.3.4"); ok || wait <= 0 {
		t.Errorf("the fourth attempt must be refused with a wait, got %v %v", ok, wait)
	}
	if ok, _ := l.Allow("5.6.7.8"); !ok {
		t.Error("another address has its own budget")
	}
}
