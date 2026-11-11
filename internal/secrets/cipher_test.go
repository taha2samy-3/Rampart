package secrets_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"rampart/internal/secrets"
)

func newCipher(t *testing.T) *secrets.Cipher {
	t.Helper()
	c, err := secrets.NewCipher(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTripAndNotPlaintext(t *testing.T) {
	c, tenant := newCipher(t), uuid.New()
	ct, err := c.Encrypt(tenant, "scansource:ci:token", []byte("s3cr3t-token"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("s3cr3t-token")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	pt, err := c.Decrypt(tenant, "scansource:ci:token", ct)
	if err != nil || string(pt) != "s3cr3t-token" {
		t.Fatalf("round trip: %q %v", pt, err)
	}
	ct2, _ := c.Encrypt(tenant, "scansource:ci:token", []byte("s3cr3t-token"))
	if bytes.Equal(ct, ct2) {
		t.Fatal("two encryptions of the same value must differ (random nonce)")
	}
}

func TestCiphertextIsBoundToTenantNameAndKey(t *testing.T) {
	c, tenant := newCipher(t), uuid.New()
	ct, _ := c.Encrypt(tenant, "a", []byte("v"))

	if _, err := c.Decrypt(uuid.New(), "a", ct); !errors.Is(err, secrets.ErrDecrypt) {
		t.Error("another tenant must not decrypt it")
	}
	if _, err := c.Decrypt(tenant, "b", ct); !errors.Is(err, secrets.ErrDecrypt) {
		t.Error("another secret name must not decrypt it")
	}
	other, _ := secrets.NewCipher(bytes.Repeat([]byte{9}, 32))
	if _, err := other.Decrypt(tenant, "a", ct); !errors.Is(err, secrets.ErrDecrypt) {
		t.Error("another master key must not decrypt it")
	}
	ct[len(ct)-1] ^= 1
	if _, err := c.Decrypt(tenant, "a", ct); !errors.Is(err, secrets.ErrDecrypt) {
		t.Error("a tampered ciphertext must not decrypt")
	}
	if _, err := c.Decrypt(tenant, "a", []byte{1, 2}); !errors.Is(err, secrets.ErrDecrypt) {
		t.Error("a truncated ciphertext must not decrypt")
	}
}

func TestKeyMustBe32Bytes(t *testing.T) {
	if _, err := secrets.NewCipher([]byte("short")); err == nil {
		t.Fatal("expected an error for a short key")
	}
	p := filepath.Join(t.TempDir(), "key")
	_ = os.WriteFile(p, append(bytes.Repeat([]byte{1}, 32), '\n'), 0o600)
	if _, err := secrets.LoadCipher(p); err != nil {
		t.Fatalf("a key file with a trailing newline must load: %v", err)
	}
}
