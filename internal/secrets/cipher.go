// Package secrets encrypts secret material before it is written to PostgreSQL (D1).
//
// D1: the operator copies referenced Kubernetes Secrets into secret_material,
// envelope-encrypted with AES-256-GCM and one data key per tenant, wrapped by a master key.
// The per-tenant data key is derived from the master key with HKDF-SHA256 and the tenant id,
// so no key material is stored next to the ciphertext and rotating the master key rotates all
// tenants at once. The ciphertext is bound to its tenant and its secret name (AAD), so a row
// copied to another tenant or another name does not decrypt.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
)

const (
	formatV1  = 1
	keyLength = 32
)

// ErrDecrypt is returned for any failure to open a ciphertext; it never says why.
var ErrDecrypt = errors.New("secrets: cannot decrypt secret material")

// Cipher encrypts and decrypts secret material for tenants.
type Cipher struct {
	master []byte
}

// NewCipher creates a Cipher from a 32-byte master key.
func NewCipher(master []byte) (*Cipher, error) {
	if len(master) != keyLength {
		return nil, fmt.Errorf("secrets: master key must be %d bytes, got %d", keyLength, len(master))
	}
	return &Cipher{master: append([]byte(nil), master...)}, nil
}

// LoadCipher reads the master key from a file (auth.session.keyFile, D6). Trailing newlines
// are ignored; the key itself must be exactly 32 bytes.
func LoadCipher(path string) (*Cipher, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("secrets: reading master key: %w", err)
	}
	return NewCipher([]byte(strings.TrimRight(string(raw), "\r\n")))
}

func (c *Cipher) aead(tenantID uuid.UUID) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, c.master, nil, "rampart/secret-material/v1/"+tenantID.String(), keyLength)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aad(tenantID uuid.UUID, name string) []byte {
	return []byte(tenantID.String() + "\x1f" + name)
}

// Encrypt returns version || nonce || ciphertext.
func (c *Cipher) Encrypt(tenantID uuid.UUID, name string, plaintext []byte) ([]byte, error) {
	g, err := c.aead(tenantID)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{formatV1}, nonce...)
	return g.Seal(out, nonce, plaintext, aad(tenantID, name)), nil
}

// Decrypt reverses Encrypt. The tenant and name must match those used to encrypt.
func (c *Cipher) Decrypt(tenantID uuid.UUID, name string, data []byte) ([]byte, error) {
	g, err := c.aead(tenantID)
	if err != nil || len(data) < 1+g.NonceSize()+g.Overhead() || data[0] != formatV1 {
		return nil, ErrDecrypt
	}
	nonce, ct := data[1:1+g.NonceSize()], data[1+g.NonceSize():]
	pt, err := g.Open(nil, nonce, ct, aad(tenantID, name))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
