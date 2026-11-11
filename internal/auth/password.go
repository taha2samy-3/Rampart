package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters (OWASP's second recommended profile: 19 MiB is the floor; 64 MiB with 3
// passes is comfortably above it and still ~100 ms on a small core).
const (
	argonMemoryKiB = 64 * 1024
	argonTime      = 3
	argonThreads   = 2
	argonKeyLen    = 32
	argonSaltLen   = 16

	// MinPasswordLength is enforced when a person chooses a password (the generated one is longer).
	MinPasswordLength = 12
)

// ErrWeakPassword is returned when a chosen password is too short.
var ErrWeakPassword = fmt.Errorf("auth: password must be at least %d characters", MinPasswordLength)

// HashPassword returns a PHC string: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>. The salt is
// random per password, so two people with the same password get different hashes.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemoryKiB, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword checks a password against a PHC string in constant time. Any malformed hash is
// simply "no match": it never panics and never says why.
func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory, time uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false
	}
	// A stored hash cannot make the server burn unbounded memory or time.
	if memory == 0 || memory > 256*1024 || time == 0 || time > 10 || threads == 0 || threads > 16 {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(want) == 0 || len(want) > 128 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is verified when the account does not exist, so a missing user costs the same time as a
// wrong password and the response does not reveal which usernames exist.
var dummyHash = func() string {
	h, err := HashPassword("not-a-real-account-password")
	if err != nil {
		panic(err)
	}
	return h
}()

// GeneratePassword returns a random password of n characters from an alphabet without look-alike
// characters (0/O, 1/l/I), so it can be typed from a terminal or a Secret without mistakes.
func GeneratePassword(n int) (string, error) {
	if n < MinPasswordLength {
		return "", errors.New("auth: generated passwords must be at least 12 characters")
	}
	const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	buf := make([]byte, n*2)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) >= 256-256%len(alphabet) { // reject the biased tail
				continue
			}
			out[i] = alphabet[int(b)%len(alphabet)]
			if i++; i == n {
				break
			}
		}
	}
	return string(out), nil
}
