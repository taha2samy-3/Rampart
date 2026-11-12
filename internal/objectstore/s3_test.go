package objectstore_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"rampart/internal/objectstore"
)

// These tests run against a real S3 API (SeaweedFS in CI). Set RAMPART_TEST_S3_ENDPOINT,
// RAMPART_TEST_S3_ACCESS_KEY and RAMPART_TEST_S3_SECRET_KEY; they are skipped otherwise.
func newS3(t *testing.T, external string) *objectstore.S3 {
	t.Helper()
	ep := os.Getenv("RAMPART_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("RAMPART_TEST_S3_ENDPOINT is not set; skipping S3 tests")
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	s, err := objectstore.NewS3(context.Background(), objectstore.S3Config{
		Endpoint: ep, ExternalEndpoint: external, Bucket: "rampart-test-" + hex.EncodeToString(suffix),
		AccessKey: os.Getenv("RAMPART_TEST_S3_ACCESS_KEY"), SecretKey: os.Getenv("RAMPART_TEST_S3_SECRET_KEY"), UsePathStyle: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket: %v", err)
	}
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket must be idempotent: %v", err)
	}
	return s
}

func put(t *testing.T, p objectstore.Presigned, body []byte) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, p.URL, bytes.NewReader(body))
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	req.ContentLength = int64(len(body))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

func TestPresignedUploadRoundTripAndSizeIsEnforcedByTheStorage(t *testing.T) {
	s := newS3(t, "")
	ctx := context.Background()
	body := []byte(`{"version":"2.1.0","runs":[]}`)
	key := "tenants/t1/uploads/2026/11/12/u1"

	p, err := s.PresignPut(ctx, key, int64(len(body)), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if p.Headers["Content-Length"] != "29" {
		t.Fatalf("the signed size must be in the headers the client sends: %v", p.Headers)
	}
	if _, ok := p.Headers["Host"]; ok {
		t.Error("Host is set by the HTTP client from the URL, not sent as a header")
	}

	// D9: a body of another size is refused by the storage, and nothing is stored
	if code := put(t, p, append(body, 'x')); code < 400 {
		t.Fatalf("a body of a different size must be refused, got %d", code)
	}
	if _, err := s.Stat(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("nothing may be stored after a refused upload: %v", err)
	}

	if code := put(t, p, body); code != 200 {
		t.Fatalf("the right size must be accepted, got %d", code)
	}
	size, err := s.Stat(ctx, key)
	if err != nil || size != int64(len(body)) {
		t.Fatalf("Stat: %d %v", size, err)
	}
	rc, err := s.Open(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, body) {
		t.Fatalf("round trip: %q", got)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, key); err != nil {
		t.Fatalf("deleting a missing object is not an error: %v", err)
	}
	if _, err := s.Open(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatalf("Open after delete: %v", err)
	}
}

func TestTamperedAndForeignKeyUploadsAreRefused(t *testing.T) {
	s := newS3(t, "")
	p, _ := s.PresignPut(context.Background(), "tenants/t1/uploads/a", 3, time.Minute)
	// the same signature for another key must not work
	other := p
	other.URL = strings.Replace(p.URL, "uploads/a", "uploads/b", 1)
	if code := put(t, other, []byte("abc")); code < 400 {
		t.Fatalf("a signature is bound to its key, got %d", code)
	}
	if _, err := s.Stat(context.Background(), "tenants/t1/uploads/b"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatal("the foreign key must not exist")
	}
}

func TestPresignedURLUsesTheExternalEndpoint(t *testing.T) {
	ep := os.Getenv("RAMPART_TEST_S3_ENDPOINT")
	if ep == "" {
		t.Skip("RAMPART_TEST_S3_ENDPOINT is not set")
	}
	external := strings.Replace(ep, "127.0.0.1", "localhost", 1)
	if external == ep {
		t.Skip("the test endpoint has no 127.0.0.1 host to swap")
	}
	s := newS3(t, external)
	p, err := s.PresignPut(context.Background(), "tenants/t1/uploads/ext", 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p.URL, external) {
		t.Fatalf("presigned URLs must carry the external host so the signature matches: %s", p.URL)
	}
	if code := put(t, p, []byte("abc")); code != 200 {
		t.Fatalf("the externally signed URL must work, got %d", code)
	}
	if n, err := s.Stat(context.Background(), "tenants/t1/uploads/ext"); err != nil || n != 3 {
		t.Fatalf("Stat via the internal endpoint: %d %v", n, err)
	}
}

func TestMemoryStore(t *testing.T) {
	m := objectstore.NewMemory()
	ctx := context.Background()
	if _, err := m.Stat(ctx, "k"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Fatal(err)
	}
	m.Put("k", []byte("hello"))
	if n, _ := m.Stat(ctx, "k"); n != 5 {
		t.Fatal(n)
	}
	rc, _ := m.Open(ctx, "k")
	b, _ := io.ReadAll(rc)
	if string(b) != "hello" {
		t.Fatal(string(b))
	}
}
