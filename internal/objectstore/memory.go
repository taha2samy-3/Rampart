package objectstore

import (
	"bytes"
	"context"
	"io"
	"sync"
	"time"
)

// Memory is an in-process Store for tests. It cannot presign: nothing outside the process can PUT to
// it, so tests put objects with Put instead of through a URL.
type Memory struct {
	mu      sync.Mutex
	objects map[string][]byte
	// Base is the URL prefix PresignPut returns (tests only inspect it).
	Base string
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory { return &Memory{objects: map[string][]byte{}, Base: "memory://objects/"} }

// Put stores an object directly.
func (m *Memory) Put(key string, data []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.objects[key] = append([]byte(nil), data...)
}

// Write implements Store.
func (m *Memory) Write(_ context.Context, key string, data []byte, _ string) error {
	m.Put(key, data)
	return nil
}

// PresignPut implements Store.
func (m *Memory) PresignPut(_ context.Context, key string, size int64, ttl time.Duration) (Presigned, error) {
	return Presigned{URL: m.Base + key, Headers: map[string]string{"Content-Length": itoa(size)}, Expires: time.Now().Add(ttl)}, nil
}

// Stat implements Store.
func (m *Memory) Stat(_ context.Context, key string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return 0, ErrNotFound
	}
	return int64(len(b)), nil
}

// Open implements Store.
func (m *Memory) Open(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.objects[key]
	if !ok {
		return nil, ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

// Delete implements Store.
func (m *Memory) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	return nil
}

// EnsureBucket implements Store.
func (m *Memory) EnsureBucket(context.Context) error { return nil }

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
