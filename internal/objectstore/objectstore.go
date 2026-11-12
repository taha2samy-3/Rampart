// Package objectstore is the S3-compatible object storage the raw reports live in (D9, doc 15 section 6).
// Any S3 API works: SeaweedFS (the bundled default), AWS S3, GCS interoperability, Ceph RGW, Garage.
package objectstore

import (
	"context"
	"errors"
	"io"
	"time"
)

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("objectstore: object not found")

// Presigned is a short-lived upload grant: the client sends PUT to URL with exactly Headers.
type Presigned struct {
	URL     string
	Headers map[string]string
	Expires time.Time
}

// Store is what Rampart needs from object storage.
type Store interface {
	// PresignPut grants one upload of exactly size bytes to key. The size is signed into the request
	// (Content-Length), so a body of any other size is rejected by the storage itself (D9).
	PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (Presigned, error)
	// Stat returns the size of an object, or ErrNotFound.
	Stat(ctx context.Context, key string) (int64, error)
	// Open streams an object. The caller closes the reader.
	Open(ctx context.Context, key string) (io.ReadCloser, error)
	// Delete removes an object; deleting a missing object is not an error.
	Delete(ctx context.Context, key string) error
	// EnsureBucket creates the bucket if it does not exist.
	EnsureBucket(ctx context.Context) error
}
