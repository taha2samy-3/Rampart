package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awscfg "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3Config configures the S3 client.
type S3Config struct {
	// Endpoint is how the server reaches the storage (for example http://objectstore:8333).
	Endpoint string
	// ExternalEndpoint is the address clients use for presigned URLs. It can differ from Endpoint
	// (inside and outside a cluster); the signature covers the host, so it is signed with this one.
	// Empty means the same as Endpoint.
	ExternalEndpoint string
	Region           string
	Bucket           string
	AccessKey        string
	SecretKey        string
	UsePathStyle     bool
}

// S3 implements Store over the S3 API.
type S3 struct {
	bucket  string
	client  *s3.Client // server-side calls
	presign *s3.PresignClient
}

// NewS3 builds the clients. It does not contact the storage.
func NewS3(ctx context.Context, c S3Config) (*S3, error) {
	if c.Endpoint == "" || c.Bucket == "" {
		return nil, errors.New("objectstore: endpoint and bucket are required")
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if c.ExternalEndpoint == "" {
		c.ExternalEndpoint = c.Endpoint
	}
	cfg, err := awscfg.LoadDefaultConfig(ctx,
		awscfg.WithRegion(c.Region),
		awscfg.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(c.AccessKey, c.SecretKey, "")),
	)
	if err != nil {
		return nil, err
	}
	mk := func(endpoint string) *s3.Client {
		return s3.NewFromConfig(cfg, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
			o.UsePathStyle = c.UsePathStyle
			// S3-compatible stores do not all understand the newer default checksums; send them only
			// when an operation requires one.
			o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
			o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		})
	}
	return &S3{bucket: c.Bucket, client: mk(c.Endpoint), presign: s3.NewPresignClient(mk(c.ExternalEndpoint))}, nil
}

// PresignPut implements Store.
func (s *S3) PresignPut(ctx context.Context, key string, size int64, ttl time.Duration) (Presigned, error) {
	req, err := s.presign.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), ContentLength: aws.Int64(size),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return Presigned{}, err
	}
	headers := map[string]string{}
	for k, v := range req.SignedHeader {
		if strings.EqualFold(k, "host") { // the HTTP client sets Host from the URL
			continue
		}
		headers[http.CanonicalHeaderKey(k)] = strings.Join(v, ",")
	}
	return Presigned{URL: req.URL, Headers: headers, Expires: time.Now().Add(ttl)}, nil
}

// Write implements Store.
func (s *S3) Write(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(key), Body: bytes.NewReader(data),
		ContentLength: aws.Int64(int64(len(data))), ContentType: aws.String(contentType),
	})
	return err
}

// Stat implements Store.
func (s *S3) Stat(ctx context.Context, key string) (int64, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		if isNotFound(err) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return aws.ToInt64(out.ContentLength), nil
}

// Open implements Store.
func (s *S3) Open(ctx context.Context, key string) (io.ReadCloser, error) {
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil {
		if isNotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out.Body, nil
}

// Delete implements Store.
func (s *S3) Delete(ctx context.Context, key string) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(key)})
	if err != nil && !isNotFound(err) {
		return err
	}
	return nil
}

// EnsureBucket implements Store.
func (s *S3) EnsureBucket(ctx context.Context) error {
	if _, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.bucket)}); err == nil {
		return nil
	}
	_, err := s.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: aws.String(s.bucket)})
	var exists *types.BucketAlreadyOwnedByYou
	if err != nil && !errors.As(err, &exists) {
		return fmt.Errorf("objectstore: creating bucket %q: %w", s.bucket, err)
	}
	return nil
}

func isNotFound(err error) bool {
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchKey", "NotFound", "NoSuchBucket":
			return true
		}
	}
	return false
}
