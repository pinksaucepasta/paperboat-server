package diagnosticuploads

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type fakePresigner struct {
	input   *s3.PutObjectInput
	expires time.Duration
}

func (f *fakePresigner) PresignPutObject(_ context.Context, input *s3.PutObjectInput, options ...func(*s3.PresignOptions)) (*awsv4.PresignedHTTPRequest, error) {
	settings := s3.PresignOptions{}
	for _, apply := range options {
		apply(&settings)
	}
	f.input, f.expires = input, settings.Expires
	return &awsv4.PresignedHTTPRequest{URL: "https://objects.example.test/upload?signed=yes", SignedHeader: http.Header{
		"Host": {"objects.example.test"}, "Content-Type": {"application/zip"}, "X-Amz-Checksum-Sha256": {*input.ChecksumSHA256}, "If-None-Match": {"*"},
	}}, nil
}

type fakeHead struct{ output *s3.HeadObjectOutput }

func (f *fakeHead) HeadObject(_ context.Context, _ *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	return f.output, nil
}

func TestS3AuthorizePutBindsExactObject(t *testing.T) {
	presigner := &fakePresigner{}
	store := &S3ObjectStore{bucket: "diagnostics", presigner: presigner}
	digest := sha256.Sum256([]byte("bundle"))
	authority, err := store.AuthorizePut(context.Background(), "diagnostics/diag_0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef.zip", 1234, digest, time.Now().Add(10*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToString(presigner.input.Bucket) != "diagnostics" || aws.ToString(presigner.input.Key) == "" || aws.ToInt64(presigner.input.ContentLength) != 1234 || aws.ToString(presigner.input.ContentType) != "application/zip" || aws.ToString(presigner.input.IfNoneMatch) != "*" {
		t.Fatalf("unbound input: %#v", presigner.input)
	}
	if got := aws.ToString(presigner.input.ChecksumSHA256); got != base64.StdEncoding.EncodeToString(digest[:]) {
		t.Fatalf("checksum = %q", got)
	}
	if presigner.expires <= 9*time.Minute || presigner.expires > 10*time.Minute || authority.Headers["Host"] != "" || authority.Headers["If-None-Match"] != "*" {
		t.Fatalf("authority = %#v expiry=%s", authority, presigner.expires)
	}
}

func TestS3StatRequiresProviderChecksum(t *testing.T) {
	digest := sha256.Sum256([]byte("bundle"))
	length, checksum, etag := int64(6), base64.StdEncoding.EncodeToString(digest[:]), `"etag"`
	store := &S3ObjectStore{bucket: "diagnostics", head: &fakeHead{output: &s3.HeadObjectOutput{ContentLength: &length, ChecksumSHA256: &checksum, ETag: &etag}}}
	metadata, err := store.Stat(context.Background(), "diagnostics/diag_0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef.zip")
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Bytes != length || metadata.SHA256 != digest || metadata.ETag != "etag" {
		t.Fatalf("metadata = %#v", metadata)
	}
	store.head = &fakeHead{output: &s3.HeadObjectOutput{ContentLength: &length, ETag: &etag}}
	if _, err := store.Stat(context.Background(), "diagnostics/diag_0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef.zip"); err == nil {
		t.Fatal("missing checksum accepted")
	}
	store.head = &fakeHead{output: &s3.HeadObjectOutput{ContentLength: &length, ETag: &etag, Metadata: map[string]string{"paperboat-sha256": fmt.Sprintf("%x", digest[:])}}}
	metadata, err = store.Stat(context.Background(), "diagnostics/diag_0123456789abcdef0123456789abcdef/0123456789abcdef0123456789abcdef.zip")
	if err != nil || metadata.SHA256 != digest {
		t.Fatalf("signed metadata fallback=%#v error=%v", metadata, err)
	}
}
