package diagnosticuploads

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

func TestS3ObjectStoreLifecycle(t *testing.T) {
	endpoint := os.Getenv("PAPERBOAT_TEST_S3_ENDPOINT")
	if endpoint == "" {
		t.Skip("set PAPERBOAT_TEST_S3_ENDPOINT to run S3-compatible integration tests")
	}
	accessKey, secretKey, bucket := os.Getenv("PAPERBOAT_TEST_S3_ACCESS_KEY"), os.Getenv("PAPERBOAT_TEST_S3_SECRET_KEY"), os.Getenv("PAPERBOAT_TEST_S3_BUCKET")
	client := &http.Client{Timeout: 10 * time.Second}
	store, err := NewS3ObjectStore(context.Background(), config.Diagnostics{ObjectEndpoint: endpoint, ObjectRegion: "us-east-1", ObjectBucket: bucket, ForcePathStyle: true}, accessKey, secretKey, client)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("paperboat exact diagnostic bundle integration bytes")
	digest := sha256.Sum256(content)
	key := "diagnostics/diag_0123456789abcdef0123456789abcdef/" + time.Now().UTC().Format("20060102150405") + "aa.zip"
	authority, err := store.AuthorizePut(context.Background(), key, int64(len(content)), digest, time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPut, authority.URL, bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	request.ContentLength = int64(len(content))
	for name, value := range authority.Headers {
		if name != "Content-Length" {
			request.Header.Set(name, value)
		}
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		t.Fatalf("PUT status=%d", response.StatusCode)
	}
	metadata, err := store.Stat(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Bytes != int64(len(content)) || metadata.SHA256 != digest || metadata.ETag == "" {
		t.Fatalf("metadata=%#v", metadata)
	}
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stat(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted stat=%v", err)
	}
}
