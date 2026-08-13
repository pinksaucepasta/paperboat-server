package diagnosticuploads

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/pinksaucepasta/paperboat-server/internal/config"
)

type s3HeadClient interface {
	HeadObject(context.Context, *s3.HeadObjectInput, ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
}

type s3PresignClient interface {
	PresignPutObject(context.Context, *s3.PutObjectInput, ...func(*s3.PresignOptions)) (*awsv4.PresignedHTTPRequest, error)
}

type s3DeleteClient interface {
	DeleteObject(context.Context, *s3.DeleteObjectInput, ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

type S3ObjectStore struct {
	bucket    string
	head      s3HeadClient
	presigner s3PresignClient
	cleaner   s3DeleteClient
}

func NewS3ObjectStore(ctx context.Context, cfg config.Diagnostics, accessKey, secretKey string, client *http.Client) (*S3ObjectStore, error) {
	endpoint, err := url.Parse(strings.TrimSpace(cfg.ObjectEndpoint))
	if err != nil || endpoint.Scheme == "" || endpoint.Host == "" || strings.TrimSpace(cfg.ObjectRegion) == "" || strings.TrimSpace(cfg.ObjectBucket) == "" || strings.TrimSpace(accessKey) == "" || strings.TrimSpace(secretKey) == "" || client == nil {
		return nil, ErrInvalid
	}
	loaded, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.ObjectRegion),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKey, secretKey, "")),
		awsconfig.WithHTTPClient(client),
		awsconfig.WithBaseEndpoint(endpoint.String()),
		awsconfig.WithRequestChecksumCalculation(aws.RequestChecksumCalculationWhenRequired),
		awsconfig.WithResponseChecksumValidation(aws.ResponseChecksumValidationWhenRequired),
	)
	if err != nil {
		return nil, fmt.Errorf("configure diagnostic object storage: %w", err)
	}
	s3Client := s3.NewFromConfig(loaded, func(options *s3.Options) { options.UsePathStyle = cfg.ForcePathStyle })
	return &S3ObjectStore{bucket: cfg.ObjectBucket, head: s3Client, presigner: s3.NewPresignClient(s3Client), cleaner: s3Client}, nil
}

func (s *S3ObjectStore) AuthorizePut(ctx context.Context, objectKey string, bytes int64, digest [sha256.Size]byte, expiresAt time.Time) (UploadAuthority, error) {
	if s == nil || s.presigner == nil || s.bucket == "" || !validObjectKey(objectKey) || bytes < 1 || bytes > MaximumBundleBytes {
		return UploadAuthority{}, ErrInvalid
	}
	lifetime := time.Until(expiresAt)
	if lifetime <= 0 || lifetime > IntentLifetime {
		return UploadAuthority{}, ErrExpired
	}
	checksum := base64.StdEncoding.EncodeToString(digest[:])
	contentType, noOverwrite := "application/zip", "*"
	presigned, err := s.presigner.PresignPutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.bucket), Key: aws.String(objectKey), ContentType: &contentType,
		ContentLength: aws.Int64(bytes), ChecksumSHA256: &checksum, IfNoneMatch: &noOverwrite,
		Metadata: map[string]string{"paperboat-sha256": fmt.Sprintf("%x", digest[:])},
	}, func(options *s3.PresignOptions) { options.Expires = lifetime })
	if err != nil {
		return UploadAuthority{}, fmt.Errorf("authorize diagnostic upload: %w", err)
	}
	headers := make(map[string]string, len(presigned.SignedHeader))
	for name, values := range presigned.SignedHeader {
		if strings.EqualFold(name, "host") {
			continue
		}
		if len(values) != 1 {
			return UploadAuthority{}, ErrInvalid
		}
		headers[name] = values[0]
	}
	return UploadAuthority{URL: presigned.URL, Headers: headers}, nil
}

func (s *S3ObjectStore) Stat(ctx context.Context, objectKey string) (ObjectMetadata, error) {
	if s == nil || s.head == nil || s.bucket == "" || !validObjectKey(objectKey) {
		return ObjectMetadata{}, ErrInvalid
	}
	output, err := s.head.HeadObject(ctx, &s3.HeadObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(objectKey), ChecksumMode: types.ChecksumModeEnabled})
	if err != nil {
		var apiError smithy.APIError
		if errors.As(err, &apiError) && (apiError.ErrorCode() == "NotFound" || apiError.ErrorCode() == "NoSuchKey") {
			return ObjectMetadata{}, ErrNotFound
		}
		return ObjectMetadata{}, fmt.Errorf("inspect diagnostic upload: %w", err)
	}
	if output.ContentLength == nil || output.ETag == nil {
		return ObjectMetadata{}, ErrUploadMismatch
	}
	var decoded []byte
	if output.ChecksumSHA256 != nil {
		decoded, err = base64.StdEncoding.DecodeString(*output.ChecksumSHA256)
	} else {
		decoded, err = hex.DecodeString(output.Metadata["paperboat-sha256"])
	}
	if err != nil || len(decoded) != sha256.Size {
		return ObjectMetadata{}, ErrUploadMismatch
	}
	var digest [sha256.Size]byte
	copy(digest[:], decoded)
	return ObjectMetadata{Bytes: *output.ContentLength, SHA256: digest, ETag: strings.Trim(*output.ETag, `"`)}, nil
}

func (s *S3ObjectStore) Delete(ctx context.Context, objectKey string) error {
	if s == nil || s.bucket == "" || !validObjectKey(objectKey) {
		return ErrInvalid
	}
	if s.cleaner == nil {
		return ErrUnavailable
	}
	_, err := s.cleaner.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: aws.String(s.bucket), Key: aws.String(objectKey)})
	if err != nil {
		return fmt.Errorf("delete diagnostic upload: %w", err)
	}
	return nil
}

func validObjectKey(value string) bool {
	parts := strings.Split(value, "/")
	return len(parts) == 3 && parts[0] == "diagnostics" && strings.HasPrefix(parts[1], "diag_") && validIdentifier(parts[1], 21, 133) && strings.HasSuffix(parts[2], ".zip") && validIdentifier(strings.TrimSuffix(parts[2], ".zip"), 16, 128)
}
