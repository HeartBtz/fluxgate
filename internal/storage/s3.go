package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

// S3Backend implémente Backend pour le stockage objet compatible S3 (AWS, MinIO, etc.).
// Utilise le SDK AWS v2 pour la communication avec le service de stockage.
type S3Backend struct {
	client *s3.Client
	bucket string
}

// NewS3Backend crée un nouveau backend S3 avec les credentials et la configuration fournis.
func NewS3Backend(endpoint, region, bucket, accessKey, secretKey string, useSSL, forcePathStyle bool) (*S3Backend, error) {
	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey, secretKey, "",
		)),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = forcePathStyle
		if endpoint != "" {
			scheme := "https"
			if !useSSL {
				scheme = "http"
			}
			o.BaseEndpoint = aws.String(fmt.Sprintf("%s://%s", scheme, endpoint))
		}
	})

	return &S3Backend{
		client: client,
		bucket: bucket,
	}, nil
}

// Put stores data in S3
func (s *S3Backend) Put(ctx context.Context, path string, reader io.Reader, size int64) (int64, error) {
	input := &s3.CreateMultipartUploadInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}
	upload, err := s.client.CreateMultipartUpload(ctx, input)
	if err != nil {
		return 0, fmt.Errorf("s3 create multipart failed: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			_, _ = s.client.AbortMultipartUpload(cleanupCtx, &s3.AbortMultipartUploadInput{
				Bucket: input.Bucket, Key: input.Key, UploadId: upload.UploadId,
			})
		}
	}()
	// Seekable, bounded parts work with SDK signing/retries and unknown lengths.
	buffer := make([]byte, 16<<20)
	var written int64
	var parts []types.CompletedPart
	for partNumber := int32(1); ; partNumber++ {
		n, readErr := io.ReadFull(&contextReader{ctx: ctx, reader: reader}, buffer)
		if readErr != nil && readErr != io.EOF && readErr != io.ErrUnexpectedEOF {
			return written, readErr
		}
		if n == 0 && len(parts) > 0 {
			break
		}
		if partNumber > 10000 {
			return written, fmt.Errorf("S3 multipart part limit exceeded")
		}
		part, err := s.client.UploadPart(ctx, &s3.UploadPartInput{
			Bucket: input.Bucket, Key: input.Key, UploadId: upload.UploadId,
			PartNumber: aws.Int32(partNumber), Body: bytes.NewReader(buffer[:n]), ContentLength: aws.Int64(int64(n)),
		})
		if err != nil {
			return written, fmt.Errorf("s3 upload part failed: %w", err)
		}
		written += int64(n)
		parts = append(parts, types.CompletedPart{ETag: part.ETag, PartNumber: aws.Int32(partNumber)})
		if readErr != nil {
			break
		}
	}
	_, err = s.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket: input.Bucket, Key: input.Key, UploadId: upload.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{Parts: parts},
	})
	if err != nil {
		return written, fmt.Errorf("s3 complete multipart failed: %w", err)
	}
	complete = true
	return written, nil
}

// Get returns a reader for an S3 object
func (s *S3Backend) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}

	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("s3 get failed: %w", err)
	}

	return output.Body, nil
}

// GetRange returns a reader for a byte range
func (s *S3Backend) GetRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	rangeStr := fmt.Sprintf("bytes=%d-", offset)
	if length > 0 {
		rangeStr = fmt.Sprintf("bytes=%d-%d", offset, offset+length-1)
	}

	input := &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
		Range:  aws.String(rangeStr),
	}

	output, err := s.client.GetObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("s3 get range failed: %w", err)
	}

	return output.Body, nil
}

// Delete removes an S3 object
func (s *S3Backend) Delete(ctx context.Context, path string) error {
	input := &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}

	_, err := s.client.DeleteObject(ctx, input)
	if err != nil {
		return fmt.Errorf("s3 delete failed: %w", err)
	}

	return nil
}

// Exists checks if an S3 object exists
func (s *S3Backend) Exists(ctx context.Context, path string) (bool, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}

	_, err := s.client.HeadObject(ctx, input)
	if err != nil {
		var nf *types.NotFound
		if errors.As(err, &nf) {
			return false, nil
		}
		// Check for NoSuchKey as well
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return false, nil
		}
		return false, fmt.Errorf("s3 head failed: %w", err)
	}

	return true, nil
}

// Size returns the object size
func (s *S3Backend) Size(ctx context.Context, path string) (int64, error) {
	input := &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(path),
	}

	output, err := s.client.HeadObject(ctx, input)
	if err != nil {
		return 0, fmt.Errorf("s3 head failed: %w", err)
	}

	if output.ContentLength != nil {
		return *output.ContentLength, nil
	}
	return 0, nil
}

// PutChunk deliberately rejects persisted resumable sessions on S3.
func (s *S3Backend) PutChunk(ctx context.Context, path string, reader io.Reader, offset, size int64) error {
	return fmt.Errorf("resumable uploads are not supported by the S3 backend")
}

// Type returns "s3"
func (s *S3Backend) Type() string {
	return "s3"
}
