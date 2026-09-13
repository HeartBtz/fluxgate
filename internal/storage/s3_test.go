package storage

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestS3UnknownLengthAndAbort(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			var uploaded, aborted atomic.Int64
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/xml")
				switch {
				case r.Method == "POST" && r.URL.Query().Has("uploads"):
					fmt.Fprint(w, `<InitiateMultipartUploadResult><UploadId>test-upload</UploadId></InitiateMultipartUploadResult>`)
				case r.Method == "PUT":
					n, err := io.Copy(io.Discard, r.Body)
					if err != nil {
						t.Error(err)
					}
					uploaded.Add(n)
					w.Header().Set("ETag", `"test-etag"`)
				case r.Method == "POST":
					fmt.Fprint(w, `<CompleteMultipartUploadResult><ETag>test-etag</ETag></CompleteMultipartUploadResult>`)
				case r.Method == "DELETE":
					aborted.Add(1)
					w.WriteHeader(http.StatusNoContent)
				default:
					t.Errorf("unexpected S3 request: %s", r.Method)
					w.WriteHeader(400)
				}
			}))
			defer server.Close()
			backend, err := NewS3Backend(strings.TrimPrefix(server.URL, "http://"), "us-east-1", "test-bucket", "test-access", "test-secret", false, true)
			if err != nil {
				t.Fatal(err)
			}
			var reader io.Reader = strings.NewReader("payload")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if fail {
				reader = cancelReader{cancel}
			}
			n, err := backend.Put(ctx, "file", reader, 0)
			if fail {
				if err == nil || aborted.Load() != 1 {
					t.Fatalf("canceled upload: %v, aborts %d", err, aborted.Load())
				}
			} else if err != nil || n != 7 || uploaded.Load() < 7 || aborted.Load() != 0 {
				t.Fatalf("upload: size %d, err %v, bytes %d, aborts %d", n, err, uploaded.Load(), aborted.Load())
			}
		})
	}
}
