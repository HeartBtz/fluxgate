package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestUploadChunkRecoversAuthoritativeOffsetAfterLostResponse(t *testing.T) {
	const payload = "resumable upload payload"
	var uploaded int64
	mux := http.NewServeMux()
	mux.HandleFunc("PATCH /api/v1/files/upload/session-1", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		uploaded += int64(len(body))
		// Simulate a proxy losing the successful upstream response.
		http.Error(w, "upstream response lost", http.StatusBadGateway)
	})
	mux.HandleFunc("GET /api/v1/files/upload/session-1", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(uploadStatusResponse{
			SessionID: "session-1", Filename: "payload.bin",
			UploadedBytes: uploaded, TotalSize: int64(len(payload)), ChunkSize: len(payload),
		})
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	file, err := os.CreateTemp(t.TempDir(), "payload-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteString(payload); err != nil {
		t.Fatal(err)
	}

	progress := &progressReader{total: int64(len(payload)), startTime: time.Now()}
	next, err := uploadChunkWithRetry(server.Client(), server.URL, "Bearer test", file, "session-1", 0, int64(len(payload)), int64(len(payload)), progress)
	if err != nil {
		t.Fatal(err)
	}
	if next != int64(len(payload)) {
		t.Fatalf("next offset = %d, want %d", next, len(payload))
	}
}

func TestHumanizeBytes(t *testing.T) {
	if got := humanizeBytes(64 * 1024 * 1024); got != "64.0 MB" {
		t.Fatalf("humanizeBytes = %q", got)
	}
}
