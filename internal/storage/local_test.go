package storage

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestLocalBackendRoundTripAndRange(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("0123456789")
	if n, err := b.Put(context.Background(), "ab/cd/file", bytes.NewReader(data), int64(len(data))); err != nil || n != int64(len(data)) {
		t.Fatalf("Put() = %d, %v", n, err)
	}
	r, err := b.GetRange(context.Background(), "ab/cd/file", 3, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, err := io.ReadAll(r)
	if err != nil || string(got) != "3456" {
		t.Fatalf("GetRange() = %q, %v", got, err)
	}
}

func TestLocalConfinement(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	victim := filepath.Join(outside, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(b.basePath, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(b.basePath, "leaf")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, path := range []string{"../victim", ".", "", victim, "escape/victim", "leaf"} {
		t.Run(path, func(t *testing.T) {
			if r, err := b.Get(ctx, path); err == nil {
				r.Close()
				t.Fatal("read escaped confinement")
			}
			if err := b.PutChunk(ctx, path, strings.NewReader("x"), 0, 1); err == nil {
				t.Fatal("chunk accepted unsafe path")
			}
			if err := b.Truncate(ctx, path, 0); err == nil {
				t.Fatal("truncate escaped confinement")
			}
		})
	}
	if _, err := b.Put(ctx, "escape/new", strings.NewReader("x"), 1); err == nil {
		t.Fatal("put followed external symlink")
	}
	if err := b.Delete(ctx, "escape/victim"); err == nil {
		t.Fatal("delete followed external directory")
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != "keep" {
		t.Fatalf("outside file changed: %q, %v", got, err)
	}
}

type cancelReader struct{ cancel context.CancelFunc }

func (r cancelReader) Read(p []byte) (int, error) { r.cancel(); return copy(p, "partial"), io.EOF }

func TestLocalCancellationRollsBackAndRemovesTemporary(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := b.Put(ctx, "file", cancelReader{cancel}, 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put: %v", err)
	}
	entries, err := os.ReadDir(b.basePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary files retained: %v, %v", entries, err)
	}
	if err := b.PutChunk(context.Background(), "chunk", strings.NewReader("abc"), 0, 3); err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	if err := b.PutChunk(ctx, "chunk", cancelReader{cancel}, 3, 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("chunk: %v", err)
	}
	if size, err := b.Size(context.Background(), "chunk"); err != nil || size != 3 {
		t.Fatalf("rollback size: %d, %v", size, err)
	}
}

func TestLocalConcurrentChunkHasOneWinner(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Go(func() { results <- b.PutChunk(context.Background(), "chunk", strings.NewReader("abc"), 0, 3) })
	}
	wg.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrChunkOffsetMismatch) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("winners = %d", winners)
	}
}

func TestLocalDeleteCleansOnlyOwnCrashStaging(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	own := filepath.Join(b.basePath, temporaryPrefix("file")+"crash")
	other := filepath.Join(b.basePath, temporaryPrefix("other")+"live")
	for _, path := range []string{own, other} {
		if err := os.WriteFile(path, []byte("partial"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Delete(context.Background(), "file"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(own); !os.IsNotExist(err) {
		t.Fatalf("staging remains: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated staging removed: %v", err)
	}
}

func TestLocalBackendPathLockIsSharded(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := b.pathLock("same")
	second := b.pathLock("same")
	if first != second {
		t.Fatal("same path must use the same lock")
	}
	different := false
	for i := 0; i < 128; i++ {
		if b.pathLock("same") != b.pathLock(string(rune(i+1))) {
			different = true
			break
		}
	}
	if !different {
		t.Fatal("all paths unexpectedly share one lock")
	}
}

func TestLocalBackendRejectsOversizedChunkWithoutAdvancingFile(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutChunk(context.Background(), "upload", bytes.NewReader([]byte("abcd")), 0, 3); err != ErrChunkTooLarge {
		t.Fatalf("PutChunk() error = %v, want %v", err, ErrChunkTooLarge)
	}
	if size, err := b.Size(context.Background(), "upload"); err != nil || size != 0 {
		t.Fatalf("Size() = %d, %v, want 0", size, err)
	}
}

func TestLocalBackendRejectsStaleChunkOffset(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutChunk(context.Background(), "upload", bytes.NewReader([]byte("abc")), 0, 3); err != nil {
		t.Fatal(err)
	}
	if err := b.PutChunk(context.Background(), "upload", bytes.NewReader([]byte("xyz")), 0, 3); err != ErrChunkOffsetMismatch {
		t.Fatalf("stale PutChunk() error = %v, want %v", err, ErrChunkOffsetMismatch)
	}
	r, err := b.Get(context.Background(), "upload")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	got, _ := io.ReadAll(r)
	if string(got) != "abc" {
		t.Fatalf("stale chunk overwrote data: %q", got)
	}
}

func TestLocalBackendTruncateRollsBackChunk(t *testing.T) {
	b, err := NewLocalBackend(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := b.PutChunk(context.Background(), "upload", bytes.NewReader([]byte("abcdef")), 0, 6); err != nil {
		t.Fatal(err)
	}
	if err := b.Truncate(context.Background(), "upload", 3); err != nil {
		t.Fatal(err)
	}
	if size, err := b.Size(context.Background(), "upload"); err != nil || size != 3 {
		t.Fatalf("Size() = %d, %v, want 3", size, err)
	}
}
