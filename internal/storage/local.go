package storage

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// LocalBackend implémente Backend pour le stockage sur le système de fichiers local.
// Filesystem operations are confined with os.Root, including symlink resolution.
type LocalBackend struct {
	basePath string
	locks    [64]sync.Mutex
}

// AvailableBytes reports bytes available to the service user on the backing
// filesystem. Bavail is used rather than Bfree so reserved filesystem blocks
// remain unavailable to the application.
func (l *LocalBackend) AvailableBytes(_ context.Context) (int64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(l.basePath, &stat); err != nil {
		return 0, fmt.Errorf("failed to inspect storage capacity: %w", err)
	}
	if stat.Bsize <= 0 || stat.Bavail > uint64(math.MaxInt64)/uint64(stat.Bsize) {
		return 0, fmt.Errorf("filesystem capacity exceeds supported range")
	}
	return int64(stat.Bavail * uint64(stat.Bsize)), nil // #nosec G115 -- product is bounded by MaxInt64 above
}

// NewLocalBackend creates a new local filesystem storage backend
func NewLocalBackend(basePath string) (*LocalBackend, error) {
	absPath, err := filepath.Abs(basePath)
	if err != nil {
		return nil, fmt.Errorf("invalid base path: %w", err)
	}

	if err := os.MkdirAll(absPath, 0750); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}

	return &LocalBackend{basePath: absPath}, nil
}

func (l *LocalBackend) openRoot(ctx context.Context, path string) (*os.Root, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !filepath.IsLocal(path) || filepath.Clean(path) == "." {
		return nil, fmt.Errorf("invalid storage path")
	}
	return os.OpenRoot(l.basePath)
}

// Put stores data from reader at the given path
func (l *LocalBackend) Put(ctx context.Context, path string, reader io.Reader, size int64) (int64, error) {
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	lock := l.pathLock(path)
	lock.Lock()
	defer lock.Unlock()

	if err := root.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return 0, fmt.Errorf("failed to create directory: %w", err)
	}

	tmpName := filepath.Join(filepath.Dir(path), temporaryPrefix(path)+rand.Text())
	f, err := root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file: %w", err)
	}
	committed := false
	defer func() {
		_ = f.Close()
		if !committed {
			_ = root.Remove(tmpName)
		}
	}()
	if err := f.Chmod(0o640); err != nil {
		return 0, fmt.Errorf("failed to chmod temporary file: %w", err)
	}

	written, err := io.Copy(f, &contextReader{ctx: ctx, reader: reader})
	if err != nil {
		return 0, fmt.Errorf("failed to write file: %w", err)
	}

	if err := ctx.Err(); err != nil {
		return written, err
	}
	if err := f.Sync(); err != nil {
		return written, fmt.Errorf("failed to sync file: %w", err)
	}
	if err := f.Close(); err != nil {
		return written, fmt.Errorf("failed to close file: %w", err)
	}
	if err := root.Rename(tmpName, path); err != nil {
		return written, fmt.Errorf("failed to commit file: %w", err)
	}
	committed = true

	return written, nil
}

// Get returns a reader for the file at the given path
func (l *LocalBackend) Get(ctx context.Context, path string) (io.ReadCloser, error) {
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	f, err := root.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("storage object is not a regular file")
	}
	return f, nil
}

// GetRange returns a reader for a byte range
func (l *LocalBackend) GetRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error) {
	if offset < 0 || length <= 0 {
		return nil, fmt.Errorf("invalid range bounds")
	}
	r, err := l.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	f := r.(*os.File)

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("failed to seek: %w", err)
	}

	if length > 0 {
		return &limitedReadCloser{
			reader: io.LimitReader(f, length),
			closer: f,
		}, nil
	}

	return f, nil
}

// Delete removes the file at the given path
func (l *LocalBackend) Delete(ctx context.Context, path string) error {
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return err
	}
	defer root.Close()
	lock := l.pathLock(path)
	lock.Lock()
	defer lock.Unlock()

	if err := root.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete file: %w", err)
	}
	// Reclaim this object's staging files after a crash, not other live uploads.
	dir, err := root.Open(filepath.Dir(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer dir.Close()
	for {
		entries, err := dir.ReadDir(128)
		for _, entry := range entries {
			if strings.HasPrefix(entry.Name(), temporaryPrefix(path)) {
				if err := root.Remove(filepath.Join(filepath.Dir(path), entry.Name())); err != nil && !os.IsNotExist(err) {
					return err
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func temporaryPrefix(path string) string {
	hash := sha256.Sum256([]byte(filepath.Clean(path)))
	return fmt.Sprintf(".fluxgate-upload-%x-", hash[:16])
}

// Exists checks if a file exists
func (l *LocalBackend) Exists(ctx context.Context, path string) (bool, error) {
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return false, err
	}
	defer root.Close()

	_, err = root.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

// Size returns the file size
func (l *LocalBackend) Size(ctx context.Context, path string) (int64, error) {
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return 0, err
	}
	defer root.Close()

	info, err := root.Stat(path)
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("storage object is not a regular file")
	}

	return info.Size(), nil
}

// PutChunk writes a chunk at a specific offset
func (l *LocalBackend) PutChunk(ctx context.Context, path string, reader io.Reader, offset, size int64) error {
	if offset < 0 || size <= 0 {
		return fmt.Errorf("invalid chunk bounds")
	}
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return err
	}
	defer root.Close()

	if err := root.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	lock := l.pathLock(path)
	lock.Lock()
	defer lock.Unlock()

	flags := os.O_CREATE | os.O_WRONLY
	f, err := root.OpenFile(path, flags, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("failed to inspect upload file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() != offset {
		return ErrChunkOffsetMismatch
	}

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	rollback := func() {
		_ = f.Truncate(offset)
		_ = f.Sync()
	}
	written, err := io.Copy(f, io.LimitReader(&contextReader{ctx: ctx, reader: reader}, size+1))
	if err != nil {
		rollback()
		return fmt.Errorf("failed to write chunk: %w", err)
	}
	if written > size {
		rollback()
		return ErrChunkTooLarge
	}
	if err := ctx.Err(); err != nil {
		rollback()
		return err
	}

	if err := f.Sync(); err != nil {
		rollback()
		return fmt.Errorf("failed to sync chunk: %w", err)
	}
	return nil
}

// Truncate rolls a local resumable upload back to its last database-confirmed
// offset. The same path lock serializes this with PutChunk.
func (l *LocalBackend) Truncate(ctx context.Context, path string, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if size < 0 {
		return fmt.Errorf("invalid truncate size")
	}
	root, err := l.openRoot(ctx, path)
	if err != nil {
		return err
	}
	defer root.Close()
	lock := l.pathLock(path)
	lock.Lock()
	defer lock.Unlock()
	f, err := root.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(size); err != nil {
		return fmt.Errorf("failed to truncate upload: %w", err)
	}
	return f.Sync()
}

func (l *LocalBackend) pathLock(path string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write([]byte(filepath.Clean(path)))
	return &l.locks[h.Sum32()%uint32(len(l.locks))]
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Type returns "local"
func (l *LocalBackend) Type() string {
	return "local"
}

// limitedReadCloser wraps a limited reader with a closer
type limitedReadCloser struct {
	reader io.Reader
	closer io.Closer
}

func (l *limitedReadCloser) Read(p []byte) (int, error) {
	return l.reader.Read(p)
}

func (l *limitedReadCloser) Close() error {
	return l.closer.Close()
}
