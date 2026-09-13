// Package storage définit l'interface d'abstraction de stockage de FluxGate
// et ses implémentations (système de fichiers local, S3/MinIO).
//
// L'interface Backend permet de stocker et récupérer des fichiers de manière
// transparente, indépendamment du backend sous-jacent. Elle supporte :
//   - Upload/download complet et par morceaux (chunked)
//   - Range requests pour la reprise de téléchargements
//   - Vérification d'existence et récupération de taille
package storage

import (
	"context"
	"errors"
	"io"
)

var (
	ErrChunkTooLarge       = errors.New("storage chunk exceeds declared size")
	ErrChunkOffsetMismatch = errors.New("storage chunk offset does not match file size")
)

// Backend defines the storage abstraction interface
// All storage backends (local, S3, MinIO) must implement this interface
type Backend interface {
	// Put stores data from reader at the given path
	// Returns the number of bytes written
	Put(ctx context.Context, path string, reader io.Reader, size int64) (int64, error)

	// Get returns a reader for the file at the given path
	// The caller is responsible for closing the reader
	Get(ctx context.Context, path string) (io.ReadCloser, error)

	// GetRange returns a reader for a byte range of the file
	// Used for HTTP Range requests (resume support)
	GetRange(ctx context.Context, path string, offset, length int64) (io.ReadCloser, error)

	// Delete removes the file at the given path
	Delete(ctx context.Context, path string) error

	// Exists checks if a file exists at the given path
	Exists(ctx context.Context, path string) (bool, error)

	// Size returns the size of the file in bytes
	Size(ctx context.Context, path string) (int64, error)

	// PutChunk writes a chunk at a specific offset (for resumable uploads)
	PutChunk(ctx context.Context, path string, reader io.Reader, offset, size int64) error

	// Type returns the backend type identifier
	Type() string
}

// CapacityBackend is implemented by storage backends that can report local
// free space. It allows upload admission control to preserve a safety floor.
type CapacityBackend interface {
	AvailableBytes(context.Context) (int64, error)
}

// TruncateBackend supports rolling back a local chunk when the corresponding
// database progress update cannot be committed.
type TruncateBackend interface {
	Truncate(context.Context, string, int64) error
}
