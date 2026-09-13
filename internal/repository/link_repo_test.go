package repository

import (
	"context"
	"errors"
	"github.com/HeartBtz/fluxgate/internal/domain"
	"strings"
	"testing"
)

func TestHashLinkTokenIsPrefixedAndOneWay(t *testing.T) {
	raw := "download-secret"
	hashed := hashLinkToken(raw)
	if hashed == raw || !strings.HasPrefix(hashed, "sha256:") || len(hashed) != 71 {
		t.Fatalf("unexpected stored link token %q", hashed)
	}
	if hashed != hashLinkToken(raw) || hashed == hashLinkToken(raw+"x") {
		t.Fatal("link token hashing is unstable or collided")
	}
}

func TestStoredLinkDigestCannotAuthenticate(t *testing.T) {
	r := NewLinkRepository(nil)
	if _, err := r.GetByToken(context.Background(), hashLinkToken("raw-secret")); !errors.Is(err, domain.ErrLinkNotFound) {
		t.Fatalf("stored digest accepted: %v", err)
	}
}
