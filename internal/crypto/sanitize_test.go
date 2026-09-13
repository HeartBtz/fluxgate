package crypto

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeFilenameLimitPreservesValidUTF8(t *testing.T) {
	name := strings.Repeat("é", 200) + ".txt"
	got := SanitizeFilenameLimit(name, 255)
	if len(got) > 255 {
		t.Fatalf("filename is %d bytes", len(got))
	}
	if !utf8.ValidString(got) {
		t.Fatalf("filename is invalid UTF-8: %q", got)
	}
	if !strings.HasSuffix(got, ".txt") {
		t.Fatalf("extension was not preserved: %q", got)
	}
}

func TestSanitizeFilenameRemovesTraversalAndHeaders(t *testing.T) {
	got := SanitizeFilename("../bad\r\nname.txt")
	if strings.ContainsAny(got, "/\\\r\n") || strings.HasPrefix(got, ".") {
		t.Fatalf("unsafe filename: %q", got)
	}
}
