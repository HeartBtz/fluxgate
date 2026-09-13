package crypto

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Ce fichier contient les fonctions de sanitization pour les noms de fichiers
// et la validation des extensions. Ces fonctions protègent contre les attaques
// de type path traversal et le téléchargement de fichiers potentiellement dangereux.

var (
	dangerousFilenameChars = regexp.MustCompile(`[<>:"/\\|?*\x00-\x1f]`)
	repeatedFilenameSpace  = regexp.MustCompile(`[_\s]+`)
)

// SanitizeFilename cleans a filename to prevent path traversal and injection
func SanitizeFilename(name string) string {
	return SanitizeFilenameLimit(name, 255)
}

func SanitizeFilenameLimit(name string, maxBytes int) string {
	// Extract just the filename (no directory)
	name = filepath.Base(name)
	name = strings.ToValidUTF8(name, "_")

	// Remove null bytes
	name = strings.ReplaceAll(name, "\x00", "")

	// Replace dangerous characters
	name = dangerousFilenameChars.ReplaceAllString(name, "_")

	// Remove leading dots (hidden files)
	name = strings.TrimLeft(name, ".")

	// Remove leading/trailing whitespace
	name = strings.TrimSpace(name)

	// Collapse multiple underscores/spaces
	name = repeatedFilenameSpace.ReplaceAllString(name, "_")

	// Ensure it's not empty
	if name == "" || name == "_" {
		name = "unnamed"
	}

	// Truncate to reasonable length
	if maxBytes < 1 {
		maxBytes = 255
	}
	if len(name) > maxBytes {
		ext := filepath.Ext(name)
		if len(ext) >= maxBytes {
			return truncateUTF8Bytes(name, maxBytes)
		}
		base := strings.TrimSuffix(name, ext)
		name = truncateUTF8Bytes(base, maxBytes-len(ext)) + ext
	}

	return name
}

func truncateUTF8Bytes(value string, maxBytes int) string {
	if len(value) <= maxBytes {
		return value
	}
	cut := 0
	for cut < len(value) {
		_, size := utf8.DecodeRuneInString(value[cut:])
		if size == 0 || cut+size > maxBytes {
			break
		}
		cut += size
	}
	return value[:cut]
}

// ValidateExtension checks if the file extension is allowed
func ValidateExtension(filename string, allowed, blocked []string) error {
	ext := strings.ToLower(filepath.Ext(filename))
	if ext == "" {
		ext = "."
	}

	// Check blocked list first
	if len(blocked) > 0 {
		for _, b := range blocked {
			if strings.ToLower(b) == ext {
				return fmt.Errorf("file extension %s is blocked", ext)
			}
		}
	}

	// Check allowed list (if specified)
	if len(allowed) > 0 {
		found := false
		for _, a := range allowed {
			if strings.ToLower(a) == ext {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("file extension %s is not allowed", ext)
		}
	}

	return nil
}
