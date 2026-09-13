package service

import "testing"

func TestParseDurationRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"", "tomorrow", "7days", "7junkd", "106752d", "9223372036854775807d", "0d", "-1d"} {
		if _, err := parseDuration(value); err == nil {
			t.Fatalf("parseDuration(%q) unexpectedly succeeded", value)
		}
	}
	if got, err := parseDuration("7d"); err != nil || got.Hours() != 168 {
		t.Fatalf("parseDuration(7d) = %v, %v", got, err)
	}
}

func TestExtractIP(t *testing.T) {
	tests := map[string]string{
		"192.0.2.10":        "192.0.2.10",
		"192.0.2.10:443":    "192.0.2.10",
		"2001:db8::1":       "2001:db8::1",
		"[2001:db8::1]:443": "2001:db8::1",
	}
	for input, want := range tests {
		if got := extractIP(input); got != want {
			t.Fatalf("extractIP(%q) = %q, want %q", input, got, want)
		}
	}
}
