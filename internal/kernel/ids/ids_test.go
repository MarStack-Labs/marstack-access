package ids

import (
	"strings"
	"testing"
)

func TestNewIsPrefixedAndUnique(t *testing.T) {
	seen := make(map[string]bool, 1000)

	for range 1000 {
		id := New("ses")
		if !HasPrefix(id, "ses") {
			t.Fatalf("id = %q, want a ses- prefix", id)
		}
		if seen[id] {
			t.Fatalf("id %q was generated twice", id)
		}
		seen[id] = true
	}
}

func TestNewUsesAnUnambiguousAlphabet(t *testing.T) {
	const ambiguous = "ilou"

	for range 200 {
		id := strings.TrimPrefix(New("tgt"), "tgt-")
		if strings.ContainsAny(id, ambiguous) {
			t.Fatalf("id %q contains a character that is misread when a human copies it", id)
		}
		if strings.ToLower(id) != id {
			t.Fatalf("id %q is not lowercase", id)
		}
	}
}

func TestHasPrefixRequiresTheSeparator(t *testing.T) {
	if HasPrefix("session-abc", "ses") {
		t.Fatal("HasPrefix matched a longer prefix without the separator")
	}
	if !HasPrefix("ses-abc", "ses") {
		t.Fatal("HasPrefix rejected a valid id")
	}
}
