package identity

import (
	"strings"
	"testing"
)

func TestNewSecretIsPrefixedAndParsesBack(t *testing.T) {
	secret, parts := newSecret()

	if !strings.HasPrefix(secret, tokenPrefix+"_") {
		t.Fatalf("secret = %q, want a %s_ prefix so a leaked token is recognisable to a scanner",
			secret, tokenPrefix)
	}

	parsed, ok := parseSecret(secret)
	if !ok {
		t.Fatalf("parseSecret(%q) reported malformed", secret)
	}
	if parsed != parts {
		t.Fatalf("parsed = %+v, want %+v", parsed, parts)
	}
}

func TestSecretsAreUnique(t *testing.T) {
	seen := make(map[string]bool, 2000)

	for range 1000 {
		secret, parts := newSecret()
		if seen[secret] {
			t.Fatal("a secret was generated twice")
		}
		if seen[parts.selector] {
			t.Fatal("a selector was generated twice, which would collide on the unique index")
		}
		seen[secret] = true
		seen[parts.selector] = true
	}
}

func TestSecretCarriesEnoughEntropy(t *testing.T) {
	_, parts := newSecret()

	if len(parts.verifier) < 32 {
		t.Fatalf("verifier is %d characters, want at least 32: it is the only thing standing between a guesser and an account",
			len(parts.verifier))
	}
	if len(parts.selector) < 16 {
		t.Fatalf("selector is %d characters, want at least 16", len(parts.selector))
	}
}

func TestParseSecretRejectsMalformedInput(t *testing.T) {
	for _, value := range []string{
		"",
		"mat",
		"mat_",
		"mat_only-two-parts",
		"mat__missingselector",
		"mat_missingverifier_",
		"xyz_selector_verifier",
		"mat_selector_verifier_extra",
		"selector_verifier",
	} {
		if _, ok := parseSecret(value); ok {
			t.Errorf("parseSecret(%q) = ok, want malformed", value)
		}
	}
}

func TestVerifierMatchesOnlyTheRightVerifier(t *testing.T) {
	_, parts := newSecret()
	stored := hashVerifier(parts.verifier)

	if !verifierMatches(stored, parts.verifier) {
		t.Fatal("the correct verifier did not match its own hash")
	}
	if verifierMatches(stored, parts.verifier+"x") {
		t.Fatal("a longer verifier matched")
	}
	if verifierMatches(stored, parts.verifier[:len(parts.verifier)-1]) {
		t.Fatal("a truncated verifier matched")
	}
	if verifierMatches(stored, "") {
		t.Fatal("an empty verifier matched")
	}
}

func TestVerifierMatchesRejectsAShortStoredHash(t *testing.T) {
	_, parts := newSecret()

	if verifierMatches(nil, parts.verifier) {
		t.Fatal("a nil stored hash matched: a row with a missing hash must not authenticate anyone")
	}
	if verifierMatches([]byte("short"), parts.verifier) {
		t.Fatal("a truncated stored hash matched")
	}
}

func TestHashIsNotTheVerifier(t *testing.T) {
	_, parts := newSecret()

	if strings.Contains(string(hashVerifier(parts.verifier)), parts.verifier) {
		t.Fatal("the stored value contains the verifier itself")
	}
}
