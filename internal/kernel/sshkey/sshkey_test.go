package sshkey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func ed25519Line(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func rsaLine(t *testing.T, bits int) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func TestParseAcceptsAnEd25519Key(t *testing.T) {
	raw := ed25519Line(t)

	key, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if key.Type != ssh.KeyAlgoED25519 {
		t.Errorf("type = %q, want %q", key.Type, ssh.KeyAlgoED25519)
	}
	if !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Errorf("fingerprint = %q, want a SHA256: prefix", key.Fingerprint)
	}
}

func TestParseNormalisesTheAuthorizedLine(t *testing.T) {
	raw := strings.TrimSpace(ed25519Line(t)) + " alice@laptop trailing junk"

	key, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if strings.Contains(key.Authorized, "alice@laptop") {
		t.Fatalf("the stored line kept the comment: %q. Storing what was typed rather than what was parsed means two spellings of one key look like two keys",
			key.Authorized)
	}
}

func TestTheSameKeyAlwaysHasTheSameFingerprint(t *testing.T) {
	raw := strings.TrimSpace(ed25519Line(t))

	spellings := []string{
		raw,
		raw + "\n",
		raw + " alice@laptop",
		"  " + raw + "  ",
	}

	var first string
	for i, spelling := range spellings {
		key, err := Parse(spelling)
		if err != nil {
			t.Fatalf("spelling %d: %v", i, err)
		}
		if i == 0 {
			first = key.Fingerprint
			continue
		}
		if key.Fingerprint != first {
			t.Fatalf("spelling %d gave fingerprint %q, want %q: a uniqueness index over fingerprints only works if the same key always hashes the same",
				i, key.Fingerprint, first)
		}
	}
}

func TestParseAcceptsAStrongRSAKey(t *testing.T) {
	if _, err := Parse(rsaLine(t, MinRSABits)); err != nil {
		t.Fatalf("a %d-bit RSA key was refused: %v", MinRSABits, err)
	}
}

func TestParseRefusesAWeakRSAKeyAndSaysHowWeak(t *testing.T) {
	_, err := Parse(rsaLine(t, 1024))
	if err == nil {
		t.Fatal("a 1024-bit RSA key was accepted")
	}

	f := fault.From(err)
	if f.Code != "weak_key" {
		t.Errorf("code = %q, want weak_key", f.Code)
	}
	if !strings.Contains(f.Message, "1024") {
		t.Errorf("message = %q, want it to name the actual bit length so the operator knows which key to replace", f.Message)
	}
}

func TestParseRefusesGarbage(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"prose":           "hello world",
		"private key":     "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----",
		"truncated":       "ssh-ed25519 AAAA",
		"wrong base64":    "ssh-ed25519 not-base64-at-all",
		"type only":       "ssh-ed25519",
		"authorized opts": `command="/bin/false" ssh-ed25519 AAAA`,
	}

	for label, raw := range cases {
		if _, err := Parse(raw); err == nil {
			t.Errorf("%s: Parse accepted %q", label, raw)
		} else if fault.From(err).Kind != fault.KindInvalid {
			t.Errorf("%s: kind = %v, want KindInvalid", label, fault.From(err).Kind)
		}
	}
}

func TestParseRefusesADeprecatedAlgorithm(t *testing.T) {
	if acceptedKeyTypes["ssh-dss"] {
		t.Fatal("ssh-dss is in the accepted set")
	}
	if acceptedKeyTypes["ssh-rsa-cert-v01@openssh.com"] {
		t.Fatal("a certificate type is in the accepted set. A certificate is not a key an account registers")
	}
}

func TestTheFingerprintMatchesTheStoredLine(t *testing.T) {
	key, err := Parse(ed25519Line(t))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	reparsed, err := Parse(key.Authorized)
	if err != nil {
		t.Fatalf("the stored line does not parse back: %v", err)
	}
	if reparsed.Fingerprint != key.Fingerprint {
		t.Fatal("re-parsing the stored line gives a different fingerprint, so a pin could not be re-verified after a restart")
	}
}

func TestParseHostKeyAcceptsSSHKeyscanOutput(t *testing.T) {
	raw := strings.TrimSpace(ed25519Line(t))
	want, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	scanned := "10.0.0.4 " + raw

	got, err := ParseHostKey(scanned)
	if err != nil {
		t.Fatalf("ParseHostKey refused ssh-keyscan output: %v", err)
	}
	if got.Fingerprint != want.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", got.Fingerprint, want.Fingerprint)
	}
	if strings.Contains(got.Authorized, "10.0.0.4") {
		t.Fatalf("the stored line kept the host field: %q", got.Authorized)
	}
}

func TestParseHostKeyAlsoAcceptsAPlainKeyLine(t *testing.T) {
	raw := strings.TrimSpace(ed25519Line(t))

	if _, err := ParseHostKey(raw); err != nil {
		t.Fatalf("a plain authorized_keys line was refused: %v", err)
	}
}

func TestParseHostKeySkipsCommentsAndBlanks(t *testing.T) {
	raw := strings.TrimSpace(ed25519Line(t))
	scanned := "# 10.0.0.4:22 SSH-2.0-OpenSSH_9.6\n\n10.0.0.4 " + raw + "\n"

	if _, err := ParseHostKey(scanned); err != nil {
		t.Fatalf("ssh-keyscan's comment header broke the parse: %v", err)
	}
}

func TestParseHostKeyRefusesMoreThanOneKey(t *testing.T) {
	first := strings.TrimSpace(ed25519Line(t))
	second := strings.TrimSpace(ed25519Line(t))
	scanned := "10.0.0.4 " + first + "\n10.0.0.4 " + second + "\n"

	_, err := ParseHostKey(scanned)
	if err == nil {
		t.Fatal("two host keys were accepted. ssh-keyscan without -t emits one line per algorithm, and silently pinning whichever came first means the pin may be for a key type the client never negotiates")
	}
	if fault.From(err).Code != "ambiguous_host_key" {
		t.Fatalf("code = %q, want ambiguous_host_key", fault.From(err).Code)
	}
}

func TestParseHostKeyRefusesAnEmptyInput(t *testing.T) {
	for _, raw := range []string{"", "\n\n", "# only a comment\n"} {
		if _, err := ParseHostKey(raw); err == nil {
			t.Errorf("ParseHostKey accepted %q", raw)
		}
	}
}
