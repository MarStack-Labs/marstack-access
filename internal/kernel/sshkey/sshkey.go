package sshkey

import (
	"crypto/rsa"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const MinRSABits = 2048

var acceptedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoRSA:        true,
}

type Key struct {
	Fingerprint string
	Type        string
	Authorized  string
}

func Parse(raw string) (Key, error) {
	if raw == "" {
		return Key{}, fault.Invalid("invalid_public_key", "a public key is required")
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return Key{}, fault.Invalid("invalid_public_key",
			"the public key is not in authorized_keys format")
	}

	return fromPublicKey(key)
}

func checkRSAStrength(key ssh.PublicKey) error {
	if key.Type() != ssh.KeyAlgoRSA {
		return nil
	}

	crypto, ok := key.(ssh.CryptoPublicKey)
	if !ok {
		return fault.Invalid("invalid_public_key", "the RSA key could not be inspected")
	}
	pub, ok := crypto.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return fault.Invalid("invalid_public_key", "the RSA key could not be inspected")
	}
	if bits := pub.N.BitLen(); bits < MinRSABits {
		return fault.Invalid("weak_key",
			fmt.Sprintf("an RSA key must be at least %d bits, this one is %d", MinRSABits, bits))
	}
	return nil
}

func ParseHostKey(raw string) (Key, error) {
	lines := keyLines(raw)

	switch len(lines) {
	case 0:
		return Key{}, fault.Invalid("invalid_host_key", "a host key is required")
	case 1:
	default:
		return Key{}, fault.Invalid("ambiguous_host_key",
			fmt.Sprintf("%d host keys were given; pin one, for example with ssh-keyscan -t ed25519", len(lines)))
	}

	line := lines[0]

	if _, _, pub, _, _, err := ssh.ParseKnownHosts([]byte(line)); err == nil {
		return fromPublicKey(pub)
	}
	return Parse(line)
}

func keyLines(raw string) []string {
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return lines
}

func fromPublicKey(key ssh.PublicKey) (Key, error) {
	if !acceptedKeyTypes[key.Type()] {
		return Key{}, fault.Invalid("unsupported_key_type",
			fmt.Sprintf("the key type %q is not accepted", key.Type()))
	}
	if err := checkRSAStrength(key); err != nil {
		return Key{}, err
	}

	return Key{
		Fingerprint: ssh.FingerprintSHA256(key),
		Type:        key.Type(),
		Authorized:  string(ssh.MarshalAuthorizedKey(key)),
	}, nil
}
