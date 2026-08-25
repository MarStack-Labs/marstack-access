package identity

import (
	"crypto/rsa"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const minRSABits = 2048

var acceptedKeyTypes = map[string]bool{
	ssh.KeyAlgoED25519:    true,
	ssh.KeyAlgoECDSA256:   true,
	ssh.KeyAlgoECDSA384:   true,
	ssh.KeyAlgoECDSA521:   true,
	ssh.KeyAlgoSKED25519:  true,
	ssh.KeyAlgoSKECDSA256: true,
	ssh.KeyAlgoRSA:        true,
}

type parsedKey struct {
	Fingerprint string
	Type        string
	Authorized  string
}

func parsePublicKey(raw string) (parsedKey, error) {
	if raw == "" {
		return parsedKey{}, fault.Invalid("invalid_public_key", "a public key is required")
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return parsedKey{}, fault.Invalid("invalid_public_key",
			"the public key is not in authorized_keys format")
	}

	if !acceptedKeyTypes[key.Type()] {
		return parsedKey{}, fault.Invalid("unsupported_key_type",
			fmt.Sprintf("the key type %q is not accepted", key.Type()))
	}

	if err := checkRSAStrength(key); err != nil {
		return parsedKey{}, err
	}

	return parsedKey{
		Fingerprint: ssh.FingerprintSHA256(key),
		Type:        key.Type(),
		Authorized:  string(ssh.MarshalAuthorizedKey(key)),
	}, nil
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
	if bits := pub.N.BitLen(); bits < minRSABits {
		return fault.Invalid("weak_key",
			fmt.Sprintf("an RSA key must be at least %d bits, this one is %d", minRSABits, bits))
	}
	return nil
}
