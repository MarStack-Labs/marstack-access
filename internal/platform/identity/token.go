package identity

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"strings"
)

const (
	tokenPrefix   = "mat"
	selectorBytes = 10
	verifierBytes = 20
)

var tokenEncoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

type secretParts struct {
	selector string
	verifier string
}

func newSecret() (string, secretParts) {
	selector := randomString(selectorBytes)
	verifier := randomString(verifierBytes)

	return tokenPrefix + "_" + selector + "_" + verifier, secretParts{
		selector: selector,
		verifier: verifier,
	}
}

func parseSecret(secret string) (secretParts, bool) {
	parts := strings.Split(secret, "_")
	if len(parts) != 3 {
		return secretParts{}, false
	}
	if parts[0] != tokenPrefix || parts[1] == "" || parts[2] == "" {
		return secretParts{}, false
	}
	return secretParts{selector: parts[1], verifier: parts[2]}, true
}

func hashVerifier(verifier string) []byte {
	sum := sha256.Sum256([]byte(verifier))
	return sum[:]
}

func verifierMatches(stored []byte, verifier string) bool {
	return subtle.ConstantTimeCompare(stored, hashVerifier(verifier)) == 1
}

func randomString(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("identity: crypto/rand unavailable: " + err.Error())
	}
	return tokenEncoding.EncodeToString(buf)
}
