package ids

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
)

const randomBytes = 8

var encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

func New(prefix string) string {
	buf := make([]byte, randomBytes)
	if _, err := rand.Read(buf); err != nil {
		panic("ids: crypto/rand unavailable: " + err.Error())
	}
	return prefix + "-" + encoding.EncodeToString(buf)
}

func HasPrefix(id, prefix string) bool {
	return strings.HasPrefix(id, prefix+"-")
}
