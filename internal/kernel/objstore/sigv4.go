package objstore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	algorithm     = "AWS4-HMAC-SHA256"
	service       = "s3"
	terminator    = "aws4_request"
	dateFormat    = "20060102T150405Z"
	scopeDayFmt   = "20060102"
	signedHeaders = "host;x-amz-content-sha256;x-amz-date"
)

type credentials struct {
	accessKey string
	secretKey string
	region    string
}

func sign(req *http.Request, creds credentials, payloadHash string, at time.Time) {
	stamp := at.UTC().Format(dateFormat)
	day := at.UTC().Format(scopeDayFmt)

	req.Header.Set("X-Amz-Date", stamp)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)

	canonical := canonicalRequest(req, payloadHash)
	scope := strings.Join([]string{day, creds.region, service, terminator}, "/")

	toSign := strings.Join([]string{
		algorithm,
		stamp,
		scope,
		hashHex([]byte(canonical)),
	}, "\n")

	signature := hex.EncodeToString(hmacSHA256(signingKey(creds, day), []byte(toSign)))

	req.Header.Set("Authorization", strings.Join([]string{
		algorithm + " Credential=" + creds.accessKey + "/" + scope,
		"SignedHeaders=" + signedHeadersOf(req),
		"Signature=" + signature,
	}, ", "))
}

func canonicalRequest(req *http.Request, payloadHash string) string {
	return strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		req.URL.RawQuery,
		canonicalHeaders(req),
		signedHeadersOf(req),
		payloadHash,
	}, "\n")
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}

	segments := strings.Split(path, "/")
	for i, segment := range segments {
		segments[i] = escapePathSegment(segment)
	}
	return strings.Join(segments, "/")
}

func escapePathSegment(segment string) string {
	var b strings.Builder
	for i := range len(segment) {
		c := segment[i]
		if unreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func unreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_', c == '.', c == '~':
		return true
	default:
		return false
	}
}

func signedHeaderNames(req *http.Request) []string {
	names := []string{"host"}
	for name := range req.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") {
			names = append(names, lower)
		}
	}
	sort.Strings(names)
	return names
}

func signedHeadersOf(req *http.Request) string {
	return strings.Join(signedHeaderNames(req), ";")
}

func canonicalHeaders(req *http.Request) string {
	var b strings.Builder
	for _, name := range signedHeaderNames(req) {
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(headerValue(req, name))
		b.WriteByte('\n')
	}
	return b.String()
}

func headerValue(req *http.Request, name string) string {
	if name == "host" {
		return strings.TrimSpace(req.Host)
	}
	return strings.Join(strings.Fields(req.Header.Get(name)), " ")
}

func signingKey(creds credentials, day string) []byte {
	key := hmacSHA256([]byte("AWS4"+creds.secretKey), []byte(day))
	key = hmacSHA256(key, []byte(creds.region))
	key = hmacSHA256(key, []byte(service))
	return hmacSHA256(key, []byte(terminator))
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hashHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
