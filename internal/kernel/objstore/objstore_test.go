package objstore

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2026, 8, 25, 12, 34, 56, 0, time.UTC)

func testCredentials() credentials {
	return credentials{
		accessKey: "AKIAEXAMPLE",
		secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		region:    "us-east-1",
	}
}

type capture struct {
	method  string
	path    string
	headers http.Header
	body    []byte
}

func serverCapturing(t *testing.T, seen *capture, status int) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read body: %v", err)
		}
		seen.method = r.Method
		seen.path = r.URL.Path
		seen.headers = r.Header.Clone()
		seen.headers.Set("Host", r.Host)
		seen.body = body

		w.WriteHeader(status)
		if status >= http.StatusBadRequest {
			if _, err := io.WriteString(w, "<Error><Code>AccessDenied</Code></Error>"); err != nil {
				t.Errorf("write: %v", err)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func clientFor(t *testing.T, endpoint string, mutate func(*Config)) *Client {
	t.Helper()

	cfg := Config{
		Endpoint:  endpoint,
		Bucket:    "marac-recordings",
		Region:    "us-east-1",
		AccessKey: "AKIAEXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
		RetainFor: 90 * 24 * time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}

	c, err := New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	c.now = func() time.Time { return fixedTime }
	return c
}

func TestPutSendsTheObjectToTheBucketPath(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, nil)

	stored, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader("recording\n"), "application/x-asciicast")
	if err != nil {
		t.Fatalf("put: %v", err)
	}

	if seen.method != http.MethodPut {
		t.Errorf("method = %q, want PUT", seen.method)
	}
	if want := "/marac-recordings/ses-abc.cast"; seen.path != want {
		t.Errorf("path = %q, want %q", seen.path, want)
	}
	if string(seen.body) != "recording\n" {
		t.Errorf("body = %q", seen.body)
	}
	if stored.Size != int64(len("recording\n")) {
		t.Errorf("size = %d", stored.Size)
	}
	if !stored.RetainUntil.Equal(fixedTime.Add(90 * 24 * time.Hour)) {
		t.Errorf("retain until = %v", stored.RetainUntil)
	}
}

func TestPutAsksForAnObjectLock(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, nil)

	if _, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader("recording\n"), "application/x-asciicast"); err != nil {
		t.Fatalf("put: %v", err)
	}

	if got := seen.headers.Get("X-Amz-Object-Lock-Mode"); got != LockModeCompliance {
		t.Errorf("lock mode = %q, want %q. Governance mode can be bypassed by a privileged user, which is the user this invariant is about",
			got, LockModeCompliance)
	}

	retain := seen.headers.Get("X-Amz-Object-Lock-Retain-Until-Date")
	parsed, err := time.Parse(time.RFC3339, retain)
	if err != nil {
		t.Fatalf("retain-until = %q, not RFC3339: %v", retain, err)
	}
	if !parsed.After(fixedTime) {
		t.Errorf("retain-until = %v, want a time after the upload", parsed)
	}
}

func TestNoRetentionMeansNoLockHeaders(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, func(c *Config) { c.RetainFor = 0 })

	if _, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader("x"), "text/plain"); err != nil {
		t.Fatalf("put: %v", err)
	}

	if seen.headers.Get("X-Amz-Object-Lock-Mode") != "" {
		t.Fatal("a lock mode was sent with no retention period, which most stores reject outright")
	}
}

func TestPutIsSigned(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, nil)

	if _, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader("recording\n"), "application/x-asciicast"); err != nil {
		t.Fatalf("put: %v", err)
	}

	auth := seen.headers.Get("Authorization")
	for _, want := range []string{
		algorithm,
		"Credential=AKIAEXAMPLE/20260825/us-east-1/s3/aws4_request",
		"SignedHeaders=",
		"Signature=",
	} {
		if !strings.Contains(auth, want) {
			t.Errorf("Authorization is missing %q: %s", want, auth)
		}
	}

	if got := seen.headers.Get("X-Amz-Date"); got != "20260825T123456Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
	if got := seen.headers.Get("X-Amz-Content-Sha256"); got != hashHex([]byte("recording\n")) {
		t.Errorf("X-Amz-Content-Sha256 = %q, want the payload hash", got)
	}
}

func TestTheSignedHeadersCoverEveryAmzHeaderSent(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, nil)

	if _, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader("x"), "text/plain"); err != nil {
		t.Fatalf("put: %v", err)
	}

	auth := seen.headers.Get("Authorization")
	start := strings.Index(auth, "SignedHeaders=")
	if start < 0 {
		t.Fatalf("no SignedHeaders in %q", auth)
	}
	signed := auth[start+len("SignedHeaders="):]
	if end := strings.Index(signed, ","); end >= 0 {
		signed = signed[:end]
	}
	covered := strings.Split(signed, ";")

	for name := range seen.headers {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, "x-amz-") {
			continue
		}
		found := false
		for _, c := range covered {
			if c == lower {
				found = true
			}
		}
		if !found {
			t.Errorf("%q was sent but not signed. An unsigned header can be changed in flight, and the object lock headers are exactly the ones an attacker would want to strip",
				lower)
		}
	}
}

func TestTheSignatureIsStableForFixedInputs(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut,
		"https://minio.internal:9000/marac-recordings/ses-abc.cast", strings.NewReader("recording\n"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Amz-Object-Lock-Mode", LockModeCompliance)
	req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", "2026-11-23T12:34:56Z")

	sign(req, testCredentials(), hashHex([]byte("recording\n")), fixedTime)
	first := req.Header.Get("Authorization")

	again, err := http.NewRequest(http.MethodPut,
		"https://minio.internal:9000/marac-recordings/ses-abc.cast", strings.NewReader("recording\n"))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	again.Header.Set("X-Amz-Object-Lock-Mode", LockModeCompliance)
	again.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", "2026-11-23T12:34:56Z")

	sign(again, testCredentials(), hashHex([]byte("recording\n")), fixedTime)

	if again.Header.Get("Authorization") != first {
		t.Fatal("signing the same request twice gave two signatures, so nothing about it is reproducible")
	}

	const pinned = "Signature="
	idx := strings.Index(first, pinned)
	signature := first[idx+len(pinned):]
	if len(signature) != 64 {
		t.Fatalf("signature is %d characters, want 64 hex characters", len(signature))
	}
	for _, c := range signature {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Fatalf("signature is not lowercase hex: %q", signature)
		}
	}
}

func TestChangingAnythingChangesTheSignature(t *testing.T) {
	base := func() *http.Request {
		req, err := http.NewRequest(http.MethodPut,
			"https://minio.internal:9000/marac-recordings/ses-abc.cast", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Amz-Object-Lock-Mode", LockModeCompliance)
		return req
	}

	reference := base()
	sign(reference, testCredentials(), hashHex([]byte("a")), fixedTime)
	want := reference.Header.Get("Authorization")

	cases := map[string]func() *http.Request{
		"different payload": func() *http.Request {
			r := base()
			sign(r, testCredentials(), hashHex([]byte("b")), fixedTime)
			return r
		},
		"different key": func() *http.Request {
			r := base()
			r.URL.Path = "/marac-recordings/ses-def.cast"
			sign(r, testCredentials(), hashHex([]byte("a")), fixedTime)
			return r
		},
		"different time": func() *http.Request {
			r := base()
			sign(r, testCredentials(), hashHex([]byte("a")), fixedTime.Add(time.Second))
			return r
		},
		"different lock mode": func() *http.Request {
			r := base()
			r.Header.Set("X-Amz-Object-Lock-Mode", LockModeGovernance)
			sign(r, testCredentials(), hashHex([]byte("a")), fixedTime)
			return r
		},
		"different secret": func() *http.Request {
			r := base()
			creds := testCredentials()
			creds.secretKey = "another-secret"
			sign(r, creds, hashHex([]byte("a")), fixedTime)
			return r
		},
	}

	for label, build := range cases {
		if got := build().Header.Get("Authorization"); got == want {
			t.Errorf("%s produced the same signature, so it is not covered by the signature at all", label)
		}
	}
}

func TestCanonicalURIEscapesEachSegmentButNotTheSlashes(t *testing.T) {
	cases := map[string]string{
		"/bucket/ses-abc.cast":   "/bucket/ses-abc.cast",
		"/bucket/a b":            "/bucket/a%20b",
		"/bucket/a+b":            "/bucket/a%2Bb",
		"/bucket/2026/08/x.cast": "/bucket/2026/08/x.cast",
		"":                       "/",
	}

	for input, want := range cases {
		if got := canonicalURI(input); got != want {
			t.Errorf("canonicalURI(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestTheStoreRefusingIsAnErrorCarryingWhatItSaid(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusForbidden)
	client := clientFor(t, srv.URL, nil)

	_, err := client.Put(context.Background(), "ses-abc.cast", strings.NewReader("x"), "text/plain")
	if err == nil {
		t.Fatal("a 403 was reported as success")
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("error = %q, want it to carry what the store said. A signing mistake shows up as a 403, and the store's own message is the only clue",
			err)
	}
}

func TestAnObjectLargerThanTheCapIsRefused(t *testing.T) {
	var seen capture
	srv := serverCapturing(t, &seen, http.StatusOK)
	client := clientFor(t, srv.URL, func(c *Config) { c.MaxObjectB = 16 })

	_, err := client.Put(context.Background(), "ses-abc.cast",
		strings.NewReader(strings.Repeat("a", 64)), "text/plain")

	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("err = %v, want ErrTooLarge. The payload is hashed in memory, so an unbounded read is the gateway's memory in an attacker's hands", err)
	}
	if seen.method != "" {
		t.Fatal("the oversized object was sent anyway")
	}
}

func TestAMissingEndpointOrBucketIsNotConfigured(t *testing.T) {
	for label, cfg := range map[string]Config{
		"no endpoint": {Bucket: "b", AccessKey: "a", SecretKey: "s"},
		"no bucket":   {Endpoint: "http://minio:9000", AccessKey: "a", SecretKey: "s"},
	} {
		if _, err := New(cfg); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s: err = %v, want ErrNotConfigured", label, err)
		}
	}
}

func TestMissingCredentialsAreRefusedAtConstruction(t *testing.T) {
	_, err := New(Config{Endpoint: "http://minio:9000", Bucket: "b"})
	if err == nil {
		t.Fatal("a client was built with no credentials, so every upload would fail at runtime instead of at startup")
	}
	if errors.Is(err, ErrNotConfigured) {
		t.Fatal("missing credentials read as not-configured, which would silently skip uploads rather than refusing to start")
	}
}

func TestANonHTTPEndpointIsRefused(t *testing.T) {
	if _, err := New(Config{
		Endpoint: "s3://minio:9000", Bucket: "b", AccessKey: "a", SecretKey: "s",
	}); err == nil {
		t.Fatal("an s3:// endpoint was accepted")
	}
}

func TestPlainHTTPIsReportedAsInsecure(t *testing.T) {
	insecure := clientFor(t, "http://minio:9000", nil)
	if !insecure.Insecure() {
		t.Error("a plain http endpoint does not report as insecure, so nothing can warn about it")
	}

	secure := clientFor(t, "https://minio:9000", nil)
	if secure.Insecure() {
		t.Error("an https endpoint reports as insecure")
	}
}

func TestThereIsNoWayToRemoveAnObject(t *testing.T) {
	var client any = &Client{}

	if _, ok := client.(interface {
		Delete(context.Context, string) error
	}); ok {
		t.Fatal("the client can delete. Object lock stops a store administrator, and this stops the gateway itself")
	}
	if _, ok := client.(interface {
		Remove(context.Context, string) error
	}); ok {
		t.Fatal("the client can remove")
	}
}
