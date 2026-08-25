package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
)

func newTestApp(t *testing.T) *App {
	t.Helper()

	a, err := New(context.Background(), Config{DataDir: t.TempDir()}, logging.New("error", io.Discard))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}

func do(t *testing.T, a *App, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body)
	}
	return body
}

func TestHealthzReportsOK(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := decodeBody(t, rec)["status"]; got != "ok" {
		t.Fatalf("status field = %q, want ok", got)
	}
}

func TestHealthzReportsUnavailableWhenTheStoreIsGone(t *testing.T) {
	a := newTestApp(t)
	if err := a.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	rec := do(t, a, http.MethodGet, "/healthz")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: a health check that cannot see its store must not report ok", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "sql:") || strings.Contains(body, "sqlite") {
		t.Fatalf("the response leaks the driver error: %s", body)
	}
}

func TestVersionEndpointReportsBuildMetadata(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/v1/version")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	body := decodeBody(t, rec)
	if body["version"] == "" || body["commit"] == "" {
		t.Fatalf("body = %v, want both version and commit", body)
	}
}

func TestUnknownRouteIsNotFound(t *testing.T) {
	if rec := do(t, newTestApp(t), http.MethodGet, "/v1/no-such-resource"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestTargetModuleIsWiredThroughTheFullPipeline(t *testing.T) {
	a := newTestApp(t)

	r := httptest.NewRequest(http.MethodPost, "/v1/targets",
		strings.NewReader(`{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`))
	r.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201: the module's migrations and routes must both be registered (%s)",
			rec.Code, rec.Body)
	}
	if rec.Header().Get("X-Request-Id") == "" {
		t.Error("a module route did not go through the RequestID middleware")
	}
	if rec.Header().Get("X-Frame-Options") != "DENY" {
		t.Error("a module route did not go through the SecureHeaders middleware")
	}
}

func TestIdentityExposesNoEndpointYet(t *testing.T) {
	a := newTestApp(t)

	for _, path := range []string{"/v1/users", "/v1/tokens"} {
		if rec := do(t, a, http.MethodGet, path); rec.Code != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404. An identity endpoint must not exist before the authorization middleware does, or creating an admin would be unauthenticated",
				path, rec.Code)
		}
	}
}

func TestBootstrapWritesATokenFileAndNotALogLine(t *testing.T) {
	dir := t.TempDir()
	var logged bytes.Buffer

	a, err := New(context.Background(), Config{DataDir: dir},
		slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer a.Close()

	path := filepath.Join(dir, bootstrapTokenFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bootstrap token: %v", err)
	}

	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		t.Fatal("the bootstrap token file is empty")
	}
	if !strings.Contains(logged.String(), path) {
		t.Error("the log does not name the token file, so an operator cannot find it")
	}
	if strings.Contains(logged.String(), secret) {
		t.Fatal("the bootstrap secret was written to the log")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o, want 0600: it is a working admin credential on disk", perm)
	}
}

func TestBootstrapRunsOnlyOnTheFirstStart(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)
	path := filepath.Join(dir, bootstrapTokenFile)

	first, err := New(context.Background(), Config{DataDir: dir}, log)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	first.Close()

	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	second, err := New(context.Background(), Config{DataDir: dir}, log)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	second.Close()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("a restart minted another admin credential, so deleting the file is not enough to close the window")
	}
	if len(original) == 0 {
		t.Fatal("the first start wrote nothing")
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodPost, "/healthz")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405: routes declare their method", rec.Code)
	}
}

func TestSecurityHeadersArePresentOnEveryResponse(t *testing.T) {
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	for _, path := range []string{"/healthz", "/v1/version", "/does-not-exist"} {
		rec := do(t, newTestApp(t), http.MethodGet, path)
		for header, value := range want {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("%s: %s = %q, want %q", path, header, got, value)
			}
		}
	}
}

func TestRequestIDIsAssignedEvenOnAMissingRoute(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/does-not-exist")

	if id := rec.Header().Get("X-Request-Id"); !strings.HasPrefix(id, "req-") {
		t.Fatalf("X-Request-Id = %q, want a req- prefixed id: a 404 still has to be traceable", id)
	}
}

func TestConfigDefaultsAreApplied(t *testing.T) {
	got := Config{}.withDefaults()

	if got.Listen != "127.0.0.1:7443" {
		t.Errorf("Listen = %q, want the loopback default: the control plane must not bind every interface by accident", got.Listen)
	}
	if got.DataDir == "" {
		t.Error("DataDir default is empty")
	}
	if got.RequestTimeout <= 0 {
		t.Error("RequestTimeout default must be positive")
	}
}

func TestExplicitConfigIsNotOverwritten(t *testing.T) {
	got := Config{Listen: "0.0.0.0:9000", DataDir: "/srv/marac", RequestTimeout: time.Second}.withDefaults()

	if got.Listen != "0.0.0.0:9000" || got.DataDir != "/srv/marac" || got.RequestTimeout != time.Second {
		t.Fatalf("defaults overwrote explicit config: %+v", got)
	}
}

func TestServerTimeoutsAreSet(t *testing.T) {
	a := newTestApp(t)

	if a.http.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is unset: an unauthenticated peer can hold a connection open forever")
	}
	if a.http.ReadTimeout <= 0 || a.http.WriteTimeout <= 0 || a.http.IdleTimeout <= 0 {
		t.Errorf("a timeout is unset: read=%v write=%v idle=%v",
			a.http.ReadTimeout, a.http.WriteTimeout, a.http.IdleTimeout)
	}
	if a.http.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is unset")
	}
}

func TestRestartingOnTheSameDataDirIsSafe(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)

	for range 3 {
		a, err := New(context.Background(), Config{DataDir: dir}, log)
		if err != nil {
			t.Fatalf("new app: %v", err)
		}
		a.Close()
	}
}

func TestModuleNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)

	for _, m := range newTestApp(t).modules {
		if m.Name() == "" {
			t.Error("a module reports an empty name")
		}
		if seen[m.Name()] {
			t.Errorf("module name %q is registered twice: migrations would be recorded under one owner", m.Name())
		}
		seen[m.Name()] = true
	}
}

func TestRunShutsDownOnContextCancel(t *testing.T) {
	a, err := New(context.Background(), Config{DataDir: t.TempDir(), Listen: "127.0.0.1:0"}, logging.New("error", io.Discard))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}
