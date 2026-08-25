package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	if rec := do(t, newTestApp(t), http.MethodGet, "/v1/targets"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
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
