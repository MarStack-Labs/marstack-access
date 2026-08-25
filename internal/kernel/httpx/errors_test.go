package httpx

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func serve(t *testing.T, log *slog.Logger, h Handler) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	Wrap(log, h)(rec, httptest.NewRequest(http.MethodGet, "/v1/targets/tgt-abc", nil))
	return rec
}

func errorBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	var parsed struct {
		Error map[string]string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("body is not a JSON error envelope: %v (%s)", err, rec.Body)
	}
	return parsed.Error
}

func TestFaultKindsMapToStatusCodes(t *testing.T) {
	cases := []struct {
		f    *fault.Fault
		want int
	}{
		{fault.Invalid("bad_name", "name is invalid"), http.StatusBadRequest},
		{fault.NotFound("target_not_found", "no such target"), http.StatusNotFound},
		{fault.Conflict("name_taken", "already exists"), http.StatusConflict},
		{fault.Unauthenticated("no_token", "authentication required"), http.StatusUnauthorized},
		{fault.Forbidden("no_grant", "no active grant for this target"), http.StatusForbidden},
		{fault.Unavailable("store_down", "store unreachable"), http.StatusServiceUnavailable},
		{fault.Internal(errors.New("boom")), http.StatusInternalServerError},
	}

	for _, c := range cases {
		rec := serve(t, discardLogger(), func(http.ResponseWriter, *http.Request) error {
			return c.f
		})
		if rec.Code != c.want {
			t.Errorf("%s: status = %d, want %d", c.f.Code, rec.Code, c.want)
		}
		if got := errorBody(t, rec)["code"]; got != c.f.Code {
			t.Errorf("code = %q, want %q", got, c.f.Code)
		}
	}
}

func TestAnUnclassifiedErrorFailsClosed(t *testing.T) {
	rec := serve(t, discardLogger(), func(http.ResponseWriter, *http.Request) error {
		return errors.New("some new failure nobody classified")
	})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: an unclassified error must not become a 200 or a 400", rec.Code)
	}
}

func TestInternalDetailNeverReachesTheClient(t *testing.T) {
	const leak = "ssh: cert signed by unknown authority ca-key-7f3a"

	rec := serve(t, discardLogger(), func(http.ResponseWriter, *http.Request) error {
		return fault.Internal(errors.New(leak))
	})

	if body := rec.Body.String(); strings.Contains(body, "ca-key-7f3a") || strings.Contains(body, leak) {
		t.Fatalf("the response leaks the internal cause: %s", body)
	}
	if got := errorBody(t, rec)["message"]; got != "an internal error occurred" {
		t.Fatalf("message = %q, want the generic message", got)
	}
}

func TestInternalDetailIsLoggedServerSide(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))

	serve(t, log, func(http.ResponseWriter, *http.Request) error {
		return fault.Internal(errors.New("dial 10.0.0.4:22: connection refused"))
	})

	if !strings.Contains(logged.String(), "connection refused") {
		t.Fatalf("the cause must be logged for operators: %s", logged.String())
	}
}

func TestClientErrorsAreNotLoggedAsFailures(t *testing.T) {
	var logged bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logged, nil))

	serve(t, log, func(http.ResponseWriter, *http.Request) error {
		return fault.NotFound("target_not_found", "no such target")
	})

	if logged.Len() != 0 {
		t.Fatalf("a 4xx must not be logged at error level: %s", logged.String())
	}
}

func TestHandlerReturningNilWritesNothingExtra(t *testing.T) {
	rec := serve(t, discardLogger(), func(w http.ResponseWriter, _ *http.Request) error {
		Write(w, http.StatusOK, map[string]string{"status": "ok"})
		return nil
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "error") {
		t.Fatalf("body = %s, want no error envelope", rec.Body)
	}
}
