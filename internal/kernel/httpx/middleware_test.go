package httpx

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		Write(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

func request(t *testing.T, h http.Handler) *httptest.ResponseRecorder {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	return rec
}

func TestChainAppliesMiddlewareInOrder(t *testing.T) {
	var order []string

	mark := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}

	request(t, Chain(okHandler(), mark("first"), mark("second"), mark("third")))

	if want := "first,second,third"; strings.Join(order, ",") != want {
		t.Fatalf("order = %v, want %s", order, want)
	}
}

func TestRequestIDIsSetOnTheResponseAndTheContext(t *testing.T) {
	var fromContext string

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fromContext = RequestIDFrom(r.Context())
	}), RequestID())

	rec := request(t, h)

	header := rec.Header().Get("X-Request-Id")
	if header == "" {
		t.Fatal("X-Request-Id header is empty")
	}
	if fromContext != header {
		t.Fatalf("context id = %q, header = %q: they must match so a log line ties to a response", fromContext, header)
	}
}

func TestRequestIDFromAnEmptyContextIsEmpty(t *testing.T) {
	if got := RequestIDFrom(httptest.NewRequest(http.MethodGet, "/", nil).Context()); got != "" {
		t.Fatalf("RequestIDFrom = %q, want empty", got)
	}
}

func TestRecoverTurnsAPanicIntoAJSON500(t *testing.T) {
	var logged bytes.Buffer

	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("target address was nil")
	}), Recover(slog.New(slog.NewTextHandler(&logged, nil))))

	rec := request(t, h)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "target address was nil") {
		t.Fatalf("the panic value leaked to the client: %s", body)
	}
	if !strings.Contains(logged.String(), "target address was nil") {
		t.Fatalf("the panic value must be logged: %s", logged.String())
	}
}

func TestRecoverRunsOutsideRequestIDSoThePanicIsTraceable(t *testing.T) {
	var logged bytes.Buffer

	h := Chain(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	}), RequestID(), Recover(slog.New(slog.NewTextHandler(&logged, nil))))

	rec := request(t, h)

	id := rec.Header().Get("X-Request-Id")
	if id == "" {
		t.Fatal("no request id was assigned")
	}
	if !strings.Contains(logged.String(), id) {
		t.Fatalf("the panic log must carry the request id %q: %s", id, logged.String())
	}
}

func TestSecureHeadersAreSet(t *testing.T) {
	rec := request(t, Chain(okHandler(), SecureHeaders()))

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}
	for header, value := range want {
		if got := rec.Header().Get(header); got != value {
			t.Errorf("%s = %q, want %q", header, got, value)
		}
	}
}

func TestTimeoutReturnsAJSONEnvelope(t *testing.T) {
	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}), Timeout(10*time.Millisecond))

	rec := request(t, h)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"timeout"`) {
		t.Fatalf("body = %q, want the timeout error envelope", rec.Body.String())
	}
}

func TestAccessLogRecordsTheObservedStatus(t *testing.T) {
	var logged bytes.Buffer

	h := Chain(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		Write(w, http.StatusTeapot, nil)
	}), AccessLog(slog.New(slog.NewTextHandler(&logged, nil))))

	request(t, h)

	if !strings.Contains(logged.String(), "status=418") {
		t.Fatalf("access log did not record the real status: %s", logged.String())
	}
}
