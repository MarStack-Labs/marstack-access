package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

type registerTarget struct {
	Name      string `json:"name"`
	Address   string `json:"address"`
	Principal string `json:"principal"`
}

func decodeRequest(t *testing.T, contentType, body string) (registerTarget, error) {
	t.Helper()

	r := httptest.NewRequest(http.MethodPost, "/v1/targets", strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return Decode[registerTarget](httptest.NewRecorder(), r)
}

func codeOf(t *testing.T, err error) string {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
	return fault.From(err).Code
}

func TestDecodeAcceptsAWellFormedBody(t *testing.T) {
	got, err := decodeRequest(t, "application/json",
		`{"name":"db-1","address":"10.0.0.4","principal":"deploy"}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "db-1" || got.Principal != "deploy" {
		t.Fatalf("decoded = %+v", got)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	_, err := decodeRequest(t, "application/json",
		`{"name":"db-1","address":"10.0.0.4","principal":"deploy","principals":["root"]}`)

	if code := codeOf(t, err); code != "invalid_json" {
		t.Fatalf("code = %q, want invalid_json", code)
	}
}

func TestDecodeRejectsATrailingSecondObject(t *testing.T) {
	_, err := decodeRequest(t, "application/json",
		`{"name":"db-1"}{"name":"db-2"}`)

	if code := codeOf(t, err); code != "invalid_json" {
		t.Fatalf("code = %q, want invalid_json", code)
	}
}

func TestDecodeRejectsAnEmptyBody(t *testing.T) {
	_, err := decodeRequest(t, "application/json", "")

	if code := codeOf(t, err); code != "empty_body" {
		t.Fatalf("code = %q, want empty_body", code)
	}
}

func TestDecodeRejectsAnUnexpectedMediaType(t *testing.T) {
	_, err := decodeRequest(t, "application/x-www-form-urlencoded", `name=db-1`)

	if code := codeOf(t, err); code != "unsupported_media_type" {
		t.Fatalf("code = %q, want unsupported_media_type", code)
	}
}

func TestDecodeAcceptsACharsetParameter(t *testing.T) {
	if _, err := decodeRequest(t, "application/json; charset=utf-8", `{"name":"db-1"}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDecodeCapsTheBodySize(t *testing.T) {
	oversized := `{"name":"` + strings.Repeat("a", int(MaxBodyBytes)+1) + `"}`

	_, err := decodeRequest(t, "application/json", oversized)

	if code := codeOf(t, err); code != "body_too_large" {
		t.Fatalf("code = %q, want body_too_large", code)
	}
}

func TestWriteSetsTheContentType(t *testing.T) {
	rec := httptest.NewRecorder()

	Write(rec, http.StatusCreated, map[string]string{"id": "tgt-abc"})

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("Content-Type = %q", got)
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["id"] != "tgt-abc" {
		t.Fatalf("body = %v", body)
	}
}

func TestWriteAcceptsNoBody(t *testing.T) {
	rec := httptest.NewRecorder()

	Write(rec, http.StatusNoContent, nil)

	if rec.Body.Len() != 0 {
		t.Fatalf("body = %q, want empty", rec.Body.String())
	}
}
