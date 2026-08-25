package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const MaxBodyBytes int64 = 1 << 20

func Write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}

func Decode[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var target T

	if ct := r.Header.Get("Content-Type"); ct != "" {
		if mediaType := strings.TrimSpace(strings.Split(ct, ";")[0]); mediaType != "application/json" {
			return target, fault.Invalid("unsupported_media_type", "Content-Type must be application/json")
		}
	}

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&target); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return target, fault.Invalid("body_too_large", "request body exceeds the size limit")
		}
		if errors.Is(err, io.EOF) {
			return target, fault.Invalid("empty_body", "request body must not be empty")
		}
		return target, fault.Invalid("invalid_json", "request body is not valid JSON for this endpoint")
	}

	if err := dec.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return target, fault.Invalid("invalid_json", "request body must contain exactly one JSON object")
	}

	return target, nil
}
