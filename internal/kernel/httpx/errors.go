package httpx

import (
	"log/slog"
	"net/http"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func statusFor(kind fault.Kind) int {
	switch kind {
	case fault.KindInvalid:
		return http.StatusBadRequest
	case fault.KindNotFound:
		return http.StatusNotFound
	case fault.KindConflict:
		return http.StatusConflict
	case fault.KindUnauthenticated:
		return http.StatusUnauthorized
	case fault.KindForbidden:
		return http.StatusForbidden
	case fault.KindUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

type Handler func(http.ResponseWriter, *http.Request) error

func Wrap(log *slog.Logger, h Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}

		f := fault.From(err)
		status := statusFor(f.Kind)

		if status >= http.StatusInternalServerError {
			log.ErrorContext(r.Context(), "request failed",
				"method", r.Method,
				"path", r.URL.Path,
				"request_id", RequestIDFrom(r.Context()),
				"error", f.Error(),
			)
		}

		Write(w, status, map[string]any{
			"error": map[string]string{
				"code":    f.Code,
				"message": f.Message,
			},
		})
	}
}
