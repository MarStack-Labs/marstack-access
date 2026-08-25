package fault

import (
	"errors"
	"fmt"
)

type Kind int

const (
	KindInternal Kind = iota
	KindInvalid
	KindNotFound
	KindConflict
	KindUnauthenticated
	KindForbidden
	KindUnavailable
)

type Fault struct {
	Kind    Kind
	Code    string
	Message string
	cause   error
}

func (f *Fault) Error() string {
	if f.cause != nil {
		return fmt.Sprintf("%s: %s: %v", f.Code, f.Message, f.cause)
	}
	return fmt.Sprintf("%s: %s", f.Code, f.Message)
}

func (f *Fault) Unwrap() error {
	return f.cause
}

func newFault(kind Kind, code, message string) *Fault {
	return &Fault{Kind: kind, Code: code, Message: message}
}

func Invalid(code, message string) *Fault {
	return newFault(KindInvalid, code, message)
}

func NotFound(code, message string) *Fault {
	return newFault(KindNotFound, code, message)
}

func Conflict(code, message string) *Fault {
	return newFault(KindConflict, code, message)
}

func Unauthenticated(code, message string) *Fault {
	return newFault(KindUnauthenticated, code, message)
}

func Forbidden(code, message string) *Fault {
	return newFault(KindForbidden, code, message)
}

func Unavailable(code, message string) *Fault {
	return newFault(KindUnavailable, code, message)
}

func Internal(cause error) *Fault {
	return &Fault{
		Kind:    KindInternal,
		Code:    "internal_error",
		Message: "an internal error occurred",
		cause:   cause,
	}
}

func From(err error) *Fault {
	var f *Fault
	if errors.As(err, &f) {
		return f
	}
	return Internal(err)
}
