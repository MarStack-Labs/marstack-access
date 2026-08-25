package session

import (
	"context"
	"time"
)

const (
	idPrefix       = "ses"
	userIDPrefix   = "usr"
	targetIDPrefix = "tgt"

	maxReasonLen = 500

	ReasonGatewayRestarted = "gateway restarted while this session was open"
)

type Terminator interface {
	Kill(sessionID string) bool
}

type TerminatorFunc func(sessionID string) bool

func (f TerminatorFunc) Kill(sessionID string) bool {
	return f(sessionID)
}

type Session struct {
	ID            string
	UserID        string
	UserName      string
	TargetID      string
	TargetName    string
	Principal     string
	CredentialID  string
	RemoteAddr    string
	Recording     string
	StartedAt     time.Time
	EndedAt       time.Time
	ExitCode      int
	Reason        string
	RecordedBytes int64
}

func (s Session) active() bool {
	return s.EndedAt.IsZero()
}

type OpenInput struct {
	ID           string
	UserID       string
	UserName     string
	TargetID     string
	TargetName   string
	Principal    string
	CredentialID string
	RemoteAddr   string
	Recording    string
}

type CloseInput struct {
	ExitCode      int
	Reason        string
	RecordedBytes int64
}

type Opener func(ctx context.Context, in OpenInput) error

type Closer func(ctx context.Context, id string, in CloseInput) error
