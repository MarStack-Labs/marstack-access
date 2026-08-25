package approval

import (
	"time"
)

const (
	idPrefix       = "req"
	userIDPrefix   = "usr"
	targetIDPrefix = "tgt"

	StatePending   = "pending"
	StateApproved  = "approved"
	StateDenied    = "denied"
	StateCancelled = "cancelled"
	StateExpired   = "expired"

	pendingWindow   = 24 * time.Hour
	defaultGrantTTL = time.Hour
	maxGrantTTL     = 12 * time.Hour
	maxReasonLen    = 500
)

type Request struct {
	ID               string
	RequesterID      string
	TargetID         string
	Principal        string
	Reason           string
	State            string
	GrantTTL         time.Duration
	CreatedAt        time.Time
	RequestExpiresAt time.Time
	DecidedBy        string
	DecidedAt        time.Time
	GrantExpiresAt   time.Time
}

func (r Request) effectiveState(now time.Time) string {
	switch r.State {
	case StatePending:
		if !now.Before(r.RequestExpiresAt) {
			return StateExpired
		}
	case StateApproved:
		if !now.Before(r.GrantExpiresAt) {
			return StateExpired
		}
	}
	return r.State
}

func (r Request) grantsAccess(now time.Time) bool {
	return r.State == StateApproved && now.Before(r.GrantExpiresAt)
}

type CreateInput struct {
	TargetID  string
	Principal string
	Reason    string
	GrantTTL  time.Duration
}

type GrantQuery struct {
	UserID    string
	TargetID  string
	Principal string
}

type Grant struct {
	Active    bool
	RequestID string
	ExpiresAt time.Time
	Reason    string
}
