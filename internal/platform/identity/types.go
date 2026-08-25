package identity

import (
	"errors"
	"time"
)

const (
	userIDPrefix  = "usr"
	tokenIDPrefix = "tok"
	keyIDPrefix   = "key"

	bootstrapUserName = "admin"
	maxTokenTTL       = 365 * 24 * time.Hour
)

var (
	errNameTaken        = errors.New("user name already registered")
	errSelectorTaken    = errors.New("token selector already issued")
	errKeyNameTaken     = errors.New("key name already used by this user")
	errFingerprintTaken = errors.New("public key already registered")
)

type User struct {
	ID        string
	Name      string
	Role      string
	Disabled  bool
	CreatedAt time.Time
}

type Token struct {
	ID        string
	UserID    string
	Selector  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func (t Token) expired(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

type Key struct {
	ID          string
	UserID      string
	Name        string
	Type        string
	Fingerprint string
	Authorized  string
	CreatedAt   time.Time
}

type AddKeyInput struct {
	Name      string
	PublicKey string
}

type CreateUserInput struct {
	Name string
	Role string
}
