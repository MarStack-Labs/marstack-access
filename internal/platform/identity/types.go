package identity

import (
	"errors"
	"time"
)

const (
	userIDPrefix  = "usr"
	tokenIDPrefix = "tok"

	bootstrapUserName = "admin"
	maxTokenTTL       = 365 * 24 * time.Hour
)

var (
	errNameTaken     = errors.New("user name already registered")
	errSelectorTaken = errors.New("token selector already issued")
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

type CreateUserInput struct {
	Name string
	Role string
}
