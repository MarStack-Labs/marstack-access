package target

import (
	"errors"
	"time"
)

const (
	idPrefix      = "tgt"
	defaultPort   = 22
	maxPrincipals = 32
)

var (
	errNameTaken     = errors.New("target name already registered")
	errAlreadyPinned = errors.New("target already has a pinned host key")
)

type Target struct {
	ID          string
	Name        string
	Address     string
	Port        int
	Principals  []string
	HostKey     string
	Fingerprint string
	CreatedAt   time.Time
}

type TrustInput struct {
	HostKey string
	Replace bool
}

type RegisterInput struct {
	Name       string
	Address    string
	Port       int
	Principals []string
}
