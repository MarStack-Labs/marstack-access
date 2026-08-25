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

var errNameTaken = errors.New("target name already registered")

type Target struct {
	ID         string
	Name       string
	Address    string
	Port       int
	Principals []string
	CreatedAt  time.Time
}

type RegisterInput struct {
	Name       string
	Address    string
	Port       int
	Principals []string
}
