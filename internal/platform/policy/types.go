package policy

import (
	"errors"
	"time"
)

const (
	idPrefix       = "pol"
	userIDPrefix   = "usr"
	targetIDPrefix = "tgt"

	SubjectUser = "user"
	SubjectRole = "role"

	maxPrincipals = 32
)

var subjectKinds = []string{SubjectUser, SubjectRole}

var errNameTaken = errors.New("policy name already registered")

type Policy struct {
	ID          string
	Name        string
	SubjectKind string
	SubjectID   string
	TargetID    string
	Principals  []string
	CreatedAt   time.Time
}

type CreateInput struct {
	Name        string
	SubjectKind string
	SubjectID   string
	TargetID    string
	Principals  []string
}

type Request struct {
	UserID    string
	Role      string
	TargetID  string
	Principal string
}

type Decision struct {
	Allowed  bool
	PolicyID string
	Reason   string
}
