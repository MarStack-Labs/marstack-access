package sshd

import (
	"strings"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

type destination struct {
	principal string
	target    string
}

func parseDestination(user string) (destination, error) {
	principal, target, found := strings.Cut(user, ":")
	if !found {
		return destination{}, fault.Invalid("invalid_destination",
			"connect as <principal>:<target>, for example deploy:db-1")
	}
	if strings.Contains(target, ":") {
		return destination{}, fault.Invalid("invalid_destination",
			"the destination carries more than one colon")
	}

	if err := validate.Principal("principal", principal); err != nil {
		return destination{}, err
	}
	if err := validate.Name("target", target); err != nil {
		return destination{}, err
	}

	return destination{principal: principal, target: target}, nil
}
