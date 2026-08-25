package validate

import (
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const (
	maxNameLen      = 63
	maxAddressLen   = 253
	maxPrincipalLen = 32
)

var (
	namePattern      = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	hostnamePattern  = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
	principalPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

func invalid(field, format string, args ...any) error {
	return fault.Invalid("invalid_"+field, fmt.Sprintf(format, args...))
}

func Name(field, value string) error {
	if value == "" {
		return invalid(field, "%s must not be empty", field)
	}
	if len(value) > maxNameLen {
		return invalid(field, "%s must be at most %d characters", field, maxNameLen)
	}
	if !namePattern.MatchString(value) {
		return invalid(field,
			"%s must be lowercase letters, digits, or hyphens, starting and ending with a letter or digit",
			field)
	}
	return nil
}

func Address(field, value string) error {
	if value == "" {
		return invalid(field, "%s must not be empty", field)
	}
	if len(value) > maxAddressLen {
		return invalid(field, "%s must be at most %d characters", field, maxAddressLen)
	}
	if net.ParseIP(value) != nil {
		return nil
	}
	if !hostnamePattern.MatchString(strings.ToLower(value)) {
		return invalid(field, "%s must be an IP address or a dotted hostname", field)
	}
	if strings.ToLower(value) != value {
		return invalid(field,
			"%s must be lowercase so one host cannot be registered twice under different casing", field)
	}
	return nil
}

func Port(field string, value int) error {
	if value < 1 || value > 65535 {
		return invalid(field, "%s must be between 1 and 65535", field)
	}
	return nil
}

func OneOf(field, value string, allowed ...string) error {
	for _, a := range allowed {
		if value == a {
			return nil
		}
	}
	return invalid(field, "%s must be one of: %s", field, strings.Join(allowed, ", "))
}

func Principal(field, value string) error {
	if value == "" {
		return invalid(field, "%s must not be empty", field)
	}
	if len(value) > maxPrincipalLen {
		return invalid(field, "%s must be at most %d characters", field, maxPrincipalLen)
	}
	if !principalPattern.MatchString(value) {
		return invalid(field,
			"%s must be a lowercase account name starting with a letter or underscore", field)
	}
	return nil
}
