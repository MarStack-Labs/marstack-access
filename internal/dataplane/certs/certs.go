package certs

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/validate"
)

const MaxTTL = 5 * time.Minute

type Request struct {
	PublicKey     ssh.PublicKey
	KeyID         string
	Principal     string
	ValidAfter    time.Time
	ValidBefore   time.Time
	SourceAddress string
}

type Signer interface {
	Sign(ctx context.Context, req Request) (*ssh.Certificate, error)
}

func Check(req Request) error {
	if req.PublicKey == nil {
		return fault.Invalid("invalid_certificate_request", "a public key to sign is required")
	}
	if req.KeyID == "" {
		return fault.Invalid("invalid_certificate_request",
			"a key id is required: it is the only label an audit reader has for this certificate")
	}
	if err := validate.Principal("principal", req.Principal); err != nil {
		return err
	}
	if req.SourceAddress == "" {
		return fault.Invalid("invalid_certificate_request",
			"a source address is required so a leaked certificate is useless elsewhere")
	}
	if net.ParseIP(req.SourceAddress) == nil {
		return fault.Invalid("invalid_certificate_request",
			fmt.Sprintf("the source address %q is not an IP address", req.SourceAddress))
	}
	if req.ValidAfter.Unix() <= 0 || req.ValidBefore.Unix() <= 0 {
		return fault.Invalid("invalid_certificate_request",
			"the validity window must lie after the Unix epoch")
	}
	if !req.ValidAfter.Before(req.ValidBefore) {
		return fault.Invalid("invalid_certificate_request",
			"the validity window must start before it ends")
	}
	if ttl := req.ValidBefore.Sub(req.ValidAfter); ttl > MaxTTL {
		return fault.Invalid("invalid_certificate_request",
			fmt.Sprintf("a certificate may live at most %s, this one asks for %s", MaxTTL, ttl))
	}
	return nil
}

func unixSeconds(t time.Time) uint64 {
	seconds := t.Unix()
	if seconds < 0 {
		return 0
	}
	return uint64(seconds)
}

func hostPrefix(address string) string {
	if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
		return address + "/128"
	}
	return address + "/32"
}

func build(req Request, serial uint64) *ssh.Certificate {
	return &ssh.Certificate{
		Key:             req.PublicKey,
		Serial:          serial,
		CertType:        ssh.UserCert,
		KeyId:           req.KeyID,
		ValidPrincipals: []string{req.Principal},
		ValidAfter:      unixSeconds(req.ValidAfter),
		ValidBefore:     unixSeconds(req.ValidBefore),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{
				"source-address": hostPrefix(req.SourceAddress),
			},
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
}
