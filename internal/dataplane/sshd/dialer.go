package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const (
	certLifetime  = 2 * time.Minute
	targetTimeout = 20 * time.Second
)

type dialer struct {
	signer      certs.Signer
	advertiseIP string
	now         func() time.Time
}

func (d *dialer) dial(ctx context.Context, sessionID string, target Target, principal string) (*ssh.Client, error) {
	if d.signer == nil {
		return nil, fault.Unavailable("no_signer",
			"this gateway has no signing authority configured, so it cannot authenticate to a target")
	}

	expected, err := expectedHostKey(target)
	if err != nil {
		return nil, err
	}

	address := net.JoinHostPort(target.Address, strconv.Itoa(target.Port))

	source, err := d.sourceAddress(address)
	if err != nil {
		return nil, err
	}

	ephemeral, err := newEphemeralKey()
	if err != nil {
		return nil, err
	}

	issued := d.now()
	cert, err := d.signer.Sign(ctx, certs.Request{
		PublicKey:     ephemeral.PublicKey(),
		KeyID:         sessionID,
		Principal:     principal,
		ValidAfter:    issued.Add(-clockSkew),
		ValidBefore:   issued.Add(certLifetime),
		SourceAddress: source,
	})
	if err != nil {
		return nil, err
	}

	certSigner, err := ssh.NewCertSigner(cert, ephemeral)
	if err != nil {
		return nil, fault.Internal(fmt.Errorf("build cert signer: %w", err))
	}

	client, err := ssh.Dial("tcp", address, &ssh.ClientConfig{
		User:            principal,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(expected),
		Timeout:         targetTimeout,
	})
	if err != nil {
		return nil, fault.Unavailable("target_unreachable",
			fmt.Sprintf("could not open a session on %s as %s: %v", target.Name, principal, err))
	}

	return client, nil
}

const clockSkew = 30 * time.Second

func expectedHostKey(target Target) (ssh.PublicKey, error) {
	if target.HostKey == "" {
		return nil, fault.Forbidden("host_key_not_pinned",
			fmt.Sprintf("target %q has no pinned host key, so its identity cannot be verified", target.Name))
	}

	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(target.HostKey))
	if err != nil {
		return nil, fault.Internal(fmt.Errorf("parse pinned host key for %s: %w", target.Name, err))
	}
	return key, nil
}

func (d *dialer) sourceAddress(target string) (string, error) {
	if d.advertiseIP != "" {
		return d.advertiseIP, nil
	}

	probe, err := net.Dial("udp", target)
	if err != nil {
		return "", fault.Unavailable("source_address_unknown",
			"could not work out which address this gateway reaches the target from; set --advertise-ip")
	}
	defer probe.Close()

	host, _, err := net.SplitHostPort(probe.LocalAddr().String())
	if err != nil {
		return "", fault.Internal(fmt.Errorf("split local addr: %w", err))
	}
	return host, nil
}

func newEphemeralKey() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fault.Internal(fmt.Errorf("generate session key: %w", err))
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fault.Internal(fmt.Errorf("session signer: %w", err))
	}
	return signer, nil
}
