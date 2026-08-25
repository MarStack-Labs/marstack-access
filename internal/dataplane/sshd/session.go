package sshd

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const (
	exitAuthorized = 0
	exitRefused    = 1

	startTimeout = 30 * time.Second
)

type resolved struct {
	destination destination
	target      Target
}

func (s *Server) serveSession(ctx context.Context, conn *ssh.ServerConn, id authz.Identity,
	channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	remote := conn.RemoteAddr().String()
	res, resolveErr := s.resolve(ctx, id, conn.User())

	if resolveErr != nil {
		s.log.Warn("ssh session refused",
			"remote", remote, "user", id.Name, "destination", conn.User(),
			"code", fault.From(resolveErr).Code)
	} else {
		s.log.Info("ssh session authorized",
			"remote", remote, "user", id.Name,
			"target", res.target.Name, "principal", res.destination.principal)
	}

	if !s.awaitStart(remote, id, requests) {
		return
	}

	if resolveErr != nil {
		f := fault.From(resolveErr)
		writeLine(channel.Stderr(), "marstack-access: refused")
		writeLine(channel.Stderr(), "  "+f.Message)
		sendExitStatus(channel, exitRefused)
		return
	}

	writeLine(channel, "marstack-access: authorized")
	writeLine(channel, fmt.Sprintf("  user       %s (%s)", id.Name, id.Role))
	writeLine(channel, fmt.Sprintf("  target     %s at %s:%d",
		res.target.Name, res.target.Address, res.target.Port))
	writeLine(channel, fmt.Sprintf("  principal  %s", res.destination.principal))
	writeLine(channel, "")
	writeLine(channel, "The target connection is not implemented yet, so this session ends here.")
	sendExitStatus(channel, exitAuthorized)
}

func (s *Server) awaitStart(remote string, id authz.Identity, requests <-chan *ssh.Request) bool {
	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return false
			}

			switch req.Type {
			case "shell", "exec":
				reply(req, true)
				return true
			case "pty-req", "env", "window-change", "signal":
				reply(req, true)
			default:
				s.log.Warn("ssh session request refused",
					"remote", remote, "user", id.Name, "type", req.Type)
				reply(req, false)
			}

		case <-deadline.C:
			s.log.Warn("ssh session never started", "remote", remote, "user", id.Name)
			return false
		}
	}
}

func (s *Server) resolve(ctx context.Context, id authz.Identity, user string) (resolved, error) {
	dest, err := parseDestination(user)
	if err != nil {
		return resolved{}, err
	}

	target, err := s.targets(ctx, dest.target)
	if err != nil {
		return resolved{}, err
	}

	if !accepts(target.Principals, dest.principal) {
		return resolved{}, fault.Forbidden("principal_not_accepted",
			fmt.Sprintf("target %q does not accept the principal %q", target.Name, dest.principal))
	}

	if target.HostKey == "" {
		return resolved{}, fault.Forbidden("host_key_not_pinned",
			fmt.Sprintf("target %q has no pinned host key, so its identity cannot be verified", target.Name))
	}

	if err := s.policies.Authorize(ctx, id, target.ID, dest.principal); err != nil {
		return resolved{}, err
	}

	if err := s.grants.HasGrant(ctx, id.UserID, target.ID, dest.principal); err != nil {
		return resolved{}, err
	}

	return resolved{destination: dest, target: target}, nil
}

func accepts(principals []string, principal string) bool {
	for _, candidate := range principals {
		if candidate == principal {
			return true
		}
	}
	return false
}

func reply(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func writeLine(w io.Writer, line string) {
	_, _ = io.WriteString(w, line+"\r\n")
}

func sendExitStatus(channel ssh.Channel, code uint32) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, code)
	_, _ = channel.SendRequest("exit-status", false, payload)
}
