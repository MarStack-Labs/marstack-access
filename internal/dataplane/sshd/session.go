package sshd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/ids"
)

const (
	exitRefused  = 1
	startTimeout = 30 * time.Second
	idPrefix     = "ses"
)

type resolved struct {
	destination destination
	target      Target
}

type ptyRequest struct {
	requested bool
	term      string
	cols      int
	rows      int
}

type startRequest struct {
	kind    string
	command string
	pty     ptyRequest
}

func (s *Server) serveSession(ctx context.Context, conn *ssh.ServerConn, id authz.Identity,
	channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	remote := conn.RemoteAddr().String()
	sessionID := ids.New(idPrefix)

	res, resolveErr := s.resolve(ctx, id, conn.User())
	if resolveErr != nil {
		s.log.Warn("ssh session refused",
			"session", sessionID, "remote", remote, "user", id.Name,
			"destination", conn.User(), "code", fault.From(resolveErr).Code)
	}

	start, forwards, started := s.awaitStart(sessionID, remote, id, requests)
	if !started {
		return
	}

	if resolveErr != nil {
		s.refuse(channel, resolveErr)
		return
	}

	s.proxy(ctx, sessionID, remote, id, res, start, forwards, channel)
}

func (s *Server) refuse(channel ssh.Channel, err error) {
	f := fault.From(err)
	writeLine(channel.Stderr(), "marstack-access: refused")
	writeLine(channel.Stderr(), "  "+f.Message)
	sendExitStatus(channel, exitRefused)
}

func (s *Server) awaitStart(sessionID, remote string, id authz.Identity,
	requests <-chan *ssh.Request) (startRequest, <-chan *ssh.Request, bool) {
	deadline := time.NewTimer(startTimeout)
	defer deadline.Stop()

	start := startRequest{pty: ptyRequest{term: defaultTerm, cols: defaultCols, rows: defaultRows}}

	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return startRequest{}, nil, false
			}

			switch req.Type {
			case "pty-req":
				start.pty = parsePtyRequest(req.Payload)
				reply(req, true)
			case "shell":
				start.kind = "shell"
				reply(req, true)
				return start, requests, true
			case "exec":
				start.kind = "exec"
				start.command = parseExecRequest(req.Payload)
				reply(req, true)
				return start, requests, true
			case "env", "window-change", "signal":
				reply(req, true)
			default:
				s.log.Warn("ssh session request refused",
					"session", sessionID, "remote", remote, "user", id.Name, "type", req.Type)
				reply(req, false)
			}

		case <-deadline.C:
			s.log.Warn("ssh session never started",
				"session", sessionID, "remote", remote, "user", id.Name)
			return startRequest{}, nil, false
		}
	}
}

func (s *Server) proxy(ctx context.Context, sessionID, remote string, id authz.Identity,
	res resolved, start startRequest, forwards <-chan *ssh.Request, channel ssh.Channel) {
	rec, err := newRecorder(s.cfg.DataDir, sessionID, start.pty, s.now)
	if err != nil {
		s.log.Error("ssh recording could not be opened",
			"session", sessionID, "user", id.Name, "error", err.Error())
		s.refuse(channel, fault.Unavailable("recording_unavailable",
			"this session cannot be recorded, so it will not be opened"))
		return
	}
	defer rec.Close()

	client, err := s.dialer.dial(ctx, sessionID, res.target, res.destination.principal)
	if err != nil {
		s.log.Warn("ssh target dial failed",
			"session", sessionID, "user", id.Name, "target", res.target.Name,
			"code", fault.From(err).Code)
		s.refuse(channel, err)
		return
	}
	defer client.Close()

	targetSession, err := client.NewSession()
	if err != nil {
		s.refuse(channel, fault.Unavailable("target_session_failed",
			fmt.Sprintf("the target refused a session: %v", err)))
		return
	}
	defer targetSession.Close()

	s.log.Info("ssh session opened",
		"session", sessionID, "remote", remote, "user", id.Name, "role", id.Role,
		"credential", id.CredentialID, "target", res.target.Name,
		"principal", res.destination.principal, "recording", rec.Path())

	code, reason := s.pump(ctx, sessionID, start, forwards, channel, targetSession, rec)

	s.log.Info("ssh session closed",
		"session", sessionID, "user", id.Name, "target", res.target.Name,
		"principal", res.destination.principal, "exit", code,
		"reason", reason, "recorded_bytes", rec.Recorded())

	sendExitStatus(channel, code)
}

func (s *Server) pump(ctx context.Context, sessionID string, start startRequest,
	forwards <-chan *ssh.Request, channel ssh.Channel, targetSession *ssh.Session,
	rec *recorder) (uint32, string) {
	if start.pty.requested {
		if err := targetSession.RequestPty(start.pty.term, start.pty.rows, start.pty.cols,
			ssh.TerminalModes{}); err != nil {
			return exitRefused, "pty refused by target"
		}
	}

	targetStdin, err := targetSession.StdinPipe()
	if err != nil {
		return exitRefused, "target stdin unavailable"
	}
	targetStdout, err := targetSession.StdoutPipe()
	if err != nil {
		return exitRefused, "target stdout unavailable"
	}
	targetStderr, err := targetSession.StderrPipe()
	if err != nil {
		return exitRefused, "target stderr unavailable"
	}

	if err := s.begin(targetSession, start); err != nil {
		return exitRefused, "target refused to start the session"
	}

	go forwardWindowChanges(ctx, forwards, targetSession)

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetStdin, channel)
		_ = targetStdin.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(channel, rec), targetStdout)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(io.MultiWriter(channel.Stderr(), rec), targetStderr)
	}()

	done := make(chan error, 1)
	go func() { done <- targetSession.Wait() }()

	select {
	case waitErr := <-done:
		wg.Wait()
		return exitCodeOf(waitErr)
	case <-ctx.Done():
		_ = targetSession.Signal(ssh.SIGHUP)
		_ = targetSession.Close()
		return exitRefused, "gateway shutting down"
	}
}

func (s *Server) begin(targetSession *ssh.Session, start startRequest) error {
	if start.kind == "exec" {
		return targetSession.Start(start.command)
	}
	return targetSession.Shell()
}

func exitCodeOf(waitErr error) (uint32, string) {
	if waitErr == nil {
		return 0, "target session ended"
	}

	var exitErr *ssh.ExitError
	if errors.As(waitErr, &exitErr) {
		return boundedExitStatus(exitErr.ExitStatus()), "target exit status"
	}
	return exitRefused, waitErr.Error()
}

func boundedExitStatus(status int) uint32 {
	if status < 0 || status > 255 {
		return exitRefused
	}
	return uint32(status)
}

func forwardWindowChanges(ctx context.Context, requests <-chan *ssh.Request, targetSession *ssh.Session) {
	for {
		select {
		case req, ok := <-requests:
			if !ok {
				return
			}
			if req.Type == "window-change" {
				pty := parsePtyDimensions(req.Payload)
				_ = targetSession.WindowChange(pty.rows, pty.cols)
			}
			reply(req, req.Type == "window-change")
		case <-ctx.Done():
			return
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
