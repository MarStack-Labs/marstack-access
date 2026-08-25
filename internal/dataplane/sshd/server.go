package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

const (
	handshakeTimeout = 30 * time.Second
	maxAuthTries     = 3
	acceptBackoff    = 100 * time.Millisecond
)

var errNoIdentityOnConnection = errors.New("sshd: connection carries no resolved identity")

type Target struct {
	ID         string
	Name       string
	Address    string
	Port       int
	Principals []string
	HostKey    string
}

type Identities interface {
	ByPublicKey(ctx context.Context, fingerprint string) (authz.Identity, error)
}

type Policies interface {
	Authorize(ctx context.Context, id authz.Identity, targetID, principal string) error
}

type Grants interface {
	HasGrant(ctx context.Context, userID, targetID, principal string) error
}

type TargetLookup func(ctx context.Context, name string) (Target, error)

type SessionOpened struct {
	ID           string
	UserID       string
	UserName     string
	TargetID     string
	TargetName   string
	Principal    string
	CredentialID string
	RemoteAddr   string
	Recording    string
}

type SessionClosed struct {
	ExitCode      int
	Reason        string
	RecordedBytes int64
}

type SessionOpener func(ctx context.Context, s SessionOpened) error

type SessionCloser func(ctx context.Context, id string, s SessionClosed) error

type Config struct {
	Listen      string
	DataDir     string
	AdvertiseIP string
}

type Server struct {
	cfg          Config
	log          *slog.Logger
	identities   Identities
	targets      TargetLookup
	policies     Policies
	grants       Grants
	dialer       *dialer
	openSession  SessionOpener
	closeSession SessionCloser
	live         *registry
	now          func() time.Time
	sshConfig    *ssh.ServerConfig
	hostKey      ssh.PublicKey
}

func New(cfg Config, log *slog.Logger, identities Identities, targets TargetLookup,
	policies Policies, grants Grants, signer certs.Signer,
	opener SessionOpener, closer SessionCloser) (*Server, error) {
	hostKey, err := loadOrCreateHostKey(cfg.DataDir)
	if err != nil {
		return nil, err
	}

	s := &Server{
		cfg:          cfg,
		log:          log,
		identities:   identities,
		targets:      targets,
		policies:     policies,
		grants:       grants,
		dialer:       &dialer{signer: signer, advertiseIP: cfg.AdvertiseIP, now: time.Now},
		openSession:  opener,
		closeSession: closer,
		live:         newRegistry(),
		now:          time.Now,
		hostKey:      hostKey.PublicKey(),
	}

	s.sshConfig = &ssh.ServerConfig{
		MaxAuthTries:      maxAuthTries,
		PublicKeyCallback: s.authenticate,
	}
	s.sshConfig.AddHostKey(hostKey)

	return s, nil
}

func (s *Server) HostKeyFingerprint() string {
	return ssh.FingerprintSHA256(s.hostKey)
}

func (s *Server) Kill(sessionID string) bool {
	return s.live.kill(sessionID)
}

func (s *Server) LiveSessions() int {
	return s.live.count()
}

func (s *Server) authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	fingerprint := ssh.FingerprintSHA256(key)

	id, err := s.identities.ByPublicKey(context.Background(), fingerprint)
	if err != nil {
		s.log.Warn("ssh authentication refused",
			"remote", conn.RemoteAddr().String(),
			"fingerprint", fingerprint,
			"reason", fault.From(err).Code)
		return nil, errAuthenticationFailed
	}

	return &ssh.Permissions{Extensions: map[string]string{
		extUserID:       id.UserID,
		extUserName:     id.Name,
		extRole:         id.Role,
		extCredentialID: id.CredentialID,
	}}, nil
}

var errAuthenticationFailed = errors.New("permission denied")

const (
	extUserID       = "marac-user-id"
	extUserName     = "marac-user-name"
	extRole         = "marac-role"
	extCredentialID = "marac-credential-id"
)

func identityOf(conn *ssh.ServerConn) (authz.Identity, error) {
	if conn.Permissions == nil || conn.Permissions.Extensions == nil {
		return authz.Identity{}, errNoIdentityOnConnection
	}

	ext := conn.Permissions.Extensions
	id := authz.Identity{
		UserID:       ext[extUserID],
		Name:         ext[extUserName],
		Role:         ext[extRole],
		CredentialID: ext[extCredentialID],
	}
	if id.UserID == "" {
		return authz.Identity{}, errNoIdentityOnConnection
	}
	return id, nil
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen ssh: %w", err)
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	s.log.Info("data plane listening",
		"addr", s.cfg.Listen, "host_key", s.HostKeyFingerprint())

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.log.Error("ssh accept failed", "error", err.Error())
			time.Sleep(acceptBackoff)
			continue
		}

		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	defer raw.Close()

	remote := raw.RemoteAddr().String()

	if err := raw.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.log.Error("ssh deadline failed", "remote", remote, "error", err.Error())
		return
	}

	conn, channels, requests, err := ssh.NewServerConn(raw, s.sshConfig)
	if err != nil {
		s.log.Warn("ssh handshake failed", "remote", remote, "error", err.Error())
		return
	}
	defer conn.Close()

	if err := raw.SetDeadline(time.Time{}); err != nil {
		s.log.Error("ssh deadline clear failed", "remote", remote, "error", err.Error())
		return
	}

	id, err := identityOf(conn)
	if err != nil {
		s.log.Error("ssh connection without identity", "remote", remote)
		return
	}

	s.log.Info("ssh connection established",
		"remote", remote, "user", id.Name, "role", id.Role,
		"credential", id.CredentialID, "destination", conn.User())

	go s.refuseGlobalRequests(requests, remote)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			s.log.Warn("ssh channel refused",
				"remote", remote, "user", id.Name, "type", newChannel.ChannelType())
			if err := newChannel.Reject(ssh.Prohibited, "only session channels are permitted"); err != nil {
				s.log.Error("ssh channel reject failed", "error", err.Error())
			}
			continue
		}

		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			s.log.Error("ssh channel accept failed", "remote", remote, "error", err.Error())
			continue
		}

		go s.serveSession(ctx, conn, id, channel, channelRequests)
	}
}

func (s *Server) refuseGlobalRequests(requests <-chan *ssh.Request, remote string) {
	for req := range requests {
		if req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward" {
			s.log.Warn("ssh port forwarding refused", "remote", remote, "type", req.Type)
		}
		if req.WantReply {
			if err := req.Reply(false, nil); err != nil {
				s.log.Error("ssh request reply failed", "error", err.Error())
			}
		}
	}
}
