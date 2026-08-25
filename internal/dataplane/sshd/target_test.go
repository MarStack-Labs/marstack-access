package sshd

import (
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
)

const targetBanner = "welcome to db-1\r\n"

type fakeTarget struct {
	addr    string
	hostKey ssh.Signer

	mu       sync.Mutex
	users    []string
	certs    []*ssh.Certificate
	sessions int
}

func (f *fakeTarget) record(user string, cert *ssh.Certificate) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.users = append(f.users, user)
	f.certs = append(f.certs, cert)
}

func (f *fakeTarget) countSession() {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sessions++
}

func (f *fakeTarget) seen() ([]string, []*ssh.Certificate, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string{}, f.users...), append([]*ssh.Certificate{}, f.certs...), f.sessions
}

func (f *fakeTarget) hostKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.hostKey.PublicKey())))
}

func startFakeTarget(t *testing.T, trusted *certs.FileSigner) *fakeTarget {
	t.Helper()

	target := &fakeTarget{hostKey: newKeyPair(t)}

	checker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(trusted.PublicKey())
		},
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := checker.Authenticate(conn, key)
			if err != nil {
				return nil, err
			}
			cert, _ := key.(*ssh.Certificate)
			target.record(conn.User(), cert)
			return permissions, nil
		},
	}
	config.AddHostKey(target.hostKey)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			go target.serve(raw, config)
		}
	}()

	target.addr = listener.Addr().String()
	return target
}

func (f *fakeTarget) serve(raw net.Conn, config *ssh.ServerConfig) {
	defer raw.Close()

	conn, channels, requests, err := ssh.NewServerConn(raw, config)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(requests)

	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.Prohibited, "")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go f.echoShell(channel, channelRequests)
	}
}

func (f *fakeTarget) echoShell(channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()

	started := false
	for req := range requests {
		switch req.Type {
		case "pty-req", "env", "window-change":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell", "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			started = true
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}

		if !started {
			continue
		}

		f.countSession()
		_, _ = io.WriteString(channel, targetBanner)
		_, _ = io.Copy(channel, channel)
		sendExitStatus(channel, 0)
		return
	}
}

func fakeTargetEntry(t *testing.T, target *fakeTarget) Target {
	t.Helper()

	host, port, err := net.SplitHostPort(target.addr)
	if err != nil {
		t.Fatalf("split target addr: %v", err)
	}

	parsed, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	return Target{
		ID:         dbTargetID,
		Name:       "db-1",
		Address:    host,
		Port:       parsed,
		Principals: []string{"deploy", "postgres"},
		HostKey:    target.hostKeyLine(),
	}
}

func newTestCA(t *testing.T) *certs.FileSigner {
	t.Helper()

	path := t.TempDir() + "/ca"
	if _, err := certs.Create(path); err != nil {
		t.Fatalf("create ca: %v", err)
	}
	signer, err := certs.Load(path)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	return signer
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
