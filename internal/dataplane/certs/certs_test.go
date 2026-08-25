package certs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func newKeyPair(t *testing.T) ssh.Signer {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func newSignerKey(t *testing.T) ssh.PublicKey {
	t.Helper()

	return newKeyPair(t).PublicKey()
}

func newCA(t *testing.T) *FileSigner {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca")
	if _, err := Create(path); err != nil {
		t.Fatalf("create ca: %v", err)
	}
	signer, err := Load(path)
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	return signer
}

var testNow = time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)

func checkerFor(ca *FileSigner, at time.Time) *ssh.CertChecker {
	return &ssh.CertChecker{
		Clock: func() time.Time { return at },
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(ca.PublicKey())
		},
	}
}

func validRequest(t *testing.T) Request {
	t.Helper()

	now := testNow
	return Request{
		PublicKey:     newSignerKey(t),
		KeyID:         "ses-0000000000001",
		Principal:     "deploy",
		ValidAfter:    now,
		ValidBefore:   now.Add(time.Minute),
		SourceAddress: "10.0.0.1",
	}
}

func mustSign(t *testing.T, s *FileSigner, req Request) *ssh.Certificate {
	t.Helper()

	cert, err := s.Sign(context.Background(), req)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return cert
}

func TestACertificateCarriesExactlyOnePrincipal(t *testing.T) {
	cert := mustSign(t, newCA(t), validRequest(t))

	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "deploy" {
		t.Fatalf("principals = %v, want exactly [deploy]", cert.ValidPrincipals)
	}
}

func TestACertificateGrantsNoForwarding(t *testing.T) {
	cert := mustSign(t, newCA(t), validRequest(t))

	forbidden := []string{
		"permit-port-forwarding",
		"permit-agent-forwarding",
		"permit-X11-forwarding",
		"permit-user-rc",
	}

	for _, extension := range forbidden {
		if _, present := cert.Permissions.Extensions[extension]; present {
			t.Errorf("the certificate carries %q. OpenSSH grants these by default when a cert is built carelessly, and each one is a capability on the target that no policy in this platform describes",
				extension)
		}
	}

	if _, present := cert.Permissions.Extensions["permit-pty"]; !present {
		t.Error("permit-pty is absent, so an interactive session would fail")
	}
	if len(cert.Permissions.Extensions) != 1 {
		t.Errorf("extensions = %v, want permit-pty alone", cert.Permissions.Extensions)
	}
}

func TestACertificateIsPinnedToItsSourceAddress(t *testing.T) {
	cert := mustSign(t, newCA(t), validRequest(t))

	if got := cert.Permissions.CriticalOptions["source-address"]; got != "10.0.0.1/32" {
		t.Fatalf("source-address = %q, want 10.0.0.1/32: a leaked certificate must be useless from anywhere else", got)
	}
}

func TestAnIPv6SourceAddressGetsAHostPrefix(t *testing.T) {
	req := validRequest(t)
	req.SourceAddress = "2001:db8::1"

	cert := mustSign(t, newCA(t), req)

	if got := cert.Permissions.CriticalOptions["source-address"]; got != "2001:db8::1/128" {
		t.Fatalf("source-address = %q, want a /128 host prefix. A /32 on an IPv6 address would pin the certificate to an enormous range",
			got)
	}
}

func TestTheKeyIDIsTheAuditLabel(t *testing.T) {
	req := validRequest(t)
	cert := mustSign(t, newCA(t), req)

	if cert.KeyId != req.KeyID {
		t.Fatalf("key id = %q, want %q", cert.KeyId, req.KeyID)
	}
}

func TestSerialsDiffer(t *testing.T) {
	ca := newCA(t)
	seen := map[uint64]bool{}

	for range 200 {
		cert := mustSign(t, ca, validRequest(t))
		if seen[cert.Serial] {
			t.Fatal("a serial was reused, so two certificates would be indistinguishable in an audit trail")
		}
		seen[cert.Serial] = true
	}
}

func trustingSSHD(t *testing.T, trusted *FileSigner, at time.Time) (string, ssh.PublicKey) {
	t.Helper()

	hostKey := newKeyPair(t)
	checker := &ssh.CertChecker{
		Clock: func() time.Time { return at },
		IsUserAuthority: func(auth ssh.PublicKey) bool {
			return ssh.FingerprintSHA256(auth) == ssh.FingerprintSHA256(trusted.PublicKey())
		},
	}

	config := &ssh.ServerConfig{PublicKeyCallback: checker.Authenticate}
	config.AddHostKey(hostKey)

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
			go func() {
				defer raw.Close()
				conn, chans, reqs, err := ssh.NewServerConn(raw, config)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					ch.Reject(ssh.Prohibited, "")
				}
			}()
		}
	}()

	return listener.Addr().String(), hostKey.PublicKey()
}

func connectWithCert(t *testing.T, addr string, hostKey ssh.PublicKey,
	cert *ssh.Certificate, key ssh.Signer, principal string) error {
	t.Helper()

	certSigner, err := ssh.NewCertSigner(cert, key)
	if err != nil {
		return err
	}

	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            principal,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return err
	}
	client.Close()
	return nil
}

func TestATrustingHostAcceptsAMintedCertificate(t *testing.T) {
	ca := newCA(t)
	key := newKeyPair(t)

	req := validRequest(t)
	req.PublicKey = key.PublicKey()
	req.SourceAddress = "127.0.0.1"
	cert := mustSign(t, ca, req)

	addr, hostKey := trustingSSHD(t, ca, testNow)

	if err := connectWithCert(t, addr, hostKey, cert, key, "deploy"); err != nil {
		t.Fatalf("a host that trusts our CA refused our certificate: %v", err)
	}
}

func TestAHostTrustingAnotherCARefusesIt(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	key := newKeyPair(t)

	req := validRequest(t)
	req.PublicKey = key.PublicKey()
	req.SourceAddress = "127.0.0.1"
	cert := mustSign(t, ca, req)

	addr, hostKey := trustingSSHD(t, other, testNow)

	if err := connectWithCert(t, addr, hostKey, cert, key, "deploy"); err == nil {
		t.Fatal("a host trusting an unrelated CA accepted our certificate")
	}
}

func TestTheCertificateOnlyWorksForItsOwnPrincipal(t *testing.T) {
	ca := newCA(t)
	key := newKeyPair(t)

	req := validRequest(t)
	req.PublicKey = key.PublicKey()
	req.SourceAddress = "127.0.0.1"
	cert := mustSign(t, ca, req)

	addr, hostKey := trustingSSHD(t, ca, testNow)

	if err := connectWithCert(t, addr, hostKey, cert, key, "root"); err == nil {
		t.Fatal("a certificate minted for deploy logged in as root")
	}
}

func TestTheSourceAddressPinIsEnforcedByTheHost(t *testing.T) {
	ca := newCA(t)
	key := newKeyPair(t)

	req := validRequest(t)
	req.PublicKey = key.PublicKey()
	req.SourceAddress = "10.0.0.1"
	cert := mustSign(t, ca, req)

	addr, hostKey := trustingSSHD(t, ca, testNow)

	if err := connectWithCert(t, addr, hostKey, cert, key, "deploy"); err == nil {
		t.Fatal("a certificate pinned to 10.0.0.1 authenticated from 127.0.0.1. The pin is only worth having if sshd enforces it, so this has to be checked against a real handshake rather than by reading the critical option back")
	}
}

func TestAnExpiredCertificateIsRefusedByTheHost(t *testing.T) {
	ca := newCA(t)
	key := newKeyPair(t)

	req := validRequest(t)
	req.PublicKey = key.PublicKey()
	req.SourceAddress = "127.0.0.1"
	cert := mustSign(t, ca, req)

	addr, hostKey := trustingSSHD(t, ca, req.ValidBefore.Add(time.Second))

	if err := connectWithCert(t, addr, hostKey, cert, key, "deploy"); err == nil {
		t.Fatal("an expired certificate authenticated")
	}
}

func TestCheckRejectsAnUnscopedRequest(t *testing.T) {
	base := validRequest(t)

	cases := map[string]func(*Request){
		"no public key":     func(r *Request) { r.PublicKey = nil },
		"no key id":         func(r *Request) { r.KeyID = "" },
		"no principal":      func(r *Request) { r.Principal = "" },
		"principal comma":   func(r *Request) { r.Principal = "deploy,root" },
		"principal newline": func(r *Request) { r.Principal = "deploy\nroot" },
		"no source address": func(r *Request) { r.SourceAddress = "" },
		"bad source":        func(r *Request) { r.SourceAddress = "not-an-ip" },
		"source with port":  func(r *Request) { r.SourceAddress = "10.0.0.1:22" },
		"window inverted":   func(r *Request) { r.ValidAfter, r.ValidBefore = r.ValidBefore, r.ValidAfter },
		"window empty":      func(r *Request) { r.ValidBefore = r.ValidAfter },
		"ttl too long":      func(r *Request) { r.ValidBefore = r.ValidAfter.Add(MaxTTL + time.Second) },
		"before the epoch": func(r *Request) {
			r.ValidAfter = time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC)
			r.ValidBefore = r.ValidAfter.Add(time.Minute)
		},
		"zero times": func(r *Request) { r.ValidAfter, r.ValidBefore = time.Time{}, time.Time{} },
	}

	for label, mutate := range cases {
		req := base
		mutate(&req)

		if err := Check(req); err == nil {
			t.Errorf("%s: Check accepted the request", label)
		} else if fault.From(err).Kind != fault.KindInvalid {
			t.Errorf("%s: kind = %v, want KindInvalid", label, fault.From(err).Kind)
		}
	}
}

func TestSignRefusesWhatCheckRefuses(t *testing.T) {
	ca := newCA(t)
	req := validRequest(t)
	req.ValidBefore = req.ValidAfter.Add(24 * time.Hour)

	if _, err := ca.Sign(context.Background(), req); err == nil {
		t.Fatal("Sign issued a day-long certificate. Every implementation must apply the shared caps, or the caps are advice")
	}
}

func TestTheCertificateTTLIsShortRegardlessOfSessionLength(t *testing.T) {
	if MaxTTL > 10*time.Minute {
		t.Fatalf("MaxTTL = %s. sshd validates a certificate at authentication time only, so a short window costs nothing and bounds the damage from a leak",
			MaxTTL)
	}
}

func TestCreateRefusesToOverwriteAnExistingCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")

	first, err := Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := Create(path); err == nil {
		t.Fatal("Create overwrote an existing CA. Every target trusting the old key would stop trusting the platform at once, and the old key would be gone")
	}

	reloaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if ssh.FingerprintSHA256(reloaded.PublicKey()) != ssh.FingerprintSHA256(first) {
		t.Fatal("the key on disk is not the one Create reported")
	}
}

func TestTheCAKeyIsNotWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")
	if _, err := Create(path); err != nil {
		t.Fatalf("create: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o, want 0600: this key mints access to every target that trusts it", perm)
	}
}

func TestLoadRejectsSomethingThatIsNotAKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")
	if err := os.WriteFile(path, []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted a file that is not a private key")
	}
}

func TestACertificateStopsVerifyingOnceItsWindowPasses(t *testing.T) {
	ca := newCA(t)
	req := validRequest(t)
	cert := mustSign(t, ca, req)

	if err := checkerFor(ca, req.ValidBefore.Add(-time.Second)).CheckCert("deploy", cert); err != nil {
		t.Fatalf("refused a second before expiry: %v", err)
	}
	if err := checkerFor(ca, req.ValidBefore.Add(time.Second)).CheckCert("deploy", cert); err == nil {
		t.Fatal("the certificate still verified after its window closed")
	}
	if err := checkerFor(ca, req.ValidAfter.Add(-time.Second)).CheckCert("deploy", cert); err == nil {
		t.Fatal("the certificate verified before its window opened")
	}
}

func TestAPreEpochWindowCannotBecomeUnboundedValidity(t *testing.T) {
	req := validRequest(t)
	req.ValidAfter = time.Date(1960, 1, 1, 0, 0, 0, 0, time.UTC)
	req.ValidBefore = req.ValidAfter.Add(time.Minute)

	if err := Check(req); err == nil {
		t.Fatal("a pre-epoch window was accepted. Unix() is negative there, and int64 to uint64 wraps to roughly 1.8e19 seconds, which sshd reads as valid until the end of time")
	}

	if got := unixSeconds(req.ValidAfter); got != 0 {
		t.Fatalf("unixSeconds(%v) = %d, want 0: the conversion has to be guarded as well as the check, so a future caller that skips Check cannot mint an eternal certificate",
			req.ValidAfter, got)
	}
}
