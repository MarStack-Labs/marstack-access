package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/dataplane/certs"
	"github.com/marstack-labs/marstack-access/internal/dataplane/sshd"
	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/platform/approval"
	"github.com/marstack-labs/marstack-access/internal/platform/identity"
	"github.com/marstack-labs/marstack-access/internal/platform/policy"
	"github.com/marstack-labs/marstack-access/internal/platform/session"
	"github.com/marstack-labs/marstack-access/internal/platform/system"
	"github.com/marstack-labs/marstack-access/internal/platform/target"
	"github.com/marstack-labs/marstack-access/internal/store"
)

type Module interface {
	Name() string
	Migrations() []store.Migration
	Routes(mux *http.ServeMux)
}

type Bootstrapper interface {
	Bootstrap(ctx context.Context) (string, error)
}

type Reconciler interface {
	Reconcile(ctx context.Context) error
}

const (
	bootstrapTokenFile = "bootstrap-token"
	auditDir           = "audit"
	auditJob           = "marstack-access"
)

type Config struct {
	Listen         string
	SSHListen      string
	DataDir        string
	AdvertiseIP    string
	DevCAKeyPath   string
	LokiURL        string
	RequestTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:7443"
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 30 * time.Second
	}
	return c
}

type App struct {
	cfg     Config
	log     *slog.Logger
	store   *store.Store
	modules []Module
	router  http.Handler
	http    *http.Server
	sshd    *sshd.Server
	trail   *audit.Recorder
	sink    *audit.FileSink
}

func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	cfg = cfg.withDefaults()

	st, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return nil, err
	}

	a := &App{cfg: cfg, log: log, store: st}

	a.sink, err = audit.OpenFileSink(filepath.Join(cfg.DataDir, auditDir))
	if err != nil {
		st.Close()
		return nil, err
	}

	var shipped audit.Sink
	if cfg.LokiURL != "" {
		shipped = audit.NewLokiSink(cfg.LokiURL, auditJob)
		log.Info("audit events will be shipped", "loki", cfg.LokiURL)
	} else {
		log.Warn("no audit shipping configured, the trail stays on this host",
			"trail", a.sink.Path(),
			"hint", "--audit-loki-url makes the trail survive whoever owns this host")
	}
	a.trail = audit.New(log, a.sink, shipped)

	var idm *identity.Module
	guard := authz.New(authz.AuthenticatorFunc(
		func(ctx context.Context, secret string) (authz.Identity, error) {
			return idm.Authenticate(ctx, secret)
		}), log)
	idm = identity.New(st, log, guard)

	targets := target.New(st, log, guard)
	policies := policy.New(st, log, guard, targets)

	grants := approval.New(st, log, guard, policies)

	sessions := session.New(st, log, guard, session.TerminatorFunc(func(sessionID string) bool {
		if a.sshd == nil {
			return false
		}
		return a.sshd.Kill(sessionID)
	}))

	a.modules = []Module{
		system.New(st, log, guard),
		idm,
		targets,
		policies,
		grants,
		sessions,
	}

	if err := a.migrate(ctx); err != nil {
		st.Close()
		return nil, err
	}

	if err := a.bootstrap(ctx); err != nil {
		st.Close()
		return nil, err
	}

	if err := a.reconcile(ctx); err != nil {
		st.Close()
		return nil, err
	}

	if cfg.SSHListen != "" {
		signer, signerErr := loadSigner(cfg, log)
		if signerErr != nil {
			st.Close()
			return nil, signerErr
		}

		a.sshd, err = sshd.New(
			sshd.Config{
				Listen:      cfg.SSHListen,
				DataDir:     cfg.DataDir,
				AdvertiseIP: cfg.AdvertiseIP,
			},
			log, idm, targetLookup(targets), policies, grants, signer,
			sessionOpener(sessions), sessionCloser(sessions), a.trail)
		if err != nil {
			st.Close()
			return nil, err
		}
	}

	a.router = a.buildRouter()
	a.http = &http.Server{
		Addr:              cfg.Listen,
		Handler:           a.router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	return a, nil
}

func sessionOpener(sessions *session.Module) sshd.SessionOpener {
	return func(ctx context.Context, s sshd.SessionOpened) error {
		return sessions.Open(ctx, session.OpenInput{
			ID:           s.ID,
			UserID:       s.UserID,
			UserName:     s.UserName,
			TargetID:     s.TargetID,
			TargetName:   s.TargetName,
			Principal:    s.Principal,
			CredentialID: s.CredentialID,
			RemoteAddr:   s.RemoteAddr,
			Recording:    s.Recording,
		})
	}
}

func sessionCloser(sessions *session.Module) sshd.SessionCloser {
	return func(ctx context.Context, id string, s sshd.SessionClosed) error {
		return sessions.Close(ctx, id, session.CloseInput{
			ExitCode:      s.ExitCode,
			Reason:        s.Reason,
			RecordedBytes: s.RecordedBytes,
		})
	}
}

func loadSigner(cfg Config, log *slog.Logger) (certs.Signer, error) {
	if cfg.DevCAKeyPath == "" {
		log.Warn("no signing authority configured, sessions will resolve but not connect",
			"hint", "marac ca init --path <file>, then --dev-ca-key <file>")
		return nil, nil
	}

	signer, err := certs.Load(cfg.DevCAKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}

	log.Warn("using a signing key held in a local file",
		"path", cfg.DevCAKeyPath,
		"fingerprint", ssh.FingerprintSHA256(signer.PublicKey()),
		"note", "a production deployment keeps this in marstack-secrets")
	return signer, nil
}

func targetLookup(targets *target.Module) sshd.TargetLookup {
	return func(ctx context.Context, name string) (sshd.Target, error) {
		t, err := targets.ByName(ctx, name)
		if err != nil {
			return sshd.Target{}, err
		}
		return sshd.Target{
			ID:         t.ID,
			Name:       t.Name,
			Address:    t.Address,
			Port:       t.Port,
			Principals: t.Principals,
			HostKey:    t.HostKey,
		}, nil
	}
}

func (a *App) Close() error {
	if a.trail != nil {
		_ = a.trail.Close()
	}
	if a.sink != nil {
		_ = a.sink.Close()
	}
	return a.store.Close()
}

func (a *App) migrate(ctx context.Context) error {
	var all []store.Migration
	for _, m := range a.modules {
		all = append(all, m.Migrations()...)
	}
	if err := a.store.Migrate(ctx, all); err != nil {
		return err
	}
	a.log.Info("store ready", "dir", a.cfg.DataDir, "migrations", len(all))
	return nil
}

func (a *App) bootstrap(ctx context.Context) error {
	for _, m := range a.modules {
		b, ok := m.(Bootstrapper)
		if !ok {
			continue
		}

		secret, err := b.Bootstrap(ctx)
		if err != nil {
			return fmt.Errorf("bootstrap %s: %w", m.Name(), err)
		}
		if secret == "" {
			continue
		}

		path := filepath.Join(a.cfg.DataDir, bootstrapTokenFile)
		if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
			return fmt.Errorf("write bootstrap token: %w", err)
		}
		a.log.Warn("bootstrap credential created, read it and delete the file",
			"module", m.Name(), "path", path)
	}
	return nil
}

func (a *App) reconcile(ctx context.Context) error {
	for _, m := range a.modules {
		r, ok := m.(Reconciler)
		if !ok {
			continue
		}
		if err := r.Reconcile(ctx); err != nil {
			return fmt.Errorf("reconcile %s: %w", m.Name(), err)
		}
	}
	return nil
}

func (a *App) buildRouter() http.Handler {
	mux := http.NewServeMux()
	for _, m := range a.modules {
		m.Routes(mux)
	}
	return httpx.Chain(mux,
		httpx.RequestID(),
		httpx.Recover(a.log),
		httpx.AccessLog(a.log),
		httpx.SecureHeaders(),
		httpx.Timeout(a.cfg.RequestTimeout),
	)
}

func (a *App) Handler() http.Handler {
	return a.router
}

func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errc := make(chan error, 2)
	go func() {
		a.log.Info("control plane listening", "addr", a.cfg.Listen, "modules", len(a.modules))
		err := a.http.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	if a.sshd != nil {
		go func() { errc <- a.sshd.Run(ctx) }()
	}

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		a.log.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return a.http.Shutdown(shutdownCtx)
	}
}
