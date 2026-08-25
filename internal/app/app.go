package app

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/httpx"
	"github.com/marstack-labs/marstack-access/internal/platform/system"
	"github.com/marstack-labs/marstack-access/internal/store"
)

type Module interface {
	Name() string
	Migrations() []store.Migration
	Routes(mux *http.ServeMux)
}

type Config struct {
	Listen         string
	DataDir        string
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
}

func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	cfg = cfg.withDefaults()

	st, err := store.Open(ctx, cfg.DataDir)
	if err != nil {
		return nil, err
	}

	a := &App{cfg: cfg, log: log, store: st}
	a.modules = []Module{
		system.New(st, log),
	}

	if err := a.migrate(ctx); err != nil {
		st.Close()
		return nil, err
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

func (a *App) Close() error {
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
	errc := make(chan error, 1)
	go func() {
		a.log.Info("control plane listening", "addr", a.cfg.Listen, "modules", len(a.modules))
		err := a.http.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

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
