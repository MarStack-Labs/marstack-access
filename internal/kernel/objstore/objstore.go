package objstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	putTimeout   = 60 * time.Second
	maxErrorBody = 1 << 12

	LockModeCompliance = "COMPLIANCE"
	LockModeGovernance = "GOVERNANCE"
)

var (
	ErrNotConfigured = errors.New("objstore: no object store is configured")
	ErrTooLarge      = errors.New("objstore: object exceeds the size this client will buffer")
)

type Config struct {
	Endpoint   string
	Bucket     string
	Region     string
	AccessKey  string
	SecretKey  string
	LockMode   string
	RetainFor  time.Duration
	MaxObjectB int64
}

type Client struct {
	cfg   Config
	base  *url.URL
	http  *http.Client
	now   func() time.Time
	creds credentials
}

type Stored struct {
	Bucket      string
	Key         string
	Size        int64
	RetainUntil time.Time
}

func New(cfg Config) (*Client, error) {
	if cfg.Endpoint == "" || cfg.Bucket == "" {
		return nil, ErrNotConfigured
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("objstore: credentials are required for %s", cfg.Endpoint)
	}

	base, err := url.Parse(strings.TrimRight(cfg.Endpoint, "/"))
	if err != nil {
		return nil, fmt.Errorf("objstore: parse endpoint: %w", err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return nil, fmt.Errorf("objstore: endpoint %q needs an http or https scheme", cfg.Endpoint)
	}

	if cfg.Region == "" {
		cfg.Region = "us-east-1"
	}
	if cfg.LockMode == "" {
		cfg.LockMode = LockModeCompliance
	}
	if cfg.MaxObjectB == 0 {
		cfg.MaxObjectB = 64 << 20
	}

	return &Client{
		cfg:  cfg,
		base: base,
		http: &http.Client{Timeout: putTimeout},
		now:  time.Now,
		creds: credentials{
			accessKey: cfg.AccessKey,
			secretKey: cfg.SecretKey,
			region:    cfg.Region,
		},
	}, nil
}

func (c *Client) Bucket() string {
	return c.cfg.Bucket
}

func (c *Client) Insecure() bool {
	return c.base.Scheme != "https"
}

func (c *Client) Put(ctx context.Context, key string, body io.Reader, contentType string) (Stored, error) {
	payload, err := readCapped(body, c.cfg.MaxObjectB)
	if err != nil {
		return Stored{}, err
	}

	at := c.now().UTC()
	retainUntil := at.Add(c.cfg.RetainFor)

	target := c.base.JoinPath(c.cfg.Bucket, key)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, target.String(), bytes.NewReader(payload))
	if err != nil {
		return Stored{}, fmt.Errorf("objstore: build request: %w", err)
	}

	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", contentType)
	if c.cfg.RetainFor > 0 {
		req.Header.Set("X-Amz-Object-Lock-Mode", c.cfg.LockMode)
		req.Header.Set("X-Amz-Object-Lock-Retain-Until-Date", retainUntil.Format(time.RFC3339))
	}

	sign(req, c.creds, hashHex(payload), at)

	res, err := c.http.Do(req)
	if err != nil {
		return Stored{}, fmt.Errorf("objstore: put %s: %w", key, err)
	}
	defer res.Body.Close()

	if res.StatusCode >= http.StatusBadRequest {
		detail, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
		return Stored{}, fmt.Errorf("objstore: the store refused %s with %d: %s",
			key, res.StatusCode, strings.TrimSpace(string(detail)))
	}

	stored := Stored{Bucket: c.cfg.Bucket, Key: key, Size: int64(len(payload))}
	if c.cfg.RetainFor > 0 {
		stored.RetainUntil = retainUntil
	}
	return stored, nil
}

func readCapped(body io.Reader, limit int64) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("objstore: read object: %w", err)
	}
	if int64(len(payload)) > limit {
		return nil, ErrTooLarge
	}
	return payload, nil
}
