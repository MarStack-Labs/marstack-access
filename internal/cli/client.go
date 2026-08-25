package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	defaultEndpoint = "http://127.0.0.1:7443"
	endpointEnvVar  = "MARAC_ENDPOINT"
	tokenEnvVar     = "MARAC_TOKEN"
	requestTimeout  = 30 * time.Second
	maxErrorBody    = 1 << 16
	maxResponseBody = 1 << 22
)

type client struct {
	endpoint string
	token    string
	http     *http.Client
}

func newClient(g *globals) *client {
	return &client{
		endpoint: strings.TrimRight(g.endpoint, "/"),
		token:    g.token,
		http:     &http.Client{Timeout: requestTimeout},
	}
}

type apiError struct {
	Code    string
	Message string
	Status  int
}

func (e *apiError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("control plane returned %d", e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		encoded, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, body)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("call %s: %w", c.endpoint, err)
	}
	defer res.Body.Close()

	if res.StatusCode >= http.StatusBadRequest {
		return decodeAPIError(res)
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, maxResponseBody)).Decode(out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}

func decodeAPIError(res *http.Response) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
	if err != nil {
		return &apiError{Status: res.StatusCode}
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return &apiError{Status: res.StatusCode}
	}

	return &apiError{
		Code:    envelope.Error.Code,
		Message: envelope.Error.Message,
		Status:  res.StatusCode,
	}
}
