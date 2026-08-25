package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	pushPath      = "/loki/api/v1/push"
	pushTimeout   = 10 * time.Second
	maxErrorBody  = 1 << 12
	defaultJobTag = "marstack-access"
)

type LokiSink struct {
	url    string
	job    string
	client *http.Client
}

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

func NewLokiSink(baseURL, job string) *LokiSink {
	if job == "" {
		job = defaultJobTag
	}

	return &LokiSink{
		url:    strings.TrimRight(baseURL, "/") + pushPath,
		job:    job,
		client: &http.Client{Timeout: pushTimeout},
	}
}

func (s *LokiSink) Append(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	push, err := s.build(events)
	if err != nil {
		return err
	}

	body, err := json.Marshal(push)
	if err != nil {
		return fmt.Errorf("encode loki push: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build loki request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	res, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("push to loki: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= http.StatusBadRequest {
		detail, _ := io.ReadAll(io.LimitReader(res.Body, maxErrorBody))
		return fmt.Errorf("loki refused the push with %d: %s",
			res.StatusCode, strings.TrimSpace(string(detail)))
	}

	return nil
}

func (s *LokiSink) build(events []Event) (lokiPush, error) {
	grouped := map[string][][2]string{}
	labels := map[string]map[string]string{}

	for _, e := range events {
		stream := map[string]string{
			"job":     s.job,
			"action":  e.Action,
			"outcome": e.Outcome,
		}
		key := stream["job"] + "|" + stream["action"] + "|" + stream["outcome"]

		line, err := json.Marshal(e)
		if err != nil {
			return lokiPush{}, fmt.Errorf("encode audit event: %w", err)
		}

		labels[key] = stream
		grouped[key] = append(grouped[key], [2]string{
			strconv.FormatInt(e.At.UnixNano(), 10),
			string(line),
		})
	}

	push := lokiPush{Streams: make([]lokiStream, 0, len(grouped))}
	for key, values := range grouped {
		push.Streams = append(push.Streams, lokiStream{Stream: labels[key], Values: values})
	}
	return push, nil
}
