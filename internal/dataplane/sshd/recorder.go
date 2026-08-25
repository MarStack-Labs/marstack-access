package sshd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	recordingDir     = "recordings"
	defaultCols      = 80
	defaultRows      = 24
	defaultTerm      = "xterm-256color"
	recordingPerm    = 0o600
	recordingDirPerm = 0o700
)

type recorder struct {
	path  string
	file  *os.File
	start time.Time
	now   func() time.Time

	mu      sync.Mutex
	written int64
	closed  bool
}

type header struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env"`
}

func newRecorder(dir, sessionID string, pty ptyRequest, now func() time.Time) (*recorder, error) {
	target := filepath.Join(dir, recordingDir)
	if err := os.MkdirAll(target, recordingDirPerm); err != nil {
		return nil, fmt.Errorf("create recording dir: %w", err)
	}

	path := filepath.Join(target, sessionID+".cast")
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, recordingPerm)
	if err != nil {
		return nil, fmt.Errorf("create recording: %w", err)
	}

	started := now()
	encoded, err := json.Marshal(header{
		Version:   2,
		Width:     pty.cols,
		Height:    pty.rows,
		Timestamp: started.Unix(),
		Env:       map[string]string{"TERM": pty.term},
	})
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("encode recording header: %w", err)
	}

	if _, err := file.Write(append(encoded, '\n')); err != nil {
		file.Close()
		return nil, fmt.Errorf("write recording header: %w", err)
	}

	return &recorder{path: path, file: file, start: started, now: now}, nil
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return 0, os.ErrClosed
	}

	elapsed := r.now().Sub(r.start).Seconds()
	event, err := json.Marshal([]any{elapsed, "o", string(p)})
	if err != nil {
		return 0, fmt.Errorf("encode recording event: %w", err)
	}

	if _, err := r.file.Write(append(event, '\n')); err != nil {
		return 0, fmt.Errorf("write recording event: %w", err)
	}

	r.written += int64(len(p))
	return len(p), nil
}

func (r *recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true
	return r.file.Close()
}

func (r *recorder) Path() string {
	return r.path
}

func (r *recorder) Recorded() int64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.written
}
