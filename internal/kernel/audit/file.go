package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	trailPerm    = 0o600
	trailDirPerm = 0o700
	trailName    = "audit.jsonl"
)

type FileSink struct {
	mu   sync.Mutex
	file *os.File
	path string
}

func OpenFileSink(dir string) (*FileSink, error) {
	if err := os.MkdirAll(dir, trailDirPerm); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}

	path := filepath.Join(dir, trailName)
	file, err := os.OpenFile(filepath.Clean(path),
		os.O_WRONLY|os.O_CREATE|os.O_APPEND, trailPerm)
	if err != nil {
		return nil, fmt.Errorf("open audit trail: %w", err)
	}

	return &FileSink{file: file, path: path}, nil
}

func (s *FileSink) Append(_ context.Context, events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, e := range events {
		encoded, err := json.Marshal(e)
		if err != nil {
			return fmt.Errorf("encode audit event: %w", err)
		}
		if _, err := s.file.Write(append(encoded, '\n')); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}

	return s.file.Sync()
}

func (s *FileSink) Path() string {
	return s.path
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.file.Close()
}
