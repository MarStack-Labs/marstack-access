package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	MaxTail = 500

	tailWindow  = 1 << 20
	tailLineCap = 1 << 16
)

func Tail(path string, limit int) ([]Event, error) {
	if limit <= 0 {
		return nil, nil
	}
	if limit > MaxTail {
		limit = MaxTail
	}

	file, err := os.Open(filepath.Clean(path))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, err
	}

	if info.Size() > tailWindow {
		if _, err := file.Seek(info.Size()-tailWindow, io.SeekStart); err != nil {
			return nil, err
		}
	}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 4096), tailLineCap)

	var found []Event
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			continue
		}
		found = append(found, e)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(found) > limit {
		found = found[len(found)-limit:]
	}

	newestFirst := make([]Event, len(found))
	for i, e := range found {
		newestFirst[len(found)-1-i] = e
	}
	return newestFirst, nil
}
