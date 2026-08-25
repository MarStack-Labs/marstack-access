package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	cases := map[string]slog.Level{
		"debug":   slog.LevelDebug,
		"DEBUG":   slog.LevelDebug,
		" warn ":  slog.LevelWarn,
		"warning": slog.LevelWarn,
		"error":   slog.LevelError,
		"info":    slog.LevelInfo,
		"":        slog.LevelInfo,
		"chatty":  slog.LevelInfo,
	}

	for input, want := range cases {
		if got := parseLevel(input); got != want {
			t.Errorf("parseLevel(%q) = %v, want %v", input, got, want)
		}
	}
}

func TestUnknownLevelDoesNotSilenceTheLogger(t *testing.T) {
	var buf bytes.Buffer

	New("nonsense", &buf).Info("session opened")

	if !strings.Contains(buf.String(), "session opened") {
		t.Fatal("an unparseable level must fall back to info, not discard records")
	}
}

func TestDebugIsSuppressedAtInfo(t *testing.T) {
	var buf bytes.Buffer

	New("info", &buf).Debug("certificate minted")

	if buf.Len() != 0 {
		t.Fatalf("debug record emitted at info level: %s", buf.String())
	}
}
