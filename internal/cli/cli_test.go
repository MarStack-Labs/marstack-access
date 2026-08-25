package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/version"
)

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func TestVersionPrintsBuildMetadata(t *testing.T) {
	out, err := runCLI(t, "version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimSpace(out); got != version.String() {
		t.Fatalf("output = %q, want %q", got, version.String())
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	if _, err := runCLI(t, "version", "extra"); err == nil {
		t.Fatal("expected an error for an unexpected argument")
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if _, err := runCLI(t, "definitely-not-a-command"); err == nil {
		t.Fatal("expected an error for an unknown command")
	}
}
