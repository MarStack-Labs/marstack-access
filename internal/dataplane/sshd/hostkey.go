package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const hostKeyFile = "host_ed25519"

func loadOrCreateHostKey(dir string) (ssh.Signer, error) {
	path := filepath.Join(dir, hostKeyFile)

	existing, err := readHostKey(path)
	switch {
	case err == nil:
		return existing, nil
	case !os.IsNotExist(err):
		return nil, err
	}

	return createHostKey(path)
}

func readHostKey(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse host key %s: %w", path, err)
	}
	return signer, nil
}

func createHostKey(path string) (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}

	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("host signer: %w", err)
	}
	return signer, nil
}
