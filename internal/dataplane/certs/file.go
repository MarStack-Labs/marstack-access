package certs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

type FileSigner struct {
	ca ssh.Signer
}

func Create(path string) (ssh.PublicKey, error) {
	clean := filepath.Clean(path)

	if _, err := os.Stat(clean); err == nil {
		return nil, fmt.Errorf("refusing to overwrite the existing key at %s", clean)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}
	if err := os.WriteFile(clean, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, fmt.Errorf("write ca key: %w", err)
	}

	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, fmt.Errorf("ca signer: %w", err)
	}
	return signer.PublicKey(), nil
}

func Load(path string) (*FileSigner, error) {
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	ca, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("parse ca key %s: %w", path, err)
	}
	return &FileSigner{ca: ca}, nil
}

func (s *FileSigner) PublicKey() ssh.PublicKey {
	return s.ca.PublicKey()
}

func (s *FileSigner) Sign(_ context.Context, req Request) (*ssh.Certificate, error) {
	if err := Check(req); err != nil {
		return nil, err
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	cert := build(req, serial)
	if err := cert.SignCert(rand.Reader, s.ca); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return cert, nil
}

func randomSerial() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, fmt.Errorf("serial: %w", err)
	}
	return binary.BigEndian.Uint64(buf), nil
}
