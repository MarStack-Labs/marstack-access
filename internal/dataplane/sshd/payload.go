package sshd

import (
	"encoding/binary"
)

const (
	maxTermLen    = 64
	maxCommandLen = 4096
	maxDimension  = 1000
)

func parsePtyRequest(payload []byte) ptyRequest {
	pty := ptyRequest{requested: true, term: defaultTerm, cols: defaultCols, rows: defaultRows}

	term, rest, ok := readString(payload, maxTermLen)
	if !ok {
		return pty
	}
	if term != "" {
		pty.term = term
	}

	dimensions := parsePtyDimensions(rest)
	pty.cols = dimensions.cols
	pty.rows = dimensions.rows
	return pty
}

func parsePtyDimensions(payload []byte) ptyRequest {
	pty := ptyRequest{cols: defaultCols, rows: defaultRows}

	if len(payload) < 8 {
		return pty
	}

	pty.cols = boundedDimension(binary.BigEndian.Uint32(payload[0:4]), defaultCols)
	pty.rows = boundedDimension(binary.BigEndian.Uint32(payload[4:8]), defaultRows)
	return pty
}

func parseExecRequest(payload []byte) string {
	command, _, ok := readString(payload, maxCommandLen)
	if !ok {
		return ""
	}
	return command
}

func readString(payload []byte, limit uint32) (string, []byte, bool) {
	if len(payload) < 4 {
		return "", nil, false
	}

	length := binary.BigEndian.Uint32(payload[0:4])
	if length > limit || uint64(length)+4 > uint64(len(payload)) {
		return "", nil, false
	}

	return string(payload[4 : 4+length]), payload[4+length:], true
}

func boundedDimension(value uint32, fallback int) int {
	if value == 0 || value > maxDimension {
		return fallback
	}
	return int(value)
}
