package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestAValueCannotForgeALogLine(t *testing.T) {
	forgeries := map[string]string{
		"newline":        "/x\nlevel=ERROR msg=\"the gateway was compromised\"",
		"carriage":       "/x\rlevel=ERROR msg=forged",
		"crlf":           "/x\r\nlevel=INFO msg=\"session opened\" user=root",
		"quote and pair": `/x" user=root msg="approved`,
		"tab":            "/x\tuser=root",
		"escape":         `/x\nlevel=ERROR`,
	}

	for name, value := range forgeries {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			New("info", &out).Info("request", "path", value)

			written := out.String()
			lines := strings.Count(strings.TrimSuffix(written, "\n"), "\n") + 1

			if lines != 1 {
				t.Fatalf("one call produced %d lines, so a request path can write its own log "+
					"records:\n%s", lines, written)
			}
			if strings.Contains(written, "compromised") && !strings.Contains(written, `\n`) {
				t.Fatalf("the injected text landed unescaped:\n%s", written)
			}
		})
	}
}

func TestTheEscapingHoldsForEveryControlByte(t *testing.T) {
	for b := 0; b < 0x20; b++ {
		var out bytes.Buffer
		New("info", &out).Info("request", "path", "/x"+string(rune(b))+"y")

		if strings.Count(strings.TrimSuffix(out.String(), "\n"), "\n") != 0 {
			t.Fatalf("control byte %#02x broke the record onto a second line:\n%s", b, out.String())
		}
	}
}

func TestAnAttributeKeyIsNotTakenFromInput(t *testing.T) {
	var out bytes.Buffer
	New("info", &out).Info("request", "path", "/a", "status", 200)

	written := out.String()
	for _, want := range []string{"path=/a", "status=200"} {
		if !strings.Contains(written, want) {
			t.Errorf("record is missing %q: %s", want, written)
		}
	}
}
