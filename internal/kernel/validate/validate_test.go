package validate

import (
	"strings"
	"testing"
)

func TestNameAccepts(t *testing.T) {
	for _, value := range []string{"db-1", "a", "web", "node-42", strings.Repeat("a", maxNameLen)} {
		if err := Name("name", value); err != nil {
			t.Errorf("Name(%q) = %v, want nil", value, err)
		}
	}
}

func TestNameRejects(t *testing.T) {
	for _, value := range []string{
		"",
		"-leading",
		"trailing-",
		"Upper",
		"under_score",
		"has space",
		"dot.separated",
		strings.Repeat("a", maxNameLen+1),
	} {
		if err := Name("name", value); err == nil {
			t.Errorf("Name(%q) = nil, want an error", value)
		}
	}
}

func TestAddressAcceptsIPsAndHostnames(t *testing.T) {
	for _, value := range []string{
		"10.0.0.4",
		"127.0.0.1",
		"::1",
		"2001:db8::1",
		"db-1",
		"db-1.internal",
		"a.b.c.d.example.com",
	} {
		if err := Address("address", value); err != nil {
			t.Errorf("Address(%q) = %v, want nil", value, err)
		}
	}
}

func TestAddressRejectsAnythingThatIsNotAHost(t *testing.T) {
	for _, value := range []string{
		"",
		"10.0.0.4 ",
		"10.0.0.4:22",
		"ssh://10.0.0.4",
		"db-1/../db-2",
		"db-1;reboot",
		"db-1 -oProxyCommand=id",
		"db-1\nmalicious",
		"db-1\x00",
		"-leading.example.com",
		"..",
		"db-1..internal",
		strings.Repeat("a", maxAddressLen+1),
	} {
		if err := Address("address", value); err == nil {
			t.Errorf("Address(%q) = nil, want an error", value)
		}
	}
}

func TestAddressRejectsUppercaseToKeepOneHostOneRecord(t *testing.T) {
	if err := Address("address", "DB-1.internal"); err == nil {
		t.Fatal("uppercase was accepted, so DB-1 and db-1 could be registered as two targets")
	}
}

func TestPortRange(t *testing.T) {
	for _, value := range []int{1, 22, 2222, 65535} {
		if err := Port("port", value); err != nil {
			t.Errorf("Port(%d) = %v, want nil", value, err)
		}
	}
	for _, value := range []int{0, -1, 65536, 1 << 20} {
		if err := Port("port", value); err == nil {
			t.Errorf("Port(%d) = nil, want an error", value)
		}
	}
}

func TestPrincipalAccepts(t *testing.T) {
	for _, value := range []string{"deploy", "root", "_svc", "app-runner", "ci_2", strings.Repeat("a", maxPrincipalLen)} {
		if err := Principal("principal", value); err != nil {
			t.Errorf("Principal(%q) = %v, want nil", value, err)
		}
	}
}

func TestPrincipalRejectsAnythingThatCouldBreakACertificate(t *testing.T) {
	for _, value := range []string{
		"",
		"1deploy",
		"-deploy",
		"Deploy",
		"deploy user",
		"deploy,root",
		"deploy\nroot",
		"deploy\troot",
		"deploy:root",
		"deploy/root",
		"deploy\x00root",
		"*",
		strings.Repeat("a", maxPrincipalLen+1),
	} {
		if err := Principal("principal", value); err == nil {
			t.Errorf("Principal(%q) = nil, want an error: it reaches a certificate principal list", value)
		}
	}
}

func TestErrorCodesNameTheField(t *testing.T) {
	err := Name("target_name", "")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "invalid_target_name") {
		t.Fatalf("error = %q, want it to carry the field name so a client can point at the input", err)
	}
}
