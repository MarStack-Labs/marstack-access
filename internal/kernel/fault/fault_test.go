package fault

import (
	"errors"
	"strings"
	"testing"
)

func TestFromPreservesAnExistingFault(t *testing.T) {
	original := NotFound("target_not_found", "no such target")

	if got := From(original); got != original {
		t.Fatalf("From returned a different fault: %#v", got)
	}
}

func TestFromFindsAWrappedFault(t *testing.T) {
	original := Conflict("target_name_taken", "a target with that name exists")
	wrapped := errors.New("repository: " + original.Error())

	if got := From(wrapped); got.Kind != KindInternal {
		t.Fatalf("a merely stringified fault must not be recovered: kind = %v", got.Kind)
	}

	joined := errors.Join(errors.New("context"), original)
	if got := From(joined); got != original {
		t.Fatalf("From did not unwrap a joined fault: %#v", got)
	}
}

func TestUnknownErrorBecomesInternalWithoutLeakingIt(t *testing.T) {
	secret := errors.New("dial 10.0.0.4:22: connection refused")

	f := From(secret)

	if f.Kind != KindInternal {
		t.Fatalf("kind = %v, want KindInternal", f.Kind)
	}
	if strings.Contains(f.Message, "10.0.0.4") {
		t.Fatalf("Message leaks the cause: %q", f.Message)
	}
	if !errors.Is(f, secret) {
		t.Fatal("the cause must stay reachable through Unwrap for server-side logging")
	}
}

func TestZeroKindIsInternal(t *testing.T) {
	var kind Kind
	if kind != KindInternal {
		t.Fatal("the zero Kind must be KindInternal so an uninitialised fault fails closed")
	}
}

func TestErrorIncludesTheCauseForOperators(t *testing.T) {
	f := Internal(errors.New("disk full"))

	if !strings.Contains(f.Error(), "disk full") {
		t.Fatalf("Error() = %q, want it to carry the cause", f.Error())
	}
}
