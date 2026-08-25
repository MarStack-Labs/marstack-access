package authz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func guardFor(id Identity, err error) *Guard {
	return New(AuthenticatorFunc(func(context.Context, string) (Identity, error) {
		return id, err
	}), discardLogger(), nil)
}

func call(t *testing.T, h http.Handler, header string) *httptest.ResponseRecorder {
	t.Helper()

	r := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
	if header != "" {
		r.Header.Set("Authorization", header)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func okHandler(seen *Identity) http.Handler {
	return http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if id, ok := IdentityFrom(r.Context()); ok && seen != nil {
			*seen = id
		}
	})
}

func TestCoversRanksRoles(t *testing.T) {
	cases := []struct {
		held, required string
		want           bool
	}{
		{RoleAdmin, RoleAdmin, true},
		{RoleAdmin, RoleOperator, true},
		{RoleAdmin, RoleViewer, true},
		{RoleOperator, RoleOperator, true},
		{RoleOperator, RoleViewer, true},
		{RoleOperator, RoleAdmin, false},
		{RoleViewer, RoleViewer, true},
		{RoleViewer, RoleOperator, false},
		{RoleViewer, RoleAdmin, false},
	}

	for _, c := range cases {
		if got := Covers(c.held, c.required); got != c.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", c.held, c.required, got, c.want)
		}
	}
}

func TestCoversRejectsAnUnknownRoleOnEitherSide(t *testing.T) {
	for _, c := range [][2]string{
		{"root", RoleViewer},
		{"", RoleViewer},
		{RoleAdmin, "root"},
		{RoleAdmin, ""},
		{"Admin", RoleViewer},
	} {
		if Covers(c[0], c[1]) {
			t.Errorf("Covers(%q, %q) = true: an unrecognised role must never satisfy a check", c[0], c[1])
		}
	}
}

func TestRequirePassesTheIdentityToTheHandler(t *testing.T) {
	want := Identity{UserID: "usr-abc", Name: "umar", Role: RoleAdmin, CredentialID: "tok-abc"}
	var seen Identity

	rec := call(t, guardFor(want, nil).Require(RoleOperator, okHandler(&seen)), "Bearer mat_a_b")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}
	if seen != want {
		t.Fatalf("identity in context = %+v, want %+v", seen, want)
	}
}

func TestRequireRejectsAnInsufficientRole(t *testing.T) {
	guard := guardFor(Identity{UserID: "usr-abc", Role: RoleViewer}, nil)

	rec := call(t, guard.Require(RoleAdmin, okHandler(nil)), "Bearer mat_a_b")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "insufficient_role") {
		t.Fatalf("body = %s, want the insufficient_role code", body)
	}
}

func TestForbiddenNamesTheRoleButNotTheCaller(t *testing.T) {
	guard := guardFor(Identity{UserID: "usr-secret", Name: "umar", Role: RoleViewer}, nil)

	rec := call(t, guard.Require(RoleAdmin, okHandler(nil)), "Bearer mat_a_b")

	body := rec.Body.String()
	if !strings.Contains(body, RoleAdmin) {
		t.Error("the response does not say which role is required, so the caller cannot act on it")
	}
	if strings.Contains(body, "usr-secret") || strings.Contains(body, "umar") {
		t.Fatalf("the response echoes the caller's identity back: %s", body)
	}
}

func TestRequireRejectsAMissingOrMalformedHeader(t *testing.T) {
	guard := guardFor(Identity{Role: RoleAdmin}, nil)
	handler := guard.Require(RoleViewer, okHandler(nil))

	for label, header := range map[string]string{
		"absent":       "",
		"no scheme":    "mat_a_b",
		"wrong scheme": "Basic mat_a_b",
		"scheme only":  "Bearer",
		"empty value":  "Bearer   ",
		"tab only":     "Bearer \t",
	} {
		if rec := call(t, handler, header); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", label, rec.Code)
		}
	}
}

func TestRequirePropagatesTheAuthenticatorFault(t *testing.T) {
	guard := guardFor(Identity{}, InvalidToken())

	rec := call(t, guard.Require(RoleViewer, okHandler(nil)), "Bearer mat_a_b")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAnAuthenticatorCrashBecomesA500NotAnAllow(t *testing.T) {
	guard := guardFor(Identity{Role: RoleAdmin}, fault.Internal(errors.New("database is gone")))

	rec := call(t, guard.Require(RoleViewer, okHandler(nil)), "Bearer mat_a_b")

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: an authenticator that fails must deny, not fall through", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "database is gone") {
		t.Fatal("the response leaks the internal cause")
	}
}

func TestAnEmptyRoleFromTheAuthenticatorIsDenied(t *testing.T) {
	guard := guardFor(Identity{UserID: "usr-abc", Role: ""}, nil)

	rec := call(t, guard.Require(RoleViewer, okHandler(nil)), "Bearer mat_a_b")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: a row with a blank role must not satisfy the lowest check", rec.Code)
	}
}

func TestRequirePanicsOnAnUnknownRoleAtWiringTime(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Require accepted an unknown role. A typo in a route's role would leave the route permanently unreachable, or worse, satisfied by nobody and noticed by no one")
		}
	}()

	guardFor(Identity{Role: RoleAdmin}, nil).Require("opperator", okHandler(nil))
}

func TestPublicRunsTheHandlerWithoutAToken(t *testing.T) {
	rec := call(t, Public(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})), "")

	if rec.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want the handler to run untouched", rec.Code)
	}
}

func TestIdentityFromAnUnauthenticatedContextIsAbsent(t *testing.T) {
	if _, ok := IdentityFrom(context.Background()); ok {
		t.Fatal("IdentityFrom reported an identity on a bare context")
	}
}

func TestRolesListsEveryRankedRole(t *testing.T) {
	listed := Roles()
	if len(listed) != len(ranks) {
		t.Fatalf("Roles() has %d entries but %d roles are ranked: validation and authorization would disagree",
			len(listed), len(ranks))
	}
	for _, role := range listed {
		if _, ok := ranks[role]; !ok {
			t.Errorf("Roles() offers %q which has no rank", role)
		}
	}
}

type recordingTrail struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingTrail) Record(_ context.Context, e audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.events = append(r.events, e)
	return nil
}

func (r *recordingTrail) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()

	return append([]audit.Event{}, r.events...)
}

func guardWithTrail(id Identity, err error, trail audit.Trail) *Guard {
	return New(AuthenticatorFunc(func(context.Context, string) (Identity, error) {
		return id, err
	}), discardLogger(), trail)
}

func TestEveryRefusalLandsInTheTrail(t *testing.T) {
	cases := map[string]struct {
		identity Identity
		authErr  error
		header   string
		reason   string
	}{
		"no token":          {identity: Identity{Role: RoleAdmin}, header: "", reason: "missing_token"},
		"unknown token":     {authErr: InvalidToken(), header: "Bearer mat_a_b", reason: "invalid_token"},
		"insufficient role": {identity: Identity{UserID: "usr-abc", Name: "alice", Role: RoleViewer}, header: "Bearer mat_a_b", reason: "insufficient_role"},
	}

	for label, c := range cases {
		trail := &recordingTrail{}
		guard := guardWithTrail(c.identity, c.authErr, trail)

		call(t, guard.Require(RoleAdmin, okHandler(nil)), c.header)

		events := trail.all()
		if len(events) != 1 {
			t.Errorf("%s: %d events, want 1", label, len(events))
			continue
		}

		e := events[0]
		if e.Action != "api.denied" || e.Outcome != audit.OutcomeDenied {
			t.Errorf("%s: event = %+v", label, e)
		}
		if e.Reason != c.reason {
			t.Errorf("%s: reason = %q, want %q", label, e.Reason, c.reason)
		}
		if e.Fields["required"] != RoleAdmin {
			t.Errorf("%s: required = %q, want %q", label, e.Fields["required"], RoleAdmin)
		}
		if e.Fields["path"] == "" || e.Fields["method"] == "" {
			t.Errorf("%s: the event does not say what was attempted: %+v", label, e)
		}
	}
}

func TestTheDenialEventNamesTheCallerOnlyWhenKnown(t *testing.T) {
	known := &recordingTrail{}
	call(t, guardWithTrail(Identity{UserID: "usr-abc", Name: "alice", Role: RoleViewer}, nil, known).
		Require(RoleAdmin, okHandler(nil)), "Bearer mat_a_b")

	if got := known.all()[0].ActorName; got != "alice" {
		t.Errorf("actor = %q, want alice: an authenticated caller that was refused is attributable", got)
	}

	anonymous := &recordingTrail{}
	call(t, guardWithTrail(Identity{}, InvalidToken(), anonymous).
		Require(RoleAdmin, okHandler(nil)), "Bearer mat_a_b")

	if got := anonymous.all()[0].ActorName; got != "" {
		t.Errorf("actor = %q, want empty: nothing was proved about who this was, and guessing would put a name against the wrong person", got)
	}
}

func TestAnAllowedRequestLeavesNoDenialEvent(t *testing.T) {
	trail := &recordingTrail{}
	guard := guardWithTrail(Identity{UserID: "usr-abc", Name: "alice", Role: RoleAdmin}, nil, trail)

	call(t, guard.Require(RoleOperator, okHandler(nil)), "Bearer mat_a_b")

	if got := len(trail.all()); got != 0 {
		t.Fatalf("%d events on an allowed request, want 0: the module records what it changed, and duplicating every allowed call here would bury the refusals",
			got)
	}
}

func TestANilTrailIsSafe(t *testing.T) {
	guard := guardWithTrail(Identity{Role: RoleViewer}, nil, nil)

	if rec := call(t, guard.Require(RoleAdmin, okHandler(nil)), "Bearer mat_a_b"); rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 with no trail configured", rec.Code)
	}
}
