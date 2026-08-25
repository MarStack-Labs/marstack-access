package authz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func guardFor(id Identity, err error) *Guard {
	return New(AuthenticatorFunc(func(context.Context, string) (Identity, error) {
		return id, err
	}), discardLogger())
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
	want := Identity{UserID: "usr-abc", Name: "umar", Role: RoleAdmin, TokenID: "tok-abc"}
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
