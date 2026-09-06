package app

import (
	"net/http"
	"strings"
	"testing"
)

func eventsIn(t *testing.T, body map[string]any) []map[string]any {
	t.Helper()

	raw, ok := body["events"].([]any)
	if !ok {
		t.Fatalf("body has no events array: %v", body)
	}

	events := make([]map[string]any, 0, len(raw))
	for _, e := range raw {
		events = append(events, e.(map[string]any))
	}
	return events
}

func TestTheAuditTrailIsReadableByAnAdmin(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	tokenForRole(t, a, admin, "someone", "operator")

	rec := send(t, a, http.MethodGet, "/v1/audit", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}

	events := eventsIn(t, decodeBody(t, rec))
	if len(events) == 0 {
		t.Fatal("the trail is empty after creating a user and issuing a token")
	}

	seen := map[string]bool{}
	for _, e := range events {
		seen[e["action"].(string)] = true
	}
	for _, want := range []string{"user.created", "token.issued"} {
		if !seen[want] {
			t.Errorf("the trail does not carry %q, so the screen built on it shows nothing useful", want)
		}
	}
}

func TestTheNewestAuditEventComesFirst(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	tokenForRole(t, a, admin, "someone", "operator")

	rec := send(t, a, http.MethodGet, "/v1/audit", admin, "")
	events := eventsIn(t, decodeBody(t, rec))

	if len(events) < 2 {
		t.Fatalf("got %d events, want at least 2", len(events))
	}
	if events[0]["action"] != "token.issued" {
		t.Fatalf("first event = %v, want token.issued: a reader opens this to see what just happened",
			events[0]["action"])
	}
}

func TestAnOperatorCannotReadTheAuditTrail(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "someone", "operator")

	rec := send(t, a, http.MethodGet, "/v1/audit", operator, "")

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the trail names who did what, "+
			"and an operator reading it learns which accounts are worth attacking", rec.Code)
	}
}

func TestTheAuditTrailNeedsAToken(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/v1/audit")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAnAuditLimitBeyondTheCapIsRefusedRatherThanClamped(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	rec := send(t, a, http.MethodGet, "/v1/audit?limit=100000", admin, "")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: silently returning fewer rows than asked for "+
			"reads as an empty trail rather than a refused request", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "invalid_limit") {
		t.Fatalf("body does not name the problem: %s", rec.Body)
	}
}

func TestAnAuditLimitThatIsNotANumberIsRefused(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	for _, limit := range []string{"abc", "0", "-5", "1.5"} {
		rec := send(t, a, http.MethodGet, "/v1/audit?limit="+limit, admin, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("limit=%s: status = %d, want 400", limit, rec.Code)
		}
	}
}

func TestTheAuditLimitIsHonoured(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	for _, name := range []string{"a", "b", "c", "d"} {
		tokenForRole(t, a, admin, name, "operator")
	}

	rec := send(t, a, http.MethodGet, "/v1/audit?limit=2", admin, "")
	events := eventsIn(t, decodeBody(t, rec))

	if len(events) != 2 {
		t.Fatalf("got %d events, want 2", len(events))
	}
}

func TestTheAuditViewSaysWhetherTheTrailLeavesThisHost(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	body := decodeBody(t, send(t, a, http.MethodGet, "/v1/audit", admin, ""))

	shipped, ok := body["shipped"].(bool)
	if !ok {
		t.Fatalf("the view does not say whether the trail is shipped: %v", body)
	}
	if shipped {
		t.Error("shipped is true with no Loki url configured. A reader must not be told " +
			"the trail survives this host when it does not")
	}
}

func TestReadingTheAuditTrailIsNotItselfRecorded(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	tokenForRole(t, a, admin, "someone", "operator")

	before := len(eventsIn(t, decodeBody(t, send(t, a, http.MethodGet, "/v1/audit", admin, ""))))
	send(t, a, http.MethodGet, "/v1/audit", admin, "")
	after := len(eventsIn(t, decodeBody(t, send(t, a, http.MethodGet, "/v1/audit", admin, ""))))

	if after != before {
		t.Fatalf("the trail grew from %d to %d just by being read. A console polling this screen "+
			"would fill the trail with records of itself", before, after)
	}
}

func TestNoAuditResponseCarriesATokenSecret(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "someone", "operator")

	rec := send(t, a, http.MethodGet, "/v1/audit?limit="+"500", admin, "")

	body := rec.Body.String()
	if strings.Contains(body, operator) || strings.Contains(body, admin) {
		t.Fatal("the audit response carries a token secret")
	}
	if strings.Contains(body, "mat_") {
		t.Fatalf("the audit response carries something shaped like a token: %s", body)
	}
}
