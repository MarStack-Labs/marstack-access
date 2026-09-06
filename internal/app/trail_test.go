package app

import (
	"context"
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

func TestARefusedRequestCarriesNoExpiryInTheTrail(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	operator := tokenForRole(t, a, admin, "asker", "operator")
	targetID, _ := decodeBody(t, send(t, a, http.MethodPost, "/v1/targets", admin,
		`{"name":"host-1","address":"10.0.0.9","principals":["deploy"]}`))["id"].(string)
	send(t, a, http.MethodPost, "/v1/policies", admin,
		`{"name":"p","subject_kind":"user","subject_id":"`+userOf(t, a, admin, "asker")+
			`","target_id":"`+targetID+`","principals":["deploy"]}`)

	created := send(t, a, http.MethodPost, "/v1/access-requests", operator,
		`{"target_id":"`+targetID+`","principal":"deploy","reason":"a reason","ttl":"1h"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("raise request: status = %d (%s)", created.Code, created.Body)
	}
	id, _ := decodeBody(t, created)["id"].(string)

	if rec := send(t, a, http.MethodPost, "/v1/access-requests/"+id+"/deny", admin, ""); rec.Code != http.StatusOK {
		t.Fatalf("deny: status = %d (%s)", rec.Code, rec.Body)
	}

	body := send(t, a, http.MethodGet, "/v1/audit", admin, "").Body.String()
	if strings.Contains(body, "0001-01-01") {
		t.Fatal("a denied request recorded the zero time as its grant expiry. " +
			"In a trail that reads as a real timestamp, not as an absent one")
	}
	if !strings.Contains(body, "request.denied") {
		t.Fatal("the denial was not recorded at all")
	}
}

func userOf(t *testing.T, a *App, admin, name string) string {
	t.Helper()

	listed := decodeBody(t, send(t, a, http.MethodGet, "/v1/users", admin, ""))
	for _, raw := range listed["users"].([]any) {
		user := raw.(map[string]any)
		if user["name"] == name {
			return user["id"].(string)
		}
	}
	t.Fatalf("user %q was not found", name)
	return ""
}

func openSessionRow(t *testing.T, a *App, id string) {
	t.Helper()

	_, err := a.store.DB().ExecContext(context.Background(),
		`INSERT INTO sessions
		 (id, user_id, user_name, target_id, target_name, principal, credential_id,
		  remote_addr, recording, started_at, recorded_bytes)
		 VALUES (?, 'usr-1', 'rina', 'tgt-1', 'db-1', 'deploy', 'tok-1',
		         '203.0.113.9:5000', 'rec/x.cast', '2026-01-01T00:00:00Z', 0)`, id)
	if err != nil {
		t.Fatalf("insert session row: %v", err)
	}
}

func TestAKillThatClosedNothingIsNotRecordedAsAnError(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	openSessionRow(t, a, "ses-0000000000001")

	rec := send(t, a, http.MethodPost, "/v1/sessions/ses-0000000000001/kill", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("kill: status = %d (%s)", rec.Code, rec.Body)
	}
	if killed, _ := decodeBody(t, rec)["killed"].(bool); killed {
		t.Fatal("a row with no live socket reported that it was closed")
	}

	events := eventsIn(t, decodeBody(t, send(t, a, http.MethodGet, "/v1/audit", admin, "")))

	var kill map[string]any
	for _, e := range events {
		if e["action"] == "session.killed" {
			kill = e
		}
	}
	if kill == nil {
		t.Fatal("the kill was not recorded at all, so this test proves nothing")
	}

	if kill["outcome"] == "error" {
		t.Error("killing a row with no live socket was recorded as an error. Anyone alerting on " +
			"outcome=error is then paged every time an operator tidies up a stale row, and the " +
			"real errors are lost among them")
	}

	fields, _ := kill["fields"].(map[string]any)
	if fields["closed"] != "false" {
		t.Errorf("the record does not say whether anything was actually closed: %v", fields)
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
