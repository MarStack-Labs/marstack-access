package session

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/store"
)

const (
	sessionA  = "ses-0000000000001"
	sessionB  = "ses-0000000000002"
	aliceID   = "usr-0000000000001"
	bobID     = "usr-0000000000002"
	rootID    = "usr-0000000000003"
	dbTarget  = "tgt-0000000000001"
	recording = "/data/recordings/ses-0000000000001.cast"
)

var (
	alice = authz.Identity{UserID: aliceID, Name: "alice", Role: authz.RoleOperator}
	bob   = authz.Identity{UserID: bobID, Name: "bob", Role: authz.RoleOperator}
	root  = authz.Identity{UserID: rootID, Name: "root", Role: authz.RoleAdmin}
)

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	return c.at
}

type stubTerminator struct {
	live map[string]bool
	seen []string
}

func (s *stubTerminator) Kill(sessionID string) bool {
	s.seen = append(s.seen, sessionID)
	return s.live[sessionID]
}

type recordingGuard struct {
	roles []string
}

func (g *recordingGuard) Require(role string, next http.Handler) http.Handler {
	g.roles = append(g.roles, role)
	return next
}

func newTestModule(t *testing.T, terminator Terminator) (*Module, *clock) {
	t.Helper()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, terminator)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	c := &clock{at: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)}
	m.service.now = c.now
	return m, c
}

func openInput(id, userID string) OpenInput {
	return OpenInput{
		ID:           id,
		UserID:       userID,
		UserName:     "alice",
		TargetID:     dbTarget,
		TargetName:   "db-1",
		Principal:    "deploy",
		CredentialID: "key-0000000000001",
		RemoteAddr:   "10.1.1.1:52344",
		Recording:    recording,
	}
}

func mustOpen(t *testing.T, m *Module, id, userID string) {
	t.Helper()

	if err := m.Open(context.Background(), openInput(id, userID)); err != nil {
		t.Fatalf("open %s: %v", id, err)
	}
}

func faultOf(t *testing.T, err error) *fault.Fault {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
	return fault.From(err)
}

func TestAnOpenSessionIsActiveUntilItIsClosed(t *testing.T) {
	m, c := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	record, err := m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !record.active() {
		t.Fatal("a freshly opened session is not active")
	}
	if record.Recording != recording {
		t.Errorf("recording = %q, want %q", record.Recording, recording)
	}

	c.at = c.at.Add(90 * time.Second)
	if err := m.Close(ctx, sessionA, CloseInput{ExitCode: 0, Reason: "target exit status", RecordedBytes: 4096}); err != nil {
		t.Fatalf("close: %v", err)
	}

	record, err = m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get after close: %v", err)
	}
	if record.active() {
		t.Fatal("a closed session still reports active")
	}
	if record.RecordedBytes != 4096 {
		t.Errorf("recorded bytes = %d, want 4096", record.RecordedBytes)
	}
	if !record.EndedAt.Equal(c.at) {
		t.Errorf("ended_at = %v, want %v", record.EndedAt, c.at)
	}
}

func TestClosingTwiceIsAConflict(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	if err := m.Close(ctx, sessionA, CloseInput{Reason: "first"}); err != nil {
		t.Fatalf("first close: %v", err)
	}

	err := m.Close(ctx, sessionA, CloseInput{Reason: "second"})
	if got := faultOf(t, err); got.Kind != fault.KindConflict {
		t.Fatalf("kind = %v, want KindConflict: a second close would overwrite the real end time and reason", got.Kind)
	}

	record, err := m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if record.Reason != "first" {
		t.Fatalf("reason = %q, want the first close to stand", record.Reason)
	}
}

func TestOpenRefusesAnIncompleteRecord(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()

	cases := map[string]func(*OpenInput){
		"bad session id": func(in *OpenInput) { in.ID = "banana" },
		"bad user id":    func(in *OpenInput) { in.UserID = "alice" },
		"bad target id":  func(in *OpenInput) { in.TargetID = "db-1" },
		"no principal":   func(in *OpenInput) { in.Principal = "" },
		"no recording":   func(in *OpenInput) { in.Recording = "" },
	}

	for label, mutate := range cases {
		in := openInput(sessionA, aliceID)
		mutate(&in)

		if err := m.Open(ctx, in); err == nil {
			t.Errorf("%s: Open accepted the record", label)
		}
	}
}

func TestReconcileClosesSessionsLeftOpenByACrash(t *testing.T) {
	m, c := newTestModule(t, nil)
	ctx := context.Background()

	mustOpen(t, m, sessionA, aliceID)
	mustOpen(t, m, sessionB, bobID)
	if err := m.Close(ctx, sessionB, CloseInput{Reason: "clean exit"}); err != nil {
		t.Fatalf("close: %v", err)
	}

	c.at = c.at.Add(time.Hour)
	if err := m.Reconcile(ctx); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	dangling, err := m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if dangling.active() {
		t.Fatal("a session left open by an earlier run is still active. The data plane holds no state, so any open row at startup is a phantom that can never be killed")
	}
	if dangling.Reason != ReasonGatewayRestarted {
		t.Errorf("reason = %q, want %q", dangling.Reason, ReasonGatewayRestarted)
	}
	if dangling.ExitCode != -1 {
		t.Errorf("exit code = %d, want -1 so it is not mistaken for a clean exit", dangling.ExitCode)
	}

	clean, err := m.service.get(ctx, root, sessionB)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if clean.Reason != "clean exit" {
		t.Fatalf("reason = %q, want reconcile to leave an already-closed session alone", clean.Reason)
	}
}

func TestReconcileIsSafeOnAnEmptyStore(t *testing.T) {
	m, _ := newTestModule(t, nil)

	if err := m.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
}

func TestAnOperatorSeesOnlyItsOwnSessions(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)
	mustOpen(t, m, sessionB, bobID)

	forAlice, err := m.service.list(ctx, alice)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(forAlice) != 1 || forAlice[0].UserID != aliceID {
		t.Fatalf("alice sees %d sessions, want only her own", len(forAlice))
	}

	if _, err := m.service.get(ctx, bob, sessionA); faultOf(t, err).Kind != fault.KindNotFound {
		t.Fatal("bob could read alice's session. A 403 would confirm the id exists and leak who is connected to what")
	}

	forRoot, err := m.service.list(ctx, root)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(forRoot) != 2 {
		t.Fatalf("admin sees %d sessions, want 2", len(forRoot))
	}
}

func TestKillClosesALiveSocketAndSaysSo(t *testing.T) {
	terminator := &stubTerminator{live: map[string]bool{sessionA: true}}
	m, _ := newTestModule(t, terminator)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	record, killed, err := m.service.kill(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if !killed {
		t.Fatal("kill reported no live session")
	}
	if record.ID != sessionA {
		t.Fatalf("record = %+v, want the killed session", record)
	}
	if len(terminator.seen) != 1 || terminator.seen[0] != sessionA {
		t.Fatalf("terminator saw %v, want [%s]", terminator.seen, sessionA)
	}
}

func TestKillOnAnOpenRowWithNoLiveSocketReportsFalse(t *testing.T) {
	terminator := &stubTerminator{live: map[string]bool{}}
	m, _ := newTestModule(t, terminator)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	_, killed, err := m.service.kill(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("kill: %v", err)
	}
	if killed {
		t.Fatal("kill claimed success with no socket to close")
	}
}

func TestKillingAClosedSessionIsAConflict(t *testing.T) {
	terminator := &stubTerminator{live: map[string]bool{sessionA: true}}
	m, _ := newTestModule(t, terminator)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)
	if err := m.Close(ctx, sessionA, CloseInput{Reason: "done"}); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, _, err := m.service.kill(ctx, root, sessionA)
	if got := faultOf(t, err); got.Kind != fault.KindConflict {
		t.Fatalf("kind = %v, want KindConflict", got.Kind)
	}
	if len(terminator.seen) != 0 {
		t.Fatal("the terminator was asked to close an already-ended session")
	}
}

func TestKillWithNoDataPlaneSaysWhy(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	_, _, err := m.service.kill(ctx, root, sessionA)
	got := faultOf(t, err)
	if got.Kind != fault.KindUnavailable || got.Code != "no_data_plane" {
		t.Fatalf("fault = %+v, want an explicit no_data_plane. Reporting a silent false would look like the session had already ended",
			got)
	}
}

func TestAnOperatorCannotKillEvenItsOwnSession(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	guard := &recordingGuard{}
	New(st, logging.New("error", io.Discard), guard, nil).Routes(http.NewServeMux())

	operators, admins := 0, 0
	for _, role := range guard.roles {
		switch role {
		case authz.RoleOperator:
			operators++
		case authz.RoleAdmin:
			admins++
		default:
			t.Errorf("a route requires the unexpected role %q", role)
		}
	}

	if operators != 2 {
		t.Errorf("%d routes at operator, want 2: listing and reading", operators)
	}
	if admins != 1 {
		t.Errorf("%d routes at admin, want 1: the kill switch is for the incident responder", admins)
	}
}

func TestTheViewReportsActivityAndOmitsWhatHasNotHappened(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	record, err := m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}

	encoded, err := json.Marshal(viewOf(record))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(encoded)

	if !strings.Contains(body, `"active":true`) {
		t.Errorf("view does not report the session as active: %s", body)
	}
	for _, absent := range []string{"ended_at", "exit_code"} {
		if strings.Contains(body, absent) {
			t.Errorf("an open session reports %q: %s", absent, body)
		}
	}

	if err := m.Close(ctx, sessionA, CloseInput{ExitCode: 0, Reason: "target exit status"}); err != nil {
		t.Fatalf("close: %v", err)
	}
	record, _ = m.service.get(ctx, root, sessionA)
	encoded, _ = json.Marshal(viewOf(record))
	body = string(encoded)

	if !strings.Contains(body, `"exit_code":0`) {
		t.Fatalf("a clean exit does not report exit_code 0: %s. Omitting it would make a successful session indistinguishable from one still running",
			body)
	}
}

func TestAnUnauthenticatedRouteFailsClosed(t *testing.T) {
	m, _ := newTestModule(t, nil)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)

	if err := m.handleList(rec, r); err == nil {
		t.Fatal("a handler ran with no identity on the context")
	}
}

func TestAMalformedIDIsRejectedBeforeTheDatabase(t *testing.T) {
	m, _ := newTestModule(t, nil)

	for _, id := range []string{"banana", "usr-abc", "ses", "1"} {
		if _, err := m.service.get(context.Background(), root, id); faultOf(t, err).Kind != fault.KindInvalid {
			t.Errorf("id %q was not rejected as malformed", id)
		}
	}
}

func TestALongCloseReasonIsTrimmedRatherThanRejected(t *testing.T) {
	m, _ := newTestModule(t, nil)
	ctx := context.Background()
	mustOpen(t, m, sessionA, aliceID)

	if err := m.Close(ctx, sessionA, CloseInput{Reason: strings.Repeat("a", maxReasonLen*3)}); err != nil {
		t.Fatalf("close: %v", err)
	}

	record, err := m.service.get(ctx, root, sessionA)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(record.Reason) > maxReasonLen {
		t.Fatalf("reason is %d characters, want at most %d", len(record.Reason), maxReasonLen)
	}
	if record.Reason == "" {
		t.Fatal("the reason was dropped entirely. A close must never fail on the reason, because failing would leave the session listed as active")
	}
}

func TestMigrationsAreOwnedByThisModule(t *testing.T) {
	m, _ := newTestModule(t, nil)

	for _, migration := range m.Migrations() {
		if migration.Module != m.Name() {
			t.Errorf("migration %d is owned by %q, want %q", migration.Index, migration.Module, m.Name())
		}
	}
}
