package approval

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
	dbTarget = "tgt-0000000000001"
	aliceID  = "usr-0000000000001"
	bobID    = "usr-0000000000002"
	rootID   = "usr-0000000000003"
)

var (
	alice = authz.Identity{UserID: aliceID, Name: "alice", Role: authz.RoleOperator}
	bob   = authz.Identity{UserID: bobID, Name: "bob", Role: authz.RoleOperator}
	root  = authz.Identity{UserID: rootID, Name: "root", Role: authz.RoleAdmin}
)

type stubPolicies struct {
	denied bool
}

func (s stubPolicies) Authorize(context.Context, authz.Identity, string, string) error {
	if s.denied {
		return fault.Forbidden("no_policy", "no policy grants this")
	}
	return nil
}

type clock struct {
	at time.Time
}

func (c *clock) now() time.Time {
	return c.at
}

type recordingGuard struct {
	roles []string
}

func (g *recordingGuard) Require(role string, next http.Handler) http.Handler {
	g.roles = append(g.roles, role)
	return next
}

func newTestModule(t *testing.T, policies Policies) (*Module, *clock) {
	t.Helper()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, policies)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	c := &clock{at: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)}
	m.service.now = c.now
	return m, c
}

func newAllowingModule(t *testing.T) (*Module, *clock) {
	t.Helper()

	return newTestModule(t, stubPolicies{})
}

func mustCreate(t *testing.T, m *Module, requester authz.Identity, ttl time.Duration) Request {
	t.Helper()

	req, err := m.service.create(context.Background(), requester, CreateInput{
		TargetID:  dbTarget,
		Principal: "deploy",
		Reason:    "incident 42",
		GrantTTL:  ttl,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return req
}

func faultOf(t *testing.T, err error) *fault.Fault {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error")
	}
	return fault.From(err)
}

func TestCreateStartsPending(t *testing.T) {
	m, c := newAllowingModule(t)

	req := mustCreate(t, m, alice, 2*time.Hour)

	if !strings.HasPrefix(req.ID, idPrefix+"-") {
		t.Errorf("id = %q, want a %s- prefix", req.ID, idPrefix)
	}
	if req.State != StatePending {
		t.Errorf("state = %q, want pending", req.State)
	}
	if req.RequesterID != aliceID {
		t.Errorf("requester = %q, want %q", req.RequesterID, aliceID)
	}
	if !req.GrantExpiresAt.IsZero() {
		t.Error("a pending request already carries a grant expiry")
	}
	if want := c.at.Add(pendingWindow); !req.RequestExpiresAt.Equal(want) {
		t.Errorf("request_expires_at = %v, want %v: a pending request must not linger forever",
			req.RequestExpiresAt, want)
	}
}

func TestCreateRefusesWhatPolicyForbids(t *testing.T) {
	m, _ := newTestModule(t, stubPolicies{denied: true})

	_, err := m.service.create(context.Background(), alice, CreateInput{
		TargetID: dbTarget, Principal: "deploy", Reason: "incident 42",
	})

	if got := faultOf(t, err); got.Kind != fault.KindForbidden {
		t.Fatalf("kind = %v, want KindForbidden: a request policy can never permit would invite a rubber stamp that bypasses policy",
			got.Kind)
	}
}

func TestCreateRequiresAReason(t *testing.T) {
	m, _ := newAllowingModule(t)

	for label, reason := range map[string]string{
		"empty":      "",
		"whitespace": "   \t\n ",
		"too long":   strings.Repeat("a", maxReasonLen+1),
	} {
		_, err := m.service.create(context.Background(), alice, CreateInput{
			TargetID: dbTarget, Principal: "deploy", Reason: reason,
		})
		if got := faultOf(t, err); got.Kind != fault.KindInvalid {
			t.Errorf("%s reason: kind = %v, want KindInvalid", label, got.Kind)
		}
	}
}

func TestCreateValidatesTargetPrincipalAndTTL(t *testing.T) {
	m, _ := newAllowingModule(t)

	cases := map[string]CreateInput{
		"target malformed": {TargetID: "db-1", Principal: "deploy", Reason: "r"},
		"principal comma":  {TargetID: dbTarget, Principal: "deploy,root", Reason: "r"},
		"principal empty":  {TargetID: dbTarget, Principal: "", Reason: "r"},
		"ttl negative":     {TargetID: dbTarget, Principal: "deploy", Reason: "r", GrantTTL: -time.Second},
		"ttl too long":     {TargetID: dbTarget, Principal: "deploy", Reason: "r", GrantTTL: maxGrantTTL + time.Second},
	}

	for label, in := range cases {
		if _, err := m.service.create(context.Background(), alice, in); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestTTLDefaultsWhenUnset(t *testing.T) {
	m, _ := newAllowingModule(t)

	req := mustCreate(t, m, alice, 0)

	if req.GrantTTL != defaultGrantTTL {
		t.Fatalf("grant ttl = %s, want the %s default", req.GrantTTL, defaultGrantTTL)
	}
}

func TestARequesterCannotApproveItsOwnRequest(t *testing.T) {
	m, _ := newAllowingModule(t)
	req := mustCreate(t, m, alice, time.Hour)

	selfApprover := authz.Identity{UserID: aliceID, Name: "alice", Role: authz.RoleAdmin}

	_, err := m.service.approve(context.Background(), selfApprover, req.ID)

	got := faultOf(t, err)
	if got.Kind != fault.KindForbidden || got.Code != "self_approval" {
		t.Fatalf("fault = %+v, want a self_approval refusal. Being an admin must not make you your own approver, or the whole gate is a formality",
			got)
	}
}

func TestARequesterCannotDenyItsOwnRequestEither(t *testing.T) {
	m, _ := newAllowingModule(t)
	req := mustCreate(t, m, alice, time.Hour)

	selfApprover := authz.Identity{UserID: aliceID, Role: authz.RoleAdmin}

	if _, err := m.service.deny(context.Background(), selfApprover, req.ID); err == nil {
		t.Fatal("a requester denied its own request. Deciding is deciding, and letting a requester close its own record hides it from an approver's queue")
	}
}

func TestApprovalOpensATimeBoxedGrant(t *testing.T) {
	m, c := newAllowingModule(t)
	req := mustCreate(t, m, alice, 2*time.Hour)
	ctx := context.Background()

	approved, err := m.service.approve(ctx, root, req.ID)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}

	if approved.DecidedBy != rootID {
		t.Errorf("decided_by = %q, want %q", approved.DecidedBy, rootID)
	}
	if want := c.at.Add(2 * time.Hour); !approved.GrantExpiresAt.Equal(want) {
		t.Errorf("grant_expires_at = %v, want %v", approved.GrantExpiresAt, want)
	}

	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err != nil {
		t.Fatalf("the grant is not active right after approval: %v", err)
	}
}

func TestAGrantExpiresExactlyAtItsDeadline(t *testing.T) {
	m, c := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.approve(ctx, root, req.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	c.at = c.at.Add(time.Hour - time.Second)
	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err != nil {
		t.Fatalf("refused one second before expiry: %v", err)
	}

	c.at = c.at.Add(time.Second)
	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err == nil {
		t.Fatal("the grant survived its own deadline: the window must be half-open")
	}
}

func TestAGrantIsScopedToItsRequesterTargetAndPrincipal(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.approve(ctx, root, req.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	cases := map[string]GrantQuery{
		"another user":      {UserID: bobID, TargetID: dbTarget, Principal: "deploy"},
		"another target":    {UserID: aliceID, TargetID: "tgt-0000000000002", Principal: "deploy"},
		"another principal": {UserID: aliceID, TargetID: dbTarget, Principal: "postgres"},
	}

	for label, q := range cases {
		if err := m.service.HasGrant(ctx, q.UserID, q.TargetID, q.Principal); err == nil {
			t.Errorf("%s: the grant leaked", label)
		}
	}
}

func TestADeniedRequestGrantsNothing(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.deny(ctx, root, req.ID); err != nil {
		t.Fatalf("deny: %v", err)
	}

	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err == nil {
		t.Fatal("a denied request granted access")
	}
}

func TestAPendingRequestGrantsNothing(t *testing.T) {
	m, _ := newAllowingModule(t)
	mustCreate(t, m, alice, time.Hour)

	if err := m.service.HasGrant(context.Background(), aliceID, dbTarget, "deploy"); err == nil {
		t.Fatal("a request nobody has approved granted access")
	}
}

func TestAnExpiredRequestCannotBeApproved(t *testing.T) {
	m, c := newAllowingModule(t)
	req := mustCreate(t, m, alice, time.Hour)

	c.at = c.at.Add(pendingWindow + time.Second)

	_, err := m.service.approve(context.Background(), root, req.ID)
	got := faultOf(t, err)
	if got.Kind != fault.KindConflict || got.Code != "not_pending" {
		t.Fatalf("fault = %+v, want a not_pending conflict. A request approved a week later is a surprise, not a grant",
			got)
	}
}

func TestARequestCannotBeDecidedTwice(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.approve(ctx, root, req.ID); err != nil {
		t.Fatalf("first approve: %v", err)
	}

	if _, err := m.service.deny(ctx, root, req.ID); err == nil {
		t.Fatal("an approved request was then denied, which would silently move the grant expiry")
	}
}

func TestOnlyTheRequesterMayCancel(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	_, err := m.service.cancel(ctx, root, req.ID)
	if got := faultOf(t, err); got.Code != "not_the_requester" {
		t.Fatalf("code = %q, want not_the_requester: an admin cancelling instead of denying loses the decision record", got.Code)
	}

	if _, err := m.service.cancel(ctx, alice, req.ID); err != nil {
		t.Fatalf("the requester could not cancel: %v", err)
	}
}

func TestACancelledRequestGrantsNothingAndCannotBeApproved(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.cancel(ctx, alice, req.ID); err != nil {
		t.Fatalf("cancel: %v", err)
	}
	if _, err := m.service.approve(ctx, root, req.ID); err == nil {
		t.Fatal("a cancelled request was approved")
	}
	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err == nil {
		t.Fatal("a cancelled request granted access")
	}
}

func TestAnOperatorCannotSeeAnotherOperatorsRequest(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	_, err := m.service.get(ctx, bob, req.ID)
	got := faultOf(t, err)
	if got.Kind != fault.KindNotFound {
		t.Fatalf("kind = %v, want KindNotFound. A 403 here would confirm the id exists, which leaks who is asking for access to what",
			got.Kind)
	}
}

func TestAnAdminCanSeeAnyRequest(t *testing.T) {
	m, _ := newAllowingModule(t)
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.get(context.Background(), root, req.ID); err != nil {
		t.Fatalf("an admin could not read a request it must decide: %v", err)
	}
}

func TestListIsScopedForOperatorsAndCompleteForAdmins(t *testing.T) {
	m, _ := newAllowingModule(t)
	ctx := context.Background()

	mustCreate(t, m, alice, time.Hour)
	mustCreate(t, m, bob, time.Hour)

	forAlice, err := m.service.list(ctx, alice)
	if err != nil {
		t.Fatalf("list for alice: %v", err)
	}
	if len(forAlice) != 1 || forAlice[0].RequesterID != aliceID {
		t.Fatalf("alice sees %d requests: an operator must see only its own", len(forAlice))
	}

	forRoot, err := m.service.list(ctx, root)
	if err != nil {
		t.Fatalf("list for root: %v", err)
	}
	if len(forRoot) != 2 {
		t.Fatalf("admin sees %d requests, want 2", len(forRoot))
	}
}

func TestEffectiveStateIsDerivedNotStored(t *testing.T) {
	m, c := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if got := m.viewOf(req).State; got != StatePending {
		t.Fatalf("state = %q, want pending", got)
	}

	c.at = c.at.Add(pendingWindow + time.Second)

	stored, err := m.service.repo.get(ctx, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.State != StatePending {
		t.Fatalf("the stored state changed to %q without anything writing to it", stored.State)
	}
	if got := m.viewOf(stored).State; got != StateExpired {
		t.Fatalf("reported state = %q, want expired. Expiry is derived from the clock so no reaper job is needed and a stopped reaper cannot leave a live grant",
			got)
	}
}

func TestAMalformedIDIsRejectedBeforeTheDatabase(t *testing.T) {
	m, _ := newAllowingModule(t)

	for _, id := range []string{"banana", "usr-abc", "req", "1"} {
		_, err := m.service.get(context.Background(), root, id)
		if got := faultOf(t, err); got.Kind != fault.KindInvalid {
			t.Errorf("id %q: kind = %v, want KindInvalid", id, got.Kind)
		}
	}
}

func TestGrantQueryValidatesItsInput(t *testing.T) {
	m, _ := newAllowingModule(t)

	cases := map[string]GrantQuery{
		"user malformed":   {UserID: "alice", TargetID: dbTarget, Principal: "deploy"},
		"target malformed": {UserID: aliceID, TargetID: "db-1", Principal: "deploy"},
		"principal comma":  {UserID: aliceID, TargetID: dbTarget, Principal: "a,b"},
	}

	for label, q := range cases {
		if _, err := m.service.grant(context.Background(), q); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestTheLatestGrantWinsWhenTwoOverlap(t *testing.T) {
	m, c := newAllowingModule(t)
	ctx := context.Background()

	short := mustCreate(t, m, alice, time.Hour)
	long := mustCreate(t, m, alice, 4*time.Hour)

	if _, err := m.service.approve(ctx, root, short.ID); err != nil {
		t.Fatalf("approve short: %v", err)
	}
	if _, err := m.service.approve(ctx, root, long.ID); err != nil {
		t.Fatalf("approve long: %v", err)
	}

	c.at = c.at.Add(2 * time.Hour)

	g, err := m.service.grant(ctx, GrantQuery{UserID: aliceID, TargetID: dbTarget, Principal: "deploy"})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if !g.Active || g.RequestID != long.ID {
		t.Fatalf("grant = %+v, want the longer-lived request %s", g, long.ID)
	}
}

func TestRequestingAndApprovingRoutesSplitByRole(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	guard := &recordingGuard{}
	New(st, logging.New("error", io.Discard), guard, stubPolicies{}).Routes(http.NewServeMux())

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

	if operators != 4 {
		t.Errorf("%d routes at operator, want 4: raising, listing, reading and cancelling one's own request", operators)
	}
	if admins != 3 {
		t.Errorf("%d routes at admin, want 3: approve, deny and the grant check", admins)
	}
}

func TestARouteReachedWithoutAnIdentityFailsClosed(t *testing.T) {
	m, _ := newAllowingModule(t)

	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/access-requests", nil)

	if err := m.handleList(rec, r); err == nil {
		t.Fatal("a handler ran with no identity on the context. If a route is ever registered without the guard, it must fail rather than act as somebody")
	}
}

func TestTheViewNeverInventsAGrantExpiry(t *testing.T) {
	m, _ := newAllowingModule(t)
	req := mustCreate(t, m, alice, time.Hour)

	encoded, err := json.Marshal(m.viewOf(req))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "grant_expires_at") {
		t.Fatalf("a pending request reports a grant expiry: %s", encoded)
	}
}

func TestMigrationsAreOwnedByThisModule(t *testing.T) {
	m, _ := newAllowingModule(t)

	for _, migration := range m.Migrations() {
		if migration.Module != m.Name() {
			t.Errorf("migration %d is owned by %q, want %q", migration.Index, migration.Module, m.Name())
		}
	}
}

func TestAGrantRowStoredWithAnOffsetTimezoneIsStillRefusedWhenExpired(t *testing.T) {
	m, c := newAllowingModule(t)
	ctx := context.Background()
	req := mustCreate(t, m, alice, time.Hour)

	if _, err := m.service.approve(ctx, root, req.ID); err != nil {
		t.Fatalf("approve: %v", err)
	}

	expired := c.at.Add(-time.Hour).In(time.FixedZone("WIB", 7*60*60))
	if _, err := m.service.repo.db.ExecContext(ctx,
		`UPDATE access_requests SET grant_expires_at = ? WHERE id = ?`,
		expired.Format(time.RFC3339), req.ID); err != nil {
		t.Fatalf("rewrite expiry: %v", err)
	}

	if err := m.service.HasGrant(ctx, aliceID, dbTarget, "deploy"); err == nil {
		t.Fatal("an expired grant whose row was written in a non-UTC offset was accepted. The SQL filter compares RFC3339 strings, so the parsed time.Time has to be checked again in Go")
	}
}
