package policy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/fault"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/store"
)

const (
	dbTarget  = "tgt-0000000000001"
	webTarget = "tgt-0000000000002"
	aliceID   = "usr-0000000000001"
	bobID     = "usr-0000000000002"
)

type stubTargets struct {
	principals map[string][]string
}

func (s stubTargets) Principals(_ context.Context, targetID string) ([]string, error) {
	p, ok := s.principals[targetID]
	if !ok {
		return nil, fault.NotFound("target_not_found", "no target with that id is registered")
	}
	return p, nil
}

type recordingGuard struct {
	roles []string
}

func (g *recordingGuard) Require(role string, next http.Handler) http.Handler {
	g.roles = append(g.roles, role)
	return next
}

func newTestModule(t *testing.T) (*Module, http.Handler) {
	t.Helper()

	trail := &recordingTrail{}
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	targets := stubTargets{principals: map[string][]string{
		dbTarget:  {"deploy", "postgres"},
		webTarget: {"deploy", "www"},
	}}

	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, targets, trail)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	m.Routes(mux)
	return m, mux
}

func send(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, reader)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func createPolicy(t *testing.T, h http.Handler, body string) policyView {
	t.Helper()

	rec := send(t, h, http.MethodPost, "/v1/policies", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: status = %d, want 201 (%s)", rec.Code, rec.Body)
	}

	var view policyView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view
}

func evaluate(t *testing.T, h http.Handler, body string) decisionView {
	t.Helper()

	rec := send(t, h, http.MethodPost, "/v1/policies/evaluate", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("evaluate: status = %d, want 200 (%s)", rec.Code, rec.Body)
	}

	var view decisionView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return view
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("body is not an error envelope: %v (%s)", err, rec.Body)
	}
	return parsed.Error.Code
}

func TestCreateStoresThePolicy(t *testing.T) {
	_, h := newTestModule(t)

	view := createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["postgres","deploy"]}`)

	if !strings.HasPrefix(view.ID, idPrefix+"-") {
		t.Errorf("id = %q, want a %s- prefix", view.ID, idPrefix)
	}
	if view.SubjectKind != SubjectUser || view.SubjectID != aliceID || view.TargetID != dbTarget {
		t.Errorf("view = %+v", view)
	}
	if strings.Join(view.Principals, ",") != "deploy,postgres" {
		t.Errorf("principals = %v, want them sorted and deduplicated", view.Principals)
	}
	if _, err := time.Parse(time.RFC3339, view.CreatedAt); err != nil {
		t.Errorf("created_at = %q is not RFC3339", view.CreatedAt)
	}
}

func TestCreateRejectsAPrincipalTheTargetDoesNotAccept(t *testing.T) {
	_, h := newTestModule(t)

	rec := send(t, h, http.MethodPost, "/v1/policies",
		`{"name":"db-root","subject_kind":"user","subject_id":"`+aliceID+
			`","target_id":"`+dbTarget+`","principals":["root"]}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: granting a principal the target will refuse is a policy that silently never works", rec.Code)
	}
	if got := errorCode(t, rec); got != "principal_not_accepted" {
		t.Fatalf("code = %q, want principal_not_accepted", got)
	}
}

func TestCreateRejectsAnUnknownTarget(t *testing.T) {
	_, h := newTestModule(t)

	rec := send(t, h, http.MethodPost, "/v1/policies",
		`{"name":"ghost","subject_kind":"user","subject_id":"`+aliceID+
			`","target_id":"tgt-9999999999999","principals":["deploy"]}`)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: a typo in a target id must fail at create time, not silently at session time", rec.Code)
	}
}

func TestCreateRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty name":         `{"name":"","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"unknown kind":       `{"name":"p","subject_kind":"group","subject_id":"admins","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"empty kind":         `{"name":"p","subject_kind":"","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"user id malformed":  `{"name":"p","subject_kind":"user","subject_id":"alice","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"role not a role":    `{"name":"p","subject_kind":"role","subject_id":"superuser","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"role is a user id":  `{"name":"p","subject_kind":"role","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":["deploy"]}`,
		"target malformed":   `{"name":"p","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"db-1","principals":["deploy"]}`,
		"no principals":      `{"name":"p","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":[]}`,
		"principals omitted": `{"name":"p","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `"}`,
		"principal comma":    `{"name":"p","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":["deploy,root"]}`,
		"unknown field":      `{"name":"p","subject_kind":"user","subject_id":"` + aliceID + `","target_id":"` + dbTarget + `","principals":["deploy"],"sudo":true}`,
		"empty body":         ``,
	}

	for label, body := range cases {
		_, h := newTestModule(t)

		if rec := send(t, h, http.MethodPost, "/v1/policies", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", label, rec.Code, rec.Body)
		}
	}
}

func TestDuplicateNameIsAConflict(t *testing.T) {
	_, h := newTestModule(t)
	body := `{"name":"db-deploy","subject_kind":"user","subject_id":"` + aliceID +
		`","target_id":"` + dbTarget + `","principals":["deploy"]}`

	createPolicy(t, h, body)

	rec := send(t, h, http.MethodPost, "/v1/policies", body)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := errorCode(t, rec); got != "policy_name_taken" {
		t.Fatalf("code = %q, want policy_name_taken", got)
	}
}

func TestEvaluateDeniesWithNoPolicy(t *testing.T) {
	_, h := newTestModule(t)

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if decision.Allowed {
		t.Fatal("access was allowed with no policy in the store")
	}
	if decision.PolicyID != "" {
		t.Errorf("policy_id = %q on a denial", decision.PolicyID)
	}
	if decision.Reason == "" {
		t.Error("a denial carries no reason, so an operator cannot tell why")
	}
}

func TestEvaluateAllowsAMatchingUserPolicy(t *testing.T) {
	_, h := newTestModule(t)

	created := createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+
		aliceID+`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"viewer","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if !decision.Allowed {
		t.Fatalf("denied: %s", decision.Reason)
	}
	if decision.PolicyID != created.ID {
		t.Fatalf("policy_id = %q, want %q: a decision must name the rule that made it", decision.PolicyID, created.ID)
	}
}

func TestEvaluateAllowsAMatchingRolePolicy(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"ops-db","subject_kind":"role","subject_id":"operator","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+bobID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if !decision.Allowed {
		t.Fatalf("denied a user whose role holds the policy: %s", decision.Reason)
	}
}

func TestARoleIsMatchedExactlyAndNotByRank(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"ops-db","subject_kind":"role","subject_id":"operator","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+bobID+`","role":"admin","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if decision.Allowed {
		t.Fatal("an admin inherited an operator's target grant. A platform administrator is not automatically root on every host, and rank inheritance here would make the blast radius of the admin role the whole estate")
	}
}

func TestALowerRoleDoesNotSatisfyAHigherRolePolicy(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"admin-db","subject_kind":"role","subject_id":"admin","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+bobID+`","role":"viewer","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if decision.Allowed {
		t.Fatal("a viewer satisfied an admin policy")
	}
}

func TestAPolicyIsScopedToItsPrincipal(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"postgres"}`)

	if decision.Allowed {
		t.Fatal("a policy granting deploy also granted postgres")
	}
}

func TestAPolicyIsScopedToItsTarget(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"operator","target_id":"`+
		webTarget+`","principal":"deploy"}`)

	if decision.Allowed {
		t.Fatal("a policy for one target granted access to another")
	}
}

func TestAPolicyIsScopedToItsSubject(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+bobID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"deploy"}`)

	if decision.Allowed {
		t.Fatal("a policy for one user granted access to another")
	}
}

func TestEvaluateWithoutARoleStillMatchesAUserPolicy(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","target_id":"`+dbTarget+`","principal":"deploy"}`)

	if !decision.Allowed {
		t.Fatalf("denied: %s", decision.Reason)
	}
}

func TestEvaluateRejectsMalformedInput(t *testing.T) {
	cases := map[string]string{
		"user malformed":    `{"user_id":"alice","target_id":"` + dbTarget + `","principal":"deploy"}`,
		"target malformed":  `{"user_id":"` + aliceID + `","target_id":"db-1","principal":"deploy"}`,
		"principal comma":   `{"user_id":"` + aliceID + `","target_id":"` + dbTarget + `","principal":"deploy,root"}`,
		"principal empty":   `{"user_id":"` + aliceID + `","target_id":"` + dbTarget + `","principal":""}`,
		"role not a role":   `{"user_id":"` + aliceID + `","role":"root","target_id":"` + dbTarget + `","principal":"deploy"}`,
		"principal missing": `{"user_id":"` + aliceID + `","target_id":"` + dbTarget + `"}`,
	}

	for label, body := range cases {
		_, h := newTestModule(t)

		if rec := send(t, h, http.MethodPost, "/v1/policies/evaluate", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", label, rec.Code, rec.Body)
		}
	}
}

func TestAuthorizeMirrorsEvaluate(t *testing.T) {
	m, h := newTestModule(t)
	ctx := context.Background()

	createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	allowed := authz.Identity{UserID: aliceID, Role: authz.RoleOperator}
	if err := m.service.Authorize(ctx, allowed, dbTarget, "deploy"); err != nil {
		t.Fatalf("Authorize refused a granted request: %v", err)
	}

	err := m.service.Authorize(ctx, allowed, dbTarget, "postgres")
	if err == nil {
		t.Fatal("Authorize allowed a principal no policy grants")
	}
	if got := fault.From(err); got.Kind != fault.KindForbidden {
		t.Fatalf("kind = %v, want KindForbidden", got.Kind)
	}
}

func TestDeleteRemovesThePolicyAndItsPrincipals(t *testing.T) {
	m, h := newTestModule(t)
	ctx := context.Background()

	created := createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy","postgres"]}`)

	if rec := send(t, h, http.MethodDelete, "/v1/policies/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204", rec.Code)
	}

	principals, err := m.service.repo.principalsOf(ctx, created.ID)
	if err != nil {
		t.Fatalf("principalsOf: %v", err)
	}
	if len(principals) != 0 {
		t.Fatalf("principals = %v, want none after the policy is gone", principals)
	}

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"deploy"}`)
	if decision.Allowed {
		t.Fatal("access survived the deletion of the only policy granting it")
	}
}

func TestDeleteIsNotIdempotent(t *testing.T) {
	_, h := newTestModule(t)

	created := createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)
	send(t, h, http.MethodDelete, "/v1/policies/"+created.ID, "")

	rec := send(t, h, http.MethodDelete, "/v1/policies/"+created.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: a second delete must not report success it did not perform", rec.Code)
	}
}

func TestGetAndListRoundTrip(t *testing.T) {
	_, h := newTestModule(t)

	createPolicy(t, h, `{"name":"web-deploy","subject_kind":"role","subject_id":"operator","target_id":"`+
		webTarget+`","principals":["www"]}`)
	created := createPolicy(t, h, `{"name":"db-deploy","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)

	rec := send(t, h, http.MethodGet, "/v1/policies/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get: status = %d", rec.Code)
	}
	var one policyView
	if err := json.Unmarshal(rec.Body.Bytes(), &one); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if one.Name != "db-deploy" || strings.Join(one.Principals, ",") != "deploy" {
		t.Fatalf("policy = %+v", one)
	}

	listed := send(t, h, http.MethodGet, "/v1/policies", "")
	var list policyListView
	if err := json.Unmarshal(listed.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(list.Policies))
	}
	if list.Policies[0].Name != "db-deploy" || list.Policies[1].Name != "web-deploy" {
		t.Fatalf("list is not ordered by name: %v", list.Policies)
	}
	for _, p := range list.Policies {
		if len(p.Principals) == 0 {
			t.Errorf("policy %q has no principals in the list view", p.Name)
		}
	}
}

func TestEmptyListIsAnArrayNotNull(t *testing.T) {
	_, h := newTestModule(t)

	rec := send(t, h, http.MethodGet, "/v1/policies", "")
	var list policyListView
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.Policies == nil {
		t.Fatal("policies is null, not []: a client iterating the field would break")
	}
}

func TestAMalformedIDIsRejectedBeforeTheDatabase(t *testing.T) {
	_, h := newTestModule(t)

	for _, id := range []string{"banana", "usr-abc", "pol", "1"} {
		if rec := send(t, h, http.MethodGet, "/v1/policies/"+id, ""); rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400", id, rec.Code)
		}
	}
}

func TestTwoPoliciesCanGrantTheSamePairIndependently(t *testing.T) {
	_, h := newTestModule(t)

	direct := createPolicy(t, h, `{"name":"alice-db","subject_kind":"user","subject_id":"`+aliceID+
		`","target_id":"`+dbTarget+`","principals":["deploy"]}`)
	createPolicy(t, h, `{"name":"ops-db","subject_kind":"role","subject_id":"operator","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	if rec := send(t, h, http.MethodDelete, "/v1/policies/"+direct.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d", rec.Code)
	}

	decision := evaluate(t, h, `{"user_id":"`+aliceID+`","role":"operator","target_id":"`+
		dbTarget+`","principal":"deploy"}`)
	if !decision.Allowed {
		t.Fatal("removing one of two independent grants removed access entirely")
	}
}

func TestEveryRouteRequiresTheAdminRole(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	guard := &recordingGuard{}
	New(st, logging.New("error", io.Discard), guard, stubTargets{}, nil).Routes(http.NewServeMux())

	if len(guard.roles) != 5 {
		t.Fatalf("%d routes declared a role, want 5", len(guard.roles))
	}
	for _, role := range guard.roles {
		if role != authz.RoleAdmin {
			t.Errorf("a route requires %q, want %q: writing policy is the highest privilege in the platform",
				role, authz.RoleAdmin)
		}
	}
}

func TestMigrationsAreOwnedByThisModule(t *testing.T) {
	m, _ := newTestModule(t)

	for _, migration := range m.Migrations() {
		if migration.Module != m.Name() {
			t.Errorf("migration %d is owned by %q, want %q", migration.Index, migration.Module, m.Name())
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

func (r *recordingTrail) find(action string) (audit.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, e := range r.events {
		if e.Action == action {
			return e, true
		}
	}
	return audit.Event{}, false
}

func newTestModuleWithTrail(t *testing.T) (http.Handler, *recordingTrail) {
	t.Helper()

	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	targets := stubTargets{principals: map[string][]string{
		dbTarget:  {"deploy", "postgres"},
		webTarget: {"deploy", "www"},
	}}

	trail := &recordingTrail{}
	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, targets, trail)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	m.Routes(mux)
	return mux, trail
}

func TestWritingPolicyLandsInTheTrail(t *testing.T) {
	h, trail := newTestModuleWithTrail(t)

	created := createPolicy(t, h, `{"name":"ops-db","subject_kind":"role","subject_id":"operator","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	event, ok := trail.find("policy.created")
	if !ok {
		t.Fatal("creating a policy left no audit event. Without it the trail cannot answer who changed the rules")
	}
	if event.Object != created.ID {
		t.Errorf("object = %q, want %q", event.Object, created.ID)
	}
	if event.Fields["subject"] != "role:operator" {
		t.Errorf("subject = %q, want role:operator", event.Fields["subject"])
	}
	if event.Fields["principals"] != "deploy" {
		t.Errorf("principals = %q, want deploy", event.Fields["principals"])
	}

	if rec := send(t, h, http.MethodDelete, "/v1/policies/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if _, ok := trail.find("policy.deleted"); !ok {
		t.Fatal("deleting a policy left no audit event")
	}
}

func TestEvaluatingAPolicyLeavesNoEvent(t *testing.T) {
	h, trail := newTestModuleWithTrail(t)

	createPolicy(t, h, `{"name":"ops-db","subject_kind":"role","subject_id":"operator","target_id":"`+
		dbTarget+`","principals":["deploy"]}`)

	send(t, h, http.MethodPost, "/v1/policies/evaluate",
		`{"user_id":"`+aliceID+`","role":"operator","target_id":"`+dbTarget+`","principal":"deploy"}`)

	if _, ok := trail.find("policy.evaluated"); ok {
		t.Fatal("a read-only evaluation wrote to the trail. The trail records changes and decisions that grant access; an admin asking a hypothetical is neither, and recording it would bury the events that matter")
	}
}
