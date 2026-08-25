package target

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"golang.org/x/crypto/ssh"

	"github.com/marstack-labs/marstack-access/internal/kernel/audit"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
	"github.com/marstack-labs/marstack-access/internal/kernel/sshkey"
	"github.com/marstack-labs/marstack-access/internal/store"
)

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

	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, trail)
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

func registerTarget(t *testing.T, h http.Handler, body string) targetView {
	t.Helper()

	rec := send(t, h, http.MethodPost, "/v1/targets", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status = %d, want 201 (%s)", rec.Code, rec.Body)
	}

	var view targetView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.Body)
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

func TestRegisterReturnsTheStoredTarget(t *testing.T) {
	_, h := newTestModule(t)

	view := registerTarget(t, h,
		`{"name":"db-1","address":"10.0.0.4","port":2222,"principals":["deploy","postgres"]}`)

	if !strings.HasPrefix(view.ID, idPrefix+"-") {
		t.Errorf("id = %q, want a %s- prefix", view.ID, idPrefix)
	}
	if view.Name != "db-1" || view.Address != "10.0.0.4" || view.Port != 2222 {
		t.Errorf("view = %+v", view)
	}
	if strings.Join(view.Principals, ",") != "deploy,postgres" {
		t.Errorf("principals = %v, want them sorted", view.Principals)
	}
	if _, err := time.Parse(time.RFC3339, view.CreatedAt); err != nil {
		t.Errorf("created_at = %q, not RFC3339: %v", view.CreatedAt, err)
	}
}

func TestPortDefaultsToSSH(t *testing.T) {
	_, h := newTestModule(t)

	view := registerTarget(t, h, `{"name":"web-1","address":"web-1.internal","principals":["deploy"]}`)

	if view.Port != defaultPort {
		t.Fatalf("port = %d, want the %d default", view.Port, defaultPort)
	}
}

func TestPrincipalsAreDeduplicatedAndSorted(t *testing.T) {
	_, h := newTestModule(t)

	view := registerTarget(t, h,
		`{"name":"db-1","address":"10.0.0.4","principals":["deploy","root","deploy","app"]}`)

	if got := strings.Join(view.Principals, ","); got != "app,deploy,root" {
		t.Fatalf("principals = %q, want app,deploy,root", got)
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"empty name":           `{"name":"","address":"10.0.0.4","principals":["deploy"]}`,
		"uppercase name":       `{"name":"DB-1","address":"10.0.0.4","principals":["deploy"]}`,
		"address with a port":  `{"name":"db-1","address":"10.0.0.4:22","principals":["deploy"]}`,
		"address with a space": `{"name":"db-1","address":"db-1 -oProxyCommand=id","principals":["deploy"]}`,
		"address with newline": `{"name":"db-1","address":"db-1\nevil","principals":["deploy"]}`,
		"port out of range":    `{"name":"db-1","address":"10.0.0.4","port":70000,"principals":["deploy"]}`,
		"negative port":        `{"name":"db-1","address":"10.0.0.4","port":-1,"principals":["deploy"]}`,
		"no principals":        `{"name":"db-1","address":"10.0.0.4","principals":[]}`,
		"principals omitted":   `{"name":"db-1","address":"10.0.0.4"}`,
		"principal with comma": `{"name":"db-1","address":"10.0.0.4","principals":["deploy,root"]}`,
		"principal with space": `{"name":"db-1","address":"10.0.0.4","principals":["deploy root"]}`,
		"principal uppercase":  `{"name":"db-1","address":"10.0.0.4","principals":["Deploy"]}`,
		"principal wildcard":   `{"name":"db-1","address":"10.0.0.4","principals":["*"]}`,
		"unknown field":        `{"name":"db-1","address":"10.0.0.4","principals":["deploy"],"sudo":true}`,
		"empty body":           ``,
	}

	for label, body := range cases {
		_, h := newTestModule(t)

		rec := send(t, h, http.MethodPost, "/v1/targets", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", label, rec.Code, rec.Body)
		}
	}
}

func TestTooManyPrincipalsIsRejected(t *testing.T) {
	_, h := newTestModule(t)

	principals := make([]string, maxPrincipals+1)
	for i := range principals {
		principals[i] = "user" + string(rune('a'+i%26)) + string(rune('a'+i/26))
	}
	encoded, err := json.Marshal(principals)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	rec := send(t, h, http.MethodPost, "/v1/targets",
		`{"name":"db-1","address":"10.0.0.4","principals":`+string(encoded)+`}`)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: an unbounded principal list is client-controlled allocation", rec.Code)
	}
}

func TestDuplicateNameIsAConflict(t *testing.T) {
	_, h := newTestModule(t)
	body := `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`

	registerTarget(t, h, body)
	rec := send(t, h, http.MethodPost, "/v1/targets", body)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	if got := errorCode(t, rec); got != "target_name_taken" {
		t.Fatalf("code = %q, want target_name_taken", got)
	}
}

func TestTheSameAddressMayBeRegisteredTwiceUnderDifferentNames(t *testing.T) {
	_, h := newTestModule(t)

	registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	registerTarget(t, h, `{"name":"db-1-admin","address":"10.0.0.4","principals":["root"]}`)
}

func TestGetReturnsTheRegisteredTarget(t *testing.T) {
	_, h := newTestModule(t)

	created := registerTarget(t, h,
		`{"name":"db-1","address":"10.0.0.4","principals":["deploy","root"]}`)

	rec := send(t, h, http.MethodGet, "/v1/targets/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got targetView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != created.ID || got.Name != created.Name || got.Port != created.Port {
		t.Fatalf("got = %+v, want %+v", got, created)
	}
	if strings.Join(got.Principals, ",") != "deploy,root" {
		t.Fatalf("principals = %v: they must survive the round trip", got.Principals)
	}
}

func TestGetAnUnknownTargetIsNotFound(t *testing.T) {
	_, h := newTestModule(t)

	rec := send(t, h, http.MethodGet, "/v1/targets/tgt-0000000000000", "")

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if got := errorCode(t, rec); got != "target_not_found" {
		t.Fatalf("code = %q, want target_not_found", got)
	}
}

func TestAMalformedIDIsRejectedBeforeTheDatabase(t *testing.T) {
	_, h := newTestModule(t)

	for _, id := range []string{"banana", "ses-abc", "tgt", "1"} {
		rec := send(t, h, http.MethodGet, "/v1/targets/"+id, "")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("id %q: status = %d, want 400", id, rec.Code)
		}
	}
}

func TestListIsEmptyBeforeAnythingIsRegistered(t *testing.T) {
	_, h := newTestModule(t)

	rec := send(t, h, http.MethodGet, "/v1/targets", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	var got targetListView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Targets == nil {
		t.Fatal("targets is null, not []: a client iterating the field would break")
	}
	if len(got.Targets) != 0 {
		t.Fatalf("targets = %v, want empty", got.Targets)
	}
}

func TestListIsOrderedByName(t *testing.T) {
	_, h := newTestModule(t)

	for _, name := range []string{"web-1", "api-1", "db-1"} {
		registerTarget(t, h, `{"name":"`+name+`","address":"10.0.0.4","principals":["deploy"]}`)
	}

	rec := send(t, h, http.MethodGet, "/v1/targets", "")
	var got targetListView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	names := make([]string, 0, len(got.Targets))
	for _, view := range got.Targets {
		names = append(names, view.Name)
	}
	if strings.Join(names, ",") != "api-1,db-1,web-1" {
		t.Fatalf("names = %v, want them sorted", names)
	}
}

func TestListCarriesPrincipalsForEveryTarget(t *testing.T) {
	_, h := newTestModule(t)

	registerTarget(t, h, `{"name":"api-1","address":"10.0.0.4","principals":["deploy"]}`)
	registerTarget(t, h, `{"name":"db-1","address":"10.0.0.5","principals":["postgres","root"]}`)

	rec := send(t, h, http.MethodGet, "/v1/targets", "")
	var got targetListView
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, view := range got.Targets {
		if len(view.Principals) == 0 {
			t.Errorf("target %q has no principals in the list view", view.Name)
		}
	}
}

func TestDeleteRemovesTheTarget(t *testing.T) {
	_, h := newTestModule(t)

	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)

	if rec := send(t, h, http.MethodDelete, "/v1/targets/"+created.ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status = %d, want 204", rec.Code)
	}
	if rec := send(t, h, http.MethodGet, "/v1/targets/"+created.ID, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: status = %d, want 404", rec.Code)
	}
}

func TestDeleteIsNotIdempotent(t *testing.T) {
	_, h := newTestModule(t)

	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	send(t, h, http.MethodDelete, "/v1/targets/"+created.ID, "")

	rec := send(t, h, http.MethodDelete, "/v1/targets/"+created.ID, "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404: a second delete must not report success it did not perform", rec.Code)
	}
}

func TestDeleteCascadesToPrincipals(t *testing.T) {
	m, h := newTestModule(t)
	ctx := context.Background()

	created := registerTarget(t, h,
		`{"name":"db-1","address":"10.0.0.4","principals":["deploy","root"]}`)
	send(t, h, http.MethodDelete, "/v1/targets/"+created.ID, "")

	principals, err := m.service.repo.principalsOf(ctx, created.ID)
	if err != nil {
		t.Fatalf("principalsOf: %v", err)
	}
	if len(principals) != 0 {
		t.Fatalf("principals = %v, want none: a deleted target must not leave rows that a later id could inherit", principals)
	}
}

func TestNameIsFreedAfterDelete(t *testing.T) {
	_, h := newTestModule(t)
	body := `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`

	created := registerTarget(t, h, body)
	send(t, h, http.MethodDelete, "/v1/targets/"+created.ID, "")

	registerTarget(t, h, body)
}

func TestTargetsSurviveARestart(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)
	ctx := context.Background()

	st, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m := New(st, log, &recordingGuard{}, nil)
	if err := st.Migrate(ctx, m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mux := http.NewServeMux()
	m.Routes(mux)
	created := registerTarget(t, mux, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	st.Close()

	st2, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	m2 := New(st2, log, &recordingGuard{}, nil)
	if err := st2.Migrate(ctx, m2.Migrations()); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	mux2 := http.NewServeMux()
	m2.Routes(mux2)

	rec := send(t, mux2, http.MethodGet, "/v1/targets/"+created.ID, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 after a restart (%s)", rec.Code, rec.Body)
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

func TestEveryRouteRequiresTheOperatorRole(t *testing.T) {
	st, err := store.Open(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	guard := &recordingGuard{}
	New(st, logging.New("error", io.Discard), guard, nil).Routes(http.NewServeMux())

	if len(guard.roles) != 5 {
		t.Fatalf("%d routes declared a role, want 5: a route that skips the guard is reachable unauthenticated",
			len(guard.roles))
	}
	for _, role := range guard.roles {
		if role != authz.RoleOperator {
			t.Errorf("a route requires %q, want %q", role, authz.RoleOperator)
		}
	}
}

func hostKeyLine(t *testing.T) string {
	t.Helper()

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
}

func TestATargetStartsWithNoPinnedHostKey(t *testing.T) {
	_, h := newTestModule(t)

	view := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)

	if view.Fingerprint != "" {
		t.Fatalf("fingerprint = %q, want empty: nothing has verified this host yet", view.Fingerprint)
	}
}

func TestTrustPinsTheHostKeyAndReportsItsFingerprint(t *testing.T) {
	_, h := newTestModule(t)
	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)

	raw := strings.TrimSpace(hostKeyLine(t))
	rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key",
		`{"host_key":"`+raw+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}

	var view targetView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want, err := sshkey.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if view.Fingerprint != want.Fingerprint {
		t.Fatalf("fingerprint = %q, want %q", view.Fingerprint, want.Fingerprint)
	}
}

func TestTheViewNeverCarriesTheHostKeyItself(t *testing.T) {
	_, h := newTestModule(t)
	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	raw := strings.TrimSpace(hostKeyLine(t))

	rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key",
		`{"host_key":"`+raw+`"}`)

	if strings.Contains(rec.Body.String(), "ssh-ed25519 ") {
		t.Fatalf("the response echoes the host key line: %s", rec.Body)
	}
}

func TestReplacingAPinnedHostKeyMustBeAskedFor(t *testing.T) {
	_, h := newTestModule(t)
	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	first := strings.TrimSpace(hostKeyLine(t))
	second := strings.TrimSpace(hostKeyLine(t))

	send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key", `{"host_key":"`+first+`"}`)

	rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key",
		`{"host_key":"`+second+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: a silent replacement is how a man-in-the-middle becomes permanent", rec.Code)
	}
	if got := errorCode(t, rec); got != "host_key_pinned" {
		t.Fatalf("code = %q, want host_key_pinned", got)
	}

	replaced := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key",
		`{"host_key":"`+second+`","replace":true}`)
	if replaced.Code != http.StatusOK {
		t.Fatalf("an explicit replacement was refused: %d (%s)", replaced.Code, replaced.Body)
	}

	want, err := sshkey.Parse(second)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var view targetView
	if err := json.Unmarshal(replaced.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.Fingerprint != want.Fingerprint {
		t.Fatalf("fingerprint = %q, want the replacement %q", view.Fingerprint, want.Fingerprint)
	}
}

func TestRepinningTheSameKeyIsStillAConflict(t *testing.T) {
	_, h := newTestModule(t)
	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	raw := strings.TrimSpace(hostKeyLine(t))

	send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key", `{"host_key":"`+raw+`"}`)

	rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key", `{"host_key":"`+raw+`"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409. Treating an identical repin as a no-op sounds harmless, but it means the caller cannot tell whether the key they sent is the one that was already there",
			rec.Code)
	}
}

func TestTrustRejectsSomethingThatIsNotAHostKey(t *testing.T) {
	_, h := newTestModule(t)
	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)

	for label, body := range map[string]string{
		"empty":       `{"host_key":""}`,
		"prose":       `{"host_key":"hello world"}`,
		"missing":     `{}`,
		"unknown key": `{"host_key":"ssh-ed25519 AAAA","sudo":true}`,
	} {
		rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key", body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%s)", label, rec.Code, rec.Body)
		}
	}
}

func TestTrustRejectsAnUnknownTarget(t *testing.T) {
	_, h := newTestModule(t)
	raw := strings.TrimSpace(hostKeyLine(t))

	rec := send(t, h, http.MethodPost, "/v1/targets/tgt-9999999999999/host-key",
		`{"host_key":"`+raw+`"}`)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestAPinnedKeySurvivesARestartAndStillParses(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)
	ctx := context.Background()
	raw := strings.TrimSpace(hostKeyLine(t))

	st, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	m := New(st, log, &recordingGuard{}, nil)
	if err := st.Migrate(ctx, m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	mux := http.NewServeMux()
	m.Routes(mux)
	created := registerTarget(t, mux, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	send(t, mux, http.MethodPost, "/v1/targets/"+created.ID+"/host-key", `{"host_key":"`+raw+`"}`)
	st.Close()

	st2, err := store.Open(ctx, dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	m2 := New(st2, log, &recordingGuard{}, nil)
	if err := st2.Migrate(ctx, m2.Migrations()); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}

	reloaded, err := m2.ByName(ctx, "db-1")
	if err != nil {
		t.Fatalf("by name: %v", err)
	}
	parsed, err := sshkey.Parse(reloaded.HostKey)
	if err != nil {
		t.Fatalf("the stored host key does not parse back: %v", err)
	}
	want, _ := sshkey.Parse(raw)
	if parsed.Fingerprint != want.Fingerprint {
		t.Fatal("the reloaded pin is a different key")
	}
}

func TestTheHostKeyColumnIsAddedToAnExistingTable(t *testing.T) {
	m, _ := newTestModule(t)

	migration := m.Migrations()[3]
	if !strings.Contains(migration.SQL, "ALTER TABLE targets") {
		t.Fatalf("migration 4 = %q, want an ALTER on the existing table. Recreating the table would drop every registered target",
			migration.SQL)
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

	trail := &recordingTrail{}
	m := New(st, logging.New("error", io.Discard), &recordingGuard{}, trail)
	if err := st.Migrate(context.Background(), m.Migrations()); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	m.Routes(mux)
	return mux, trail
}

func TestTargetChangesLandInTheTrail(t *testing.T) {
	h, trail := newTestModuleWithTrail(t)

	created := registerTarget(t, h, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)

	event, ok := trail.find("target.registered")
	if !ok {
		t.Fatal("registering a target left no audit event")
	}
	if event.Object != created.ID || event.Fields["address"] != "10.0.0.4" {
		t.Errorf("event = %+v", event)
	}

	raw := strings.TrimSpace(hostKeyLine(t))
	if rec := send(t, h, http.MethodPost, "/v1/targets/"+created.ID+"/host-key",
		`{"host_key":"`+raw+`"}`); rec.Code != http.StatusOK {
		t.Fatalf("trust: %d (%s)", rec.Code, rec.Body)
	}

	pinned, ok := trail.find("target.host_key_pinned")
	if !ok {
		t.Fatal("pinning a host key left no audit event. Pinning is a claim about which machine an entry means, so it has to be attributable")
	}
	want, err := sshkey.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if pinned.Fields["fingerprint"] != want.Fingerprint {
		t.Errorf("fingerprint = %q, want %q", pinned.Fields["fingerprint"], want.Fingerprint)
	}
	if pinned.Fields["replaced"] != "false" {
		t.Errorf("replaced = %q, want false: a replacement and a first pin have to be distinguishable in the trail",
			pinned.Fields["replaced"])
	}
}
