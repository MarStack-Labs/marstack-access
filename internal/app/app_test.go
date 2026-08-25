package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
	"github.com/marstack-labs/marstack-access/internal/kernel/logging"
)

func newTestApp(t *testing.T) *App {
	t.Helper()

	a, _ := newTestAppWithAdmin(t)
	return a
}

func newTestAppWithAdmin(t *testing.T) (*App, string) {
	t.Helper()

	dir := t.TempDir()
	a, err := New(context.Background(), Config{DataDir: dir}, logging.New("error", io.Discard))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	t.Cleanup(func() { a.Close() })

	raw, err := os.ReadFile(filepath.Join(dir, bootstrapTokenFile))
	if err != nil {
		t.Fatalf("read bootstrap token: %v", err)
	}
	return a, strings.TrimSpace(string(raw))
}

func send(t *testing.T, a *App, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}

	r := httptest.NewRequest(method, path, reader)
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)
	return rec
}

func do(t *testing.T, a *App, method, path string) *httptest.ResponseRecorder {
	t.Helper()

	return send(t, a, method, path, "", "")
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, rec.Body)
	}
	return body
}

func tokenForRole(t *testing.T, a *App, admin, name, role string) string {
	t.Helper()

	created := send(t, a, http.MethodPost, "/v1/users", admin,
		`{"name":"`+name+`","role":"`+role+`"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create %s user: status = %d (%s)", role, created.Code, created.Body)
	}
	id, _ := decodeBody(t, created)["id"].(string)

	issued := send(t, a, http.MethodPost, "/v1/users/"+id+"/tokens", admin, "")
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue token: status = %d (%s)", issued.Code, issued.Body)
	}
	secret, _ := decodeBody(t, issued)["secret"].(string)
	if secret == "" {
		t.Fatal("the issued token carries no secret")
	}
	return secret
}

func TestHealthzIsPublic(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/healthz")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: a load balancer probe cannot carry a token", rec.Code)
	}
	if got := decodeBody(t, rec)["status"]; got != "ok" {
		t.Fatalf("status field = %v, want ok", got)
	}
}

func TestHealthzReportsUnavailableWhenTheStoreIsGone(t *testing.T) {
	a := newTestApp(t)
	if err := a.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}

	rec := do(t, a, http.MethodGet, "/healthz")

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: a health check that cannot see its store must not report ok", rec.Code)
	}
	if body := rec.Body.String(); strings.Contains(body, "sql:") || strings.Contains(body, "sqlite") {
		t.Fatalf("the response leaks the driver error: %s", body)
	}
}

func TestEveryRouteExceptHealthzRequiresTheToken(t *testing.T) {
	a := newTestApp(t)

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/v1/version"},
		{http.MethodGet, "/v1/users"},
		{http.MethodPost, "/v1/users"},
		{http.MethodGet, "/v1/users/usr-abc"},
		{http.MethodDelete, "/v1/users/usr-abc"},
		{http.MethodPost, "/v1/users/usr-abc/tokens"},
		{http.MethodGet, "/v1/users/usr-abc/tokens"},
		{http.MethodDelete, "/v1/tokens/tok-abc"},
		{http.MethodGet, "/v1/targets"},
		{http.MethodPost, "/v1/targets"},
		{http.MethodGet, "/v1/targets/tgt-abc"},
		{http.MethodDelete, "/v1/targets/tgt-abc"},
	}

	for _, route := range protected {
		rec := send(t, a, route.method, route.path, "", "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: status = %d, want 401", route.method, route.path, rec.Code)
		}
	}
}

func TestAMalformedAuthorizationHeaderIsRejected(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	headers := map[string]string{
		"no scheme":     admin,
		"wrong scheme":  "Basic " + admin,
		"scheme only":   "Bearer",
		"empty value":   "Bearer ",
		"wrong token":   "Bearer mat_0000000000000000_00000000000000000000000000000000",
		"random string": "Bearer hunter2",
	}

	for label, header := range headers {
		r := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
		r.Header.Set("Authorization", header)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, r)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", label, rec.Code)
		}
	}
}

func TestTheBearerSchemeIsCaseInsensitive(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	for _, scheme := range []string{"Bearer", "bearer", "BEARER"} {
		r := httptest.NewRequest(http.MethodGet, "/v1/targets", nil)
		r.Header.Set("Authorization", scheme+" "+admin)
		rec := httptest.NewRecorder()
		a.Handler().ServeHTTP(rec, r)

		if rec.Code != http.StatusOK {
			t.Errorf("scheme %q: status = %d, want 200 (%s)", scheme, rec.Code, rec.Body)
		}
	}
}

func TestTheBootstrapAdminCanReachEverything(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	if rec := send(t, a, http.MethodGet, "/v1/users", admin, ""); rec.Code != http.StatusOK {
		t.Errorf("users: status = %d (%s)", rec.Code, rec.Body)
	}
	if rec := send(t, a, http.MethodGet, "/v1/targets", admin, ""); rec.Code != http.StatusOK {
		t.Errorf("targets: status = %d (%s)", rec.Code, rec.Body)
	}
	if rec := send(t, a, http.MethodGet, "/v1/version", admin, ""); rec.Code != http.StatusOK {
		t.Errorf("version: status = %d (%s)", rec.Code, rec.Body)
	}
}

func TestAViewerCannotTouchTargets(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	viewer := tokenForRole(t, a, admin, "watcher", authz.RoleViewer)

	if rec := send(t, a, http.MethodGet, "/v1/version", viewer, ""); rec.Code != http.StatusOK {
		t.Errorf("version: status = %d, a viewer may read it (%s)", rec.Code, rec.Body)
	}

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := send(t, a, method, "/v1/targets", viewer, `{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s /v1/targets as viewer: status = %d, want 403", method, rec.Code)
		}
		if code, _ := decodeBody(t, rec)["error"].(map[string]any)["code"].(string); code != "insufficient_role" {
			t.Errorf("%s /v1/targets as viewer: code = %q, want insufficient_role", method, code)
		}
	}
}

func TestAnOperatorCanUseTargetsButNotUsers(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "deployer", authz.RoleOperator)

	rec := send(t, a, http.MethodPost, "/v1/targets", operator,
		`{"name":"db-1","address":"10.0.0.4","principals":["deploy"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register target as operator: status = %d, want 201 (%s)", rec.Code, rec.Body)
	}

	if rec := send(t, a, http.MethodDelete, "/v1/targets/"+decodeBody(t, rec)["id"].(string), operator, ""); rec.Code != http.StatusNoContent {
		t.Errorf("delete target as operator: status = %d, want 204", rec.Code)
	}

	for _, route := range []string{"/v1/users", "/v1/users/usr-abc"} {
		if rec := send(t, a, http.MethodGet, route, operator, ""); rec.Code != http.StatusForbidden {
			t.Errorf("%s as operator: status = %d, want 403: an operator must not be able to mint an admin", route, rec.Code)
		}
	}
}

func TestAnOperatorCannotEscalateItself(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "deployer", authz.RoleOperator)

	rec := send(t, a, http.MethodPost, "/v1/users", operator,
		`{"name":"backdoor","role":"admin"}`)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	list := send(t, a, http.MethodGet, "/v1/users", admin, "")
	if strings.Contains(list.Body.String(), "backdoor") {
		t.Fatal("the operator created a user despite the 403")
	}
}

func TestARevokedTokenStopsWorkingImmediately(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "deployer", authz.RoleOperator)

	if rec := send(t, a, http.MethodGet, "/v1/targets", operator, ""); rec.Code != http.StatusOK {
		t.Fatalf("the fresh token does not work: %d (%s)", rec.Code, rec.Body)
	}

	users := send(t, a, http.MethodGet, "/v1/users", admin, "")
	var userList struct {
		Users []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"users"`
	}
	if err := json.Unmarshal(users.Body.Bytes(), &userList); err != nil {
		t.Fatalf("decode users: %v", err)
	}

	var operatorID string
	for _, u := range userList.Users {
		if u.Name == "deployer" {
			operatorID = u.ID
		}
	}
	if operatorID == "" {
		t.Fatal("the operator user is missing from the list")
	}

	tokens := send(t, a, http.MethodGet, "/v1/users/"+operatorID+"/tokens", admin, "")
	var tokenList struct {
		Tokens []struct {
			ID string `json:"id"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(tokens.Body.Bytes(), &tokenList); err != nil {
		t.Fatalf("decode tokens: %v", err)
	}
	if len(tokenList.Tokens) != 1 {
		t.Fatalf("got %d tokens, want 1", len(tokenList.Tokens))
	}

	if rec := send(t, a, http.MethodDelete, "/v1/tokens/"+tokenList.Tokens[0].ID, admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status = %d", rec.Code)
	}

	if rec := send(t, a, http.MethodGet, "/v1/targets", operator, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 after revocation", rec.Code)
	}
}

func TestTokenListingNeverCarriesASecret(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	created := send(t, a, http.MethodPost, "/v1/users", admin, `{"name":"deployer","role":"operator"}`)
	id := decodeBody(t, created)["id"].(string)

	issued := send(t, a, http.MethodPost, "/v1/users/"+id+"/tokens", admin, "")
	secret := decodeBody(t, issued)["secret"].(string)

	listed := send(t, a, http.MethodGet, "/v1/users/"+id+"/tokens", admin, "")
	if strings.Contains(listed.Body.String(), secret) {
		t.Fatal("the token listing returned the secret, so it is recoverable after issue")
	}
	if strings.Contains(listed.Body.String(), "secret") {
		t.Fatalf("the token listing has a secret field: %s", listed.Body)
	}
}

func TestTokenTTLIsAccepted(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	created := send(t, a, http.MethodPost, "/v1/users", admin, `{"name":"deployer","role":"operator"}`)
	id := decodeBody(t, created)["id"].(string)

	issued := send(t, a, http.MethodPost, "/v1/users/"+id+"/tokens", admin, `{"ttl":"24h"}`)
	if issued.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (%s)", issued.Code, issued.Body)
	}
	if decodeBody(t, issued)["expires_at"] == nil {
		t.Fatal("expires_at is absent even though a ttl was given")
	}

	bad := send(t, a, http.MethodPost, "/v1/users/"+id+"/tokens", admin, `{"ttl":"forever"}`)
	if bad.Code != http.StatusBadRequest {
		t.Fatalf("an unparseable ttl returned %d, want 400", bad.Code)
	}
}

func TestDeletingAUserBreaksItsToken(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	operator := tokenForRole(t, a, admin, "temp", authz.RoleOperator)

	users := send(t, a, http.MethodGet, "/v1/users", admin, "")
	var userList struct {
		Users []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"users"`
	}
	if err := json.Unmarshal(users.Body.Bytes(), &userList); err != nil {
		t.Fatalf("decode: %v", err)
	}

	for _, u := range userList.Users {
		if u.Name != "temp" {
			continue
		}
		if rec := send(t, a, http.MethodDelete, "/v1/users/"+u.ID, admin, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("delete user: status = %d", rec.Code)
		}
	}

	if rec := send(t, a, http.MethodGet, "/v1/targets", operator, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a deleted account must not keep working", rec.Code)
	}
}

func TestVersionEndpointReportsBuildMetadata(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	rec := send(t, a, http.MethodGet, "/v1/version", admin, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	body := decodeBody(t, rec)
	if body["version"] == "" || body["commit"] == "" {
		t.Fatalf("body = %v, want both version and commit", body)
	}
}

func TestUnknownRouteIsNotFound(t *testing.T) {
	if rec := do(t, newTestApp(t), http.MethodGet, "/v1/no-such-resource"); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodPost, "/healthz")

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405: routes declare their method", rec.Code)
	}
}

func TestBootstrapWritesATokenFileAndNotALogLine(t *testing.T) {
	dir := t.TempDir()
	var logged bytes.Buffer

	a, err := New(context.Background(), Config{DataDir: dir},
		slog.New(slog.NewTextHandler(&logged, nil)))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer a.Close()

	path := filepath.Join(dir, bootstrapTokenFile)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read bootstrap token: %v", err)
	}

	secret := strings.TrimSpace(string(raw))
	if secret == "" {
		t.Fatal("the bootstrap token file is empty")
	}
	if !strings.Contains(logged.String(), path) {
		t.Error("the log does not name the token file, so an operator cannot find it")
	}
	if strings.Contains(logged.String(), secret) {
		t.Fatal("the bootstrap secret was written to the log")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o, want 0600: it is a working admin credential on disk", perm)
	}
}

func TestBootstrapRunsOnlyOnTheFirstStart(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)
	path := filepath.Join(dir, bootstrapTokenFile)

	first, err := New(context.Background(), Config{DataDir: dir}, log)
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	first.Close()

	if _, err := os.ReadFile(path); err != nil {
		t.Fatalf("the first start wrote nothing: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	second, err := New(context.Background(), Config{DataDir: dir}, log)
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	second.Close()

	if _, err := os.Stat(path); err == nil {
		t.Fatal("a restart minted another admin credential, so deleting the file is not enough to close the window")
	}
}

func TestSecurityHeadersArePresentOnEveryResponse(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
		"Cache-Control":          "no-store",
	}

	cases := map[string]string{
		"/healthz":            "",
		"/v1/targets":         admin,
		"/does-not-exist":     "",
		"/v1/targets/tgt-bad": "",
	}

	for path, token := range cases {
		rec := send(t, a, http.MethodGet, path, token, "")
		for header, value := range want {
			if got := rec.Header().Get(header); got != value {
				t.Errorf("%s: %s = %q, want %q", path, header, got, value)
			}
		}
	}
}

func TestRequestIDIsAssignedEvenOnARejectedRequest(t *testing.T) {
	a := newTestApp(t)

	for _, path := range []string{"/does-not-exist", "/v1/targets"} {
		rec := do(t, a, http.MethodGet, path)
		if id := rec.Header().Get("X-Request-Id"); !strings.HasPrefix(id, "req-") {
			t.Errorf("%s: X-Request-Id = %q, want a req- prefixed id: a 401 still has to be traceable", path, id)
		}
	}
}

func TestConfigDefaultsAreApplied(t *testing.T) {
	got := Config{}.withDefaults()

	if got.Listen != "127.0.0.1:7443" {
		t.Errorf("Listen = %q, want the loopback default: the control plane must not bind every interface by accident", got.Listen)
	}
	if got.DataDir == "" {
		t.Error("DataDir default is empty")
	}
	if got.RequestTimeout <= 0 {
		t.Error("RequestTimeout default must be positive")
	}
}

func TestExplicitConfigIsNotOverwritten(t *testing.T) {
	got := Config{Listen: "0.0.0.0:9000", DataDir: "/srv/marac", RequestTimeout: time.Second}.withDefaults()

	if got.Listen != "0.0.0.0:9000" || got.DataDir != "/srv/marac" || got.RequestTimeout != time.Second {
		t.Fatalf("defaults overwrote explicit config: %+v", got)
	}
}

func TestServerTimeoutsAreSet(t *testing.T) {
	a := newTestApp(t)

	if a.http.ReadHeaderTimeout <= 0 {
		t.Error("ReadHeaderTimeout is unset: an unauthenticated peer can hold a connection open forever")
	}
	if a.http.ReadTimeout <= 0 || a.http.WriteTimeout <= 0 || a.http.IdleTimeout <= 0 {
		t.Errorf("a timeout is unset: read=%v write=%v idle=%v",
			a.http.ReadTimeout, a.http.WriteTimeout, a.http.IdleTimeout)
	}
	if a.http.MaxHeaderBytes <= 0 {
		t.Error("MaxHeaderBytes is unset")
	}
}

func TestRestartingOnTheSameDataDirIsSafe(t *testing.T) {
	dir := t.TempDir()
	log := logging.New("error", io.Discard)

	for range 3 {
		a, err := New(context.Background(), Config{DataDir: dir}, log)
		if err != nil {
			t.Fatalf("new app: %v", err)
		}
		a.Close()
	}
}

func TestModuleNamesAreUnique(t *testing.T) {
	seen := make(map[string]bool)

	for _, m := range newTestApp(t).modules {
		if m.Name() == "" {
			t.Error("a module reports an empty name")
		}
		if seen[m.Name()] {
			t.Errorf("module name %q is registered twice: migrations would be recorded under one owner", m.Name())
		}
		seen[m.Name()] = true
	}
}

func TestRunShutsDownOnContextCancel(t *testing.T) {
	a, err := New(context.Background(), Config{DataDir: t.TempDir(), Listen: "127.0.0.1:0"},
		logging.New("error", io.Discard))
	if err != nil {
		t.Fatalf("new app: %v", err)
	}
	defer a.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want a clean shutdown", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after the context was cancelled")
	}
}
