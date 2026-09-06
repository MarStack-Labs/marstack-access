package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/kernel/authz"
)

func asConsole(t *testing.T, a *App, method, path, cookie, body string) *httptest.ResponseRecorder {
	t.Helper()

	var reader *strings.Reader
	r := httptest.NewRequest(method, path, nil)
	if body != "" {
		reader = strings.NewReader(body)
		r = httptest.NewRequest(method, path, reader)
		r.Header.Set("Content-Type", "application/json")
	}

	r.Header.Set(authz.ConsoleHeader, "1")
	r.RemoteAddr = "127.0.0.1:54321"
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: authz.CookieName, Value: cookie})
	}

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)
	return rec
}

func signInToConsole(t *testing.T, a *App, token string) *http.Cookie {
	t.Helper()

	rec := asConsole(t, a, http.MethodPost, "/v1/console/session", "", `{"token":"`+token+`"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("sign in: status = %d (%s)", rec.Code, rec.Body)
	}

	for _, c := range rec.Result().Cookies() {
		if c.Name == authz.CookieName {
			return c
		}
	}
	t.Fatal("sign in returned no console cookie")
	return nil
}

func TestTheConsoleIsServedWithoutAToken(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/console/")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: the sign in page cannot require the credential it collects", rec.Code)
	}
	if body := rec.Body.String(); !strings.Contains(body, "console.js") {
		t.Fatalf("the page served is not the console: %.120s", body)
	}
}

func TestTheConsoleAssetsExist(t *testing.T) {
	a := newTestApp(t)

	for _, asset := range []string{"console.js", "console.css", "meridian.css"} {
		rec := do(t, a, http.MethodGet, "/console/"+asset)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200: index.html references it, so a missing file is a broken page",
				asset, rec.Code)
		}
	}
}

func TestTheConsoleForbidsInlineScript(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodGet, "/console/")

	policy := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "default-src 'self'") {
		t.Fatalf("policy = %q, want default-src 'self'", policy)
	}
	if strings.Contains(policy, "unsafe-inline") || strings.Contains(policy, "unsafe-eval") {
		t.Fatalf("policy = %q: an injected string must never become a script", policy)
	}
}

func TestTheConsoleServesFilesAndNothingElse(t *testing.T) {
	rec := do(t, newTestApp(t), http.MethodPost, "/console/")

	if rec.Code == http.StatusOK {
		t.Fatal("a POST to the console was accepted: it serves files, so nothing it receives can have an effect")
	}
}

func TestSigningInSwapsTheTokenForACookieScriptsCannotRead(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	cookie := signInToConsole(t, a, admin)

	if !cookie.HttpOnly {
		t.Error("the cookie is readable by page scripts, so one injected line exfiltrates the credential")
	}
	if !cookie.Secure {
		t.Error("the cookie may be sent over cleartext, and it carries an API token")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	if cookie.Value != admin {
		t.Error("the cookie does not carry the token, so the guard cannot authenticate it")
	}
}

func TestSigningInWithARejectedTokenSetsNoCookie(t *testing.T) {
	a := newTestApp(t)

	rec := asConsole(t, a, http.MethodPost, "/v1/console/session", "", `{"token":"mat_not_a_real_token"}`)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == authz.CookieName {
			t.Fatal("a refused sign in still set the cookie")
		}
	}
}

func TestSigningInOverCleartextFromElsewhereIsRefused(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	r := httptest.NewRequest(http.MethodPost, "/v1/console/session", strings.NewReader(`{"token":"`+admin+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set(authz.ConsoleHeader, "1")
	r.RemoteAddr = "203.0.113.9:41000"

	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the browser will not store a Secure cookie over http, "+
			"so accepting the token here would drop it silently and leave the operator retyping it", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == authz.CookieName {
			t.Fatal("a refused sign in still set the cookie")
		}
	}
	if strings.Contains(rec.Body.String(), admin) {
		t.Fatal("the refusal echoes the token back")
	}
}

func TestTheConsoleCookieIsRefusedWithoutTheConsoleHeader(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	cookie := signInToConsole(t, a, admin)

	r := httptest.NewRequest(http.MethodGet, "/v1/sessions", nil)
	r.AddCookie(cookie)
	rec := httptest.NewRecorder()
	a.Handler().ServeHTTP(rec, r)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: a cross site request carries the cookie by itself, "+
			"so the cookie by itself must not authenticate anything", rec.Code)
	}
}

func TestTheConsoleCookieWorksWithTheConsoleHeader(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	cookie := signInToConsole(t, a, admin)

	rec := asConsole(t, a, http.MethodGet, "/v1/sessions", cookie.Value, "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}
}

func TestWhoAmIReportsTheSignedInAccount(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	cookie := signInToConsole(t, a, admin)

	rec := asConsole(t, a, http.MethodGet, "/v1/console/whoami", cookie.Value, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body)
	}

	body := decodeBody(t, rec)
	if body["role"] != "admin" {
		t.Errorf("role = %v, want admin: the console hides actions this account cannot take", body["role"])
	}
	if body["user_id"] == "" || body["user_name"] == "" {
		t.Errorf("whoami = %v, want an identified account", body)
	}
	if _, leaked := body["token"]; leaked {
		t.Error("whoami returns the credential")
	}
}

func TestWhoAmIIsRefusedBeforeSignIn(t *testing.T) {
	rec := asConsole(t, newTestApp(t), http.MethodGet, "/v1/console/whoami", "", "")

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the page decides whether to show the sign in dialog on this answer", rec.Code)
	}
}

func TestSigningOutEndsTheConsoleSession(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)
	cookie := signInToConsole(t, a, admin)

	rec := asConsole(t, a, http.MethodDelete, "/v1/console/session", cookie.Value, "")
	if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
		t.Fatalf("sign out: status = %d (%s)", rec.Code, rec.Body)
	}

	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == authz.CookieName && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("sign out did not expire the cookie, so closing the tab is the only way out")
	}
}

func TestRevokingTheTokenEndsTheConsoleSessionImmediately(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	created := send(t, a, http.MethodPost, "/v1/users", admin, `{"name":"console-operator","role":"operator"}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create user: status = %d (%s)", created.Code, created.Body)
	}
	userID, _ := decodeBody(t, created)["id"].(string)

	issued := send(t, a, http.MethodPost, "/v1/users/"+userID+"/tokens", admin, "")
	if issued.Code != http.StatusCreated {
		t.Fatalf("issue token: status = %d (%s)", issued.Code, issued.Body)
	}
	body := decodeBody(t, issued)
	operator, _ := body["secret"].(string)
	tokenID, _ := body["id"].(string)

	cookie := signInToConsole(t, a, operator)

	if rec := asConsole(t, a, http.MethodGet, "/v1/sessions", cookie.Value, ""); rec.Code != http.StatusOK {
		t.Fatalf("before revocation: status = %d (%s)", rec.Code, rec.Body)
	}

	if rec := send(t, a, http.MethodDelete, "/v1/tokens/"+tokenID, admin, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status = %d (%s)", rec.Code, rec.Body)
	}

	rec := asConsole(t, a, http.MethodGet, "/v1/sessions", cookie.Value, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: the cookie is the token, so revoking it must close the console too", rec.Code)
	}
}

func TestAViewerSignedIntoTheConsoleCannotReadSessions(t *testing.T) {
	a, admin := newTestAppWithAdmin(t)

	viewer := tokenForRole(t, a, admin, "console-viewer", "viewer")
	cookie := signInToConsole(t, a, viewer)

	if rec := asConsole(t, a, http.MethodGet, "/v1/version", cookie.Value, ""); rec.Code != http.StatusOK {
		t.Fatalf("version: status = %d, want 200: a viewer signs in and sees the gateway is alive", rec.Code)
	}

	rec := asConsole(t, a, http.MethodGet, "/v1/sessions", cookie.Value, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the console must not become a way around a role", rec.Code)
	}
}
