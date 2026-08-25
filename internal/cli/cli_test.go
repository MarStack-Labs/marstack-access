package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marstack-labs/marstack-access/internal/version"
)

func run(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func runWithStdin(t *testing.T, stdin io.Reader, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	root := newRootCmd()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(stdin)
	root.SetArgs(args)

	err := root.Execute()
	return out.String(), err
}

func runAgainst(t *testing.T, endpoint string, args ...string) (string, error) {
	t.Helper()

	return run(t, append([]string{"--endpoint", endpoint}, args...)...)
}

func fakeControlPlane(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()

	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode response: %v", err)
	}
}

func TestVersionPrintsBuildMetadata(t *testing.T) {
	out, err := run(t, "version")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := strings.TrimSpace(out); got != version.String() {
		t.Fatalf("output = %q, want %q", got, version.String())
	}
}

func TestVersionRejectsArguments(t *testing.T) {
	if _, err := run(t, "version", "extra"); err == nil {
		t.Fatal("expected an error for an unexpected argument")
	}
}

func TestUnknownCommandFails(t *testing.T) {
	if _, err := run(t, "definitely-not-a-command"); err == nil {
		t.Fatal("expected an error for an unknown command")
	}
}

func TestEndpointComesFromTheEnvironmentWhenTheFlagIsAbsent(t *testing.T) {
	t.Setenv(endpointEnvVar, "http://control.internal:9000")

	if got := resolveDefaultEndpoint(); got != "http://control.internal:9000" {
		t.Fatalf("resolveDefaultEndpoint = %q, want the environment value", got)
	}
}

func TestEndpointFallsBackToLoopback(t *testing.T) {
	t.Setenv(endpointEnvVar, "")

	if got := resolveDefaultEndpoint(); got != defaultEndpoint {
		t.Fatalf("resolveDefaultEndpoint = %q, want %q", got, defaultEndpoint)
	}
}

func TestRegisterSendsTheFlagsAsJSON(t *testing.T) {
	var (
		received map[string]any
		method   string
		path     string
		mediaTyp string
	)

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		mediaTyp = r.Header.Get("Content-Type")
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, targetView{
			ID: "tgt-abc", Name: "db-1", Address: "10.0.0.4", Port: 2222,
			Principals: []string{"deploy", "postgres"}, CreatedAt: "2026-08-25T10:00:00Z",
		})
	})

	out, err := runAgainst(t, endpoint, "target", "register",
		"--name", "db-1", "--address", "10.0.0.4", "--port", "2222",
		"--principal", "deploy", "--principal", "postgres")
	if err != nil {
		t.Fatalf("unexpected error: %v (out: %s)", err, out)
	}

	if method != http.MethodPost || path != "/v1/targets" {
		t.Errorf("request = %s %s, want POST /v1/targets", method, path)
	}
	if mediaTyp != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", mediaTyp)
	}
	if received["name"] != "db-1" || received["address"] != "10.0.0.4" {
		t.Errorf("received = %v", received)
	}
	if received["port"] != float64(2222) {
		t.Errorf("port = %v, want 2222", received["port"])
	}

	principals, ok := received["principals"].([]any)
	if !ok || len(principals) != 2 {
		t.Fatalf("principals = %v, want two entries", received["principals"])
	}
	if principals[0] != "deploy" || principals[1] != "postgres" {
		t.Errorf("principals = %v, want [deploy postgres] in the order given", principals)
	}

	if !strings.Contains(out, "db-1") || !strings.Contains(out, "tgt-abc") {
		t.Errorf("output does not show the created target: %s", out)
	}
}

func TestRegisterSplitsACommaSeparatedPrincipalFlag(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, targetView{ID: "tgt-abc", Name: "db-1"})
	})

	if _, err := runAgainst(t, endpoint, "target", "register",
		"--name", "db-1", "--address", "10.0.0.4", "--principal", "deploy,postgres"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	principals, ok := received["principals"].([]any)
	if !ok || len(principals) != 2 {
		t.Fatalf("principals = %v, want the comma form split into two", received["principals"])
	}
}

func TestRegisterOmitsAnUnsetPortSoTheServerOwnsTheDefault(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, targetView{ID: "tgt-abc", Name: "db-1", Port: 22})
	})

	if _, err := runAgainst(t, endpoint, "target", "register",
		"--name", "db-1", "--address", "10.0.0.4", "--principal", "deploy"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, present := received["port"]; present {
		t.Fatal("port was sent even though the flag was unset, so the server default is bypassed and the two could drift")
	}
}

func TestRegisterRequiresNameAddressAndPrincipal(t *testing.T) {
	cases := map[string][]string{
		"no name":      {"--address", "10.0.0.4", "--principal", "deploy"},
		"no address":   {"--name", "db-1", "--principal", "deploy"},
		"no principal": {"--name", "db-1", "--address", "10.0.0.4"},
	}

	for label, args := range cases {
		endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: the control plane must not be called when a required flag is missing", label)
		})

		if _, err := runAgainst(t, endpoint, append([]string{"target", "register"}, args...)...); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestListRendersATable(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{
			{ID: "tgt-abc", Name: "db-1", Address: "10.0.0.4", Port: 22,
				Principals: []string{"deploy", "postgres"}, CreatedAt: "2026-08-25T10:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "target", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for _, want := range []string{"NAME", "PRINCIPALS", "db-1", "tgt-abc", "10.0.0.4", "deploy,postgres"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestListRendersJSON(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{
			{ID: "tgt-abc", Name: "db-1", Principals: []string{"deploy"}},
		}})
	})

	out, err := runAgainst(t, endpoint, "target", "list", "--output", "json")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed targetListView
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v (%s)", err, out)
	}
	if len(parsed.Targets) != 1 || parsed.Targets[0].ID != "tgt-abc" {
		t.Fatalf("parsed = %+v, want one target tgt-abc", parsed.Targets)
	}
}

func TestEmptyListIsReported(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{}})
	})

	out, err := runAgainst(t, endpoint, "target", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "no results") {
		t.Fatalf("output = %q, want a no-results message rather than a bare header row", out)
	}
}

func TestATargetWithNoPrincipalsRendersAPlaceholder(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{
			{ID: "tgt-abc", Name: "db-1", Port: 22},
		}})
	})

	out, err := runAgainst(t, endpoint, "target", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "-") {
		t.Fatalf("output = %q, want a placeholder so columns stay aligned", out)
	}
}

func TestUnknownOutputFormatFails(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{{ID: "tgt-abc"}}})
	})

	if _, err := runAgainst(t, endpoint, "target", "list", "--output", "yaml"); err == nil {
		t.Fatal("expected an error for an unknown output format")
	}
}

func TestGetRequestsTheTargetByID(t *testing.T) {
	var path string

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		writeJSON(t, w, http.StatusOK, targetView{ID: "tgt-abc", Name: "db-1", Port: 22})
	})

	if _, err := runAgainst(t, endpoint, "target", "get", "tgt-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "GET /v1/targets/tgt-abc"; path != want {
		t.Fatalf("request = %q, want %q", path, want)
	}
}

func TestGetRequiresAnID(t *testing.T) {
	endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
		t.Error("the control plane must not be called without an id")
	})

	if _, err := runAgainst(t, endpoint, "target", "get"); err == nil {
		t.Fatal("expected an error when the id is missing")
	}
}

func TestDeleteAcceptsNoContent(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("method = %s, want DELETE", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out, err := runAgainst(t, endpoint, "target", "delete", "tgt-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "deleted tgt-abc") {
		t.Fatalf("output = %q, want a deletion confirmation", out)
	}
}

func TestAPIErrorIsReportedWithItsCode(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
		if _, err := w.Write([]byte(
			`{"error":{"code":"target_name_taken","message":"a target with that name is already registered"}}`,
		)); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	_, err := runAgainst(t, endpoint, "target", "register",
		"--name", "db-1", "--address", "10.0.0.4", "--principal", "deploy")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "target_name_taken") {
		t.Fatalf("error = %q, want it to carry the API error code", err)
	}
}

func TestAnErrorBodyThatIsNotAnEnvelopeStillFails(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		if _, err := w.Write([]byte("<html>proxy error</html>")); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	_, err := runAgainst(t, endpoint, "target", "list")
	if err == nil {
		t.Fatal("expected an error: a proxy in front of the control plane must not read as success")
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("error = %q, want it to name the status code", err)
	}
}

func TestAnUnreachableEndpointNamesTheEndpoint(t *testing.T) {
	_, err := runAgainst(t, "http://127.0.0.1:1", "target", "list")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "127.0.0.1:1") {
		t.Fatalf("error = %q, want it to name the endpoint that failed", err)
	}
}

func TestTargetsIsAnAliasForTarget(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{}})
	})

	if _, err := runAgainst(t, endpoint, "targets", "list"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTheTokenFlagBecomesABearerHeader(t *testing.T) {
	var header string

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		header = r.Header.Get("Authorization")
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{}})
	})

	if _, err := run(t, "--endpoint", endpoint, "--token", "mat_sel_ver", "target", "list"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "Bearer mat_sel_ver"; header != want {
		t.Fatalf("Authorization = %q, want %q", header, want)
	}
}

func TestTheTokenComesFromTheEnvironment(t *testing.T) {
	t.Setenv(tokenEnvVar, "mat_from_env")

	if got := resolveDefaultToken(); got != "mat_from_env" {
		t.Fatalf("resolveDefaultToken = %q, want the environment value", got)
	}
}

func TestNoTokenSendsNoAuthorizationHeader(t *testing.T) {
	t.Setenv(tokenEnvVar, "")
	var present bool

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["Authorization"]
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte(`{"error":{"code":"invalid_token","message":"the token is missing"}}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	_, err := run(t, "--endpoint", endpoint, "target", "list")
	if err == nil {
		t.Fatal("expected an error")
	}
	if present {
		t.Error("an empty token still produced an Authorization header, which turns a missing credential into a malformed one")
	}
	if !strings.Contains(err.Error(), "invalid_token") {
		t.Fatalf("error = %q, want the server's code so the cause is unambiguous", err)
	}
}

func TestAForbiddenResponseNamesTheRole(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(
			`{"error":{"code":"insufficient_role","message":"this action requires the operator role"}}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	_, err := runAgainst(t, endpoint, "target", "list")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "operator") {
		t.Fatalf("error = %q, want it to name the missing role", err)
	}
}

func TestUserCreateSendsNameAndRole(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/users" {
			t.Errorf("request = %s %s, want POST /v1/users", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, userView{
			ID: "usr-abc", Name: "deployer", Role: "operator", CreatedAt: "2026-08-25T10:00:00Z",
		})
	})

	out, err := runAgainst(t, endpoint, "user", "create", "--name", "deployer", "--role", "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}
	if received["name"] != "deployer" || received["role"] != "operator" {
		t.Fatalf("received = %v", received)
	}
	if !strings.Contains(out, "usr-abc") {
		t.Fatalf("output does not show the created user: %s", out)
	}
}

func TestUserCreateRequiresNameAndRole(t *testing.T) {
	for label, args := range map[string][]string{
		"no name": {"--role", "operator"},
		"no role": {"--name", "deployer"},
	} {
		endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: the control plane must not be called", label)
		})
		if _, err := runAgainst(t, endpoint, append([]string{"user", "create"}, args...)...); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestTokenIssuePrintsTheSecretAndSaysItIsNotShownAgain(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/users/usr-abc/tokens"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(t, w, http.StatusCreated, issuedTokenView{
			tokenView: tokenView{ID: "tok-abc", UserID: "usr-abc", Selector: "sel"},
			Secret:    "mat_sel_verifier",
		})
	})

	out, err := runAgainst(t, endpoint, "token", "issue", "--user", "usr-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "mat_sel_verifier") {
		t.Fatalf("the secret was not printed: %s", out)
	}
	if !strings.Contains(out, "not shown again") {
		t.Fatalf("output does not warn that the secret is unrecoverable: %s", out)
	}
}

func TestTokenIssueSendsTheTTLOnlyWhenGiven(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, issuedTokenView{
			tokenView: tokenView{ID: "tok-abc"}, Secret: "mat_a_b",
		})
	})

	if _, err := runAgainst(t, endpoint, "token", "issue", "--user", "usr-abc"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := received["ttl"]; present {
		t.Error("ttl was sent without the flag, so the server default is bypassed")
	}

	if _, err := runAgainst(t, endpoint, "token", "issue", "--user", "usr-abc", "--ttl", "24h"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if received["ttl"] != "24h" {
		t.Fatalf("ttl = %v, want 24h", received["ttl"])
	}
}

func TestTokenListShowsNoSecretColumn(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, tokenListView{Tokens: []tokenView{
			{ID: "tok-abc", UserID: "usr-abc", Selector: "sel", CreatedAt: "2026-08-25T10:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "token", "list", "--user", "usr-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, unwanted := range []string{"SECRET", "mat_"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("the listing shows %q: %s", unwanted, out)
		}
	}
	if !strings.Contains(out, "tok-abc") || !strings.Contains(out, "sel") {
		t.Fatalf("the listing is missing the token id or selector: %s", out)
	}
}

func TestATokenWithNoExpiryRendersAPlaceholder(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, tokenListView{Tokens: []tokenView{
			{ID: "tok-abc", UserID: "usr-abc", Selector: "sel", CreatedAt: "2026-08-25T10:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "token", "list", "--user", "usr-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "EXPIRES") || !strings.Contains(out, "-") {
		t.Fatalf("output = %q, want an EXPIRES column with a placeholder", out)
	}
}

func TestTokenRevokeConfirms(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/tokens/tok-abc" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out, err := runAgainst(t, endpoint, "token", "revoke", "tok-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "revoked tok-abc") {
		t.Fatalf("output = %q, want a revocation confirmation", out)
	}
}

func TestPolicyCreateWithAUserSubject(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/policies" {
			t.Errorf("request = %s %s, want POST /v1/policies", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, policyView{
			ID: "pol-abc", Name: "db-deploy", SubjectKind: "user", SubjectID: "usr-abc",
			TargetID: "tgt-abc", Principals: []string{"deploy"}, CreatedAt: "2026-08-25T10:00:00Z",
		})
	})

	out, err := runAgainst(t, endpoint, "policy", "create",
		"--name", "db-deploy", "--user", "usr-abc", "--target", "tgt-abc", "--principal", "deploy")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}

	if received["subject_kind"] != "user" || received["subject_id"] != "usr-abc" {
		t.Fatalf("received = %v, want a user subject", received)
	}
	if !strings.Contains(out, "user:usr-abc") {
		t.Errorf("output does not show the subject: %s", out)
	}
}

func TestPolicyCreateWithARoleSubject(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, policyView{ID: "pol-abc", SubjectKind: "role", SubjectID: "operator"})
	})

	if _, err := runAgainst(t, endpoint, "policy", "create",
		"--name", "ops-db", "--role", "operator", "--target", "tgt-abc", "--principal", "deploy"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if received["subject_kind"] != "role" || received["subject_id"] != "operator" {
		t.Fatalf("received = %v, want a role subject", received)
	}
}

func TestPolicyCreateRefusesBothSubjectsAndNeither(t *testing.T) {
	cases := map[string][]string{
		"both":    {"--name", "p", "--user", "usr-abc", "--role", "operator", "--target", "tgt-abc", "--principal", "deploy"},
		"neither": {"--name", "p", "--target", "tgt-abc", "--principal", "deploy"},
	}

	for label, args := range cases {
		endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: the control plane must not be called", label)
		})
		if _, err := runAgainst(t, endpoint, append([]string{"policy", "create"}, args...)...); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestPolicyEvaluatePrintsTheDecisionAndTheReason(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/policies/evaluate"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(t, w, http.StatusOK, decisionView{
			Allowed: false, Reason: "no policy grants this user the requested principal on this target",
		})
	})

	out, err := runAgainst(t, endpoint, "policy", "evaluate",
		"--user", "usr-abc", "--target", "tgt-abc", "--principal", "deploy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "allowed: false") {
		t.Errorf("output does not state the verdict: %s", out)
	}
	if !strings.Contains(out, "no policy grants") {
		t.Errorf("output does not state the reason, so a denial is undiagnosable: %s", out)
	}
}

func TestPolicyEvaluateOmitsAnUnsetRole(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusOK, decisionView{Allowed: true, PolicyID: "pol-abc", Reason: "granted"})
	})

	if _, err := runAgainst(t, endpoint, "policy", "evaluate",
		"--user", "usr-abc", "--target", "tgt-abc", "--principal", "deploy"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := received["role"]; present {
		t.Error("an empty role was sent, which the server would reject as an unknown role")
	}
}

func TestPolicyListRendersATable(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, policyListView{Policies: []policyView{
			{ID: "pol-abc", Name: "db-deploy", SubjectKind: "role", SubjectID: "operator",
				TargetID: "tgt-abc", Principals: []string{"deploy", "postgres"}},
		}})
	})

	out, err := runAgainst(t, endpoint, "policy", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"SUBJECT", "PRINCIPALS", "role:operator", "deploy,postgres", "tgt-abc"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestPolicyDeleteConfirms(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/policies/pol-abc" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out, err := runAgainst(t, endpoint, "policy", "delete", "pol-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "deleted pol-abc") {
		t.Fatalf("output = %q, want a deletion confirmation", out)
	}
}

func TestRequestCreateNeverSendsARequesterID(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/access-requests" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, requestView{
			ID: "req-abc", RequesterID: "usr-abc", TargetID: "tgt-abc",
			Principal: "deploy", Reason: "incident 42", State: "pending",
		})
	})

	out, err := runAgainst(t, endpoint, "request", "create",
		"--target", "tgt-abc", "--principal", "deploy", "--reason", "incident 42")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}

	for _, forbidden := range []string{"requester_id", "user_id", "requester"} {
		if _, present := received[forbidden]; present {
			t.Errorf("the client sent %q. The requester must come from the token, or a caller could raise a request as somebody else", forbidden)
		}
	}
	if received["reason"] != "incident 42" {
		t.Errorf("reason = %v", received["reason"])
	}
	if !strings.Contains(out, "req-abc") || !strings.Contains(out, "pending") {
		t.Errorf("output does not show the raised request: %s", out)
	}
}

func TestRequestCreateRequiresTargetPrincipalAndReason(t *testing.T) {
	cases := map[string][]string{
		"no target":    {"--principal", "deploy", "--reason", "r"},
		"no principal": {"--target", "tgt-abc", "--reason", "r"},
		"no reason":    {"--target", "tgt-abc", "--principal", "deploy"},
	}

	for label, args := range cases {
		endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: the control plane must not be called", label)
		})
		if _, err := runAgainst(t, endpoint, append([]string{"request", "create"}, args...)...); err == nil {
			t.Errorf("%s: expected an error", label)
		}
	}
}

func TestRequestCreateOmitsAnUnsetTTL(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, requestView{ID: "req-abc", State: "pending"})
	})

	if _, err := runAgainst(t, endpoint, "request", "create",
		"--target", "tgt-abc", "--principal", "deploy", "--reason", "r"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, present := received["ttl"]; present {
		t.Error("ttl was sent unset, bypassing the platform default")
	}
}

func TestRequestDecisionsPostToTheRightSubpath(t *testing.T) {
	for _, verb := range []string{"approve", "deny", "cancel"} {
		var path string

		endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
			path = r.Method + " " + r.URL.Path
			writeJSON(t, w, http.StatusOK, requestView{ID: "req-abc", State: verb})
		})

		if _, err := runAgainst(t, endpoint, "request", verb, "req-abc"); err != nil {
			t.Fatalf("%s: unexpected error: %v", verb, err)
		}
		if want := "POST /v1/access-requests/req-abc/" + verb; path != want {
			t.Errorf("%s: request = %q, want %q", verb, path, want)
		}
	}
}

func TestRequestDecisionsRequireAnID(t *testing.T) {
	for _, verb := range []string{"approve", "deny", "cancel", "get"} {
		endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
			t.Errorf("%s: the control plane must not be called without an id", verb)
		})
		if _, err := runAgainst(t, endpoint, "request", verb); err == nil {
			t.Errorf("%s: expected an error", verb)
		}
	}
}

func TestSelfApprovalIsReportedClearly(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		if _, err := w.Write([]byte(
			`{"error":{"code":"self_approval","message":"a request cannot be decided by the account that raised it"}}`)); err != nil {
			t.Errorf("write: %v", err)
		}
	})

	_, err := runAgainst(t, endpoint, "request", "approve", "req-abc")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "self_approval") {
		t.Fatalf("error = %q, want the self_approval code", err)
	}
}

func TestRequestListRendersATable(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, requestListView{Requests: []requestView{
			{ID: "req-abc", State: "approved", RequesterID: "usr-abc", TargetID: "tgt-abc",
				Principal: "deploy", Reason: "incident 42", GrantExpires: "2026-08-25T12:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "request", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"STATE", "GRANT EXPIRES", "approved", "incident 42"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRequestGrantReportsInactiveWithoutInventingFields(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/access-requests/grant"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(t, w, http.StatusOK, grantView{Active: false})
	})

	out, err := runAgainst(t, endpoint, "request", "grant",
		"--user", "usr-abc", "--target", "tgt-abc", "--principal", "deploy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "active:  false") {
		t.Fatalf("output = %q, want the verdict", out)
	}
	if strings.Contains(out, "expires:") {
		t.Fatalf("an inactive grant printed an expiry: %s", out)
	}
}

func TestRequestGrantShowsTheReasonWhenActive(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, grantView{
			Active: true, RequestID: "req-abc",
			ExpiresAt: "2026-08-25T12:00:00Z", Reason: "incident 42",
		})
	})

	out, err := runAgainst(t, endpoint, "request", "grant",
		"--user", "usr-abc", "--target", "tgt-abc", "--principal", "deploy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"active:  true", "req-abc", "incident 42"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q: %s", want, out)
		}
	}
}

func TestKeyAddSendsTheAuthorizedKeysLine(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/users/usr-abc/keys"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, keyView{
			ID: "key-abc", UserID: "usr-abc", Name: "laptop",
			Type: "ssh-ed25519", Fingerprint: "SHA256:abc",
		})
	})

	out, err := runAgainst(t, endpoint, "key", "add",
		"--user", "usr-abc", "--name", "laptop", "--public-key", "ssh-ed25519 AAAAC3Nz alice@laptop")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}
	if received["public_key"] != "ssh-ed25519 AAAAC3Nz alice@laptop" {
		t.Fatalf("public_key = %v", received["public_key"])
	}
	if !strings.Contains(out, "SHA256:abc") {
		t.Errorf("output does not show the fingerprint: %s", out)
	}
}

func TestKeyAddReadsStdin(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, keyView{ID: "key-abc"})
	})

	out, err := runWithStdin(t, strings.NewReader("ssh-ed25519 AAAAC3Nz alice@laptop\n"),
		"--endpoint", endpoint, "key", "add", "--user", "usr-abc", "--name", "laptop")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}
	if received["public_key"] != "ssh-ed25519 AAAAC3Nz alice@laptop" {
		t.Fatalf("public_key = %q, want the piped key trimmed", received["public_key"])
	}
}

func TestKeyAddRefusesAnEmptyPipe(t *testing.T) {
	endpoint := fakeControlPlane(t, func(http.ResponseWriter, *http.Request) {
		t.Error("the control plane must not be called with no key")
	})

	if _, err := runWithStdin(t, strings.NewReader("   \n"),
		"--endpoint", endpoint, "key", "add", "--user", "usr-abc", "--name", "k"); err == nil {
		t.Fatal("expected an error for an empty pipe")
	}
}

func TestKeyAddCapsThePipedKeySize(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusCreated, keyView{ID: "key-abc"})
	})

	oversized := strings.Repeat("A", maxPipedKeyBytes*2)
	if _, err := runWithStdin(t, strings.NewReader(oversized),
		"--endpoint", endpoint, "key", "add", "--user", "usr-abc", "--name", "k"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sent, _ := received["public_key"].(string)
	if len(sent) > maxPipedKeyBytes {
		t.Fatalf("sent %d bytes, want at most %d: stdin is attacker-controlled length in a pipeline",
			len(sent), maxPipedKeyBytes)
	}
}

func TestKeyListShowsFingerprintsAndNoKeyMaterial(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, keyListView{Keys: []keyView{
			{ID: "key-abc", UserID: "usr-abc", Name: "laptop",
				Type: "ssh-ed25519", Fingerprint: "SHA256:abc", CreatedAt: "2026-08-25T10:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "key", "list", "--user", "usr-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"FINGERPRINT", "SHA256:abc", "ssh-ed25519", "laptop"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "AAAAC3Nz") {
		t.Errorf("the listing shows key material: %s", out)
	}
}

func TestKeyRemoveConfirms(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/v1/keys/key-abc" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	out, err := runAgainst(t, endpoint, "key", "remove", "key-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "removed key-abc") {
		t.Fatalf("output = %q, want a removal confirmation", out)
	}
}

func TestCAInitPrintsTheTargetSetup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")

	out, err := run(t, "ca", "init", "--path", path)
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}

	for _, want := range []string{
		"fingerprint SHA256:",
		"TrustedUserCAKeys",
		"AuthorizedPrincipalsFile",
		"ssh-ed25519",
		"no daemon runs there",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestCAInitRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")

	if _, err := run(t, "ca", "init", "--path", path); err != nil {
		t.Fatalf("first init: %v", err)
	}
	if _, err := run(t, "ca", "init", "--path", path); err == nil {
		t.Fatal("a second init overwrote the key, which would silently break every target that trusts it")
	}
}

func TestCAShowMatchesInit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca")

	created, err := run(t, "ca", "init", "--path", path)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	shown, err := run(t, "ca", "show", "--path", path)
	if err != nil {
		t.Fatalf("show: %v", err)
	}

	fingerprint := func(out string) string {
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "fingerprint ") {
				return line
			}
		}
		return ""
	}

	if got, want := fingerprint(shown), fingerprint(created); got == "" || got != want {
		t.Fatalf("show reported %q, init reported %q", got, want)
	}
}

func TestCAShowRejectsAMissingKey(t *testing.T) {
	if _, err := run(t, "ca", "show", "--path", filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected an error for a missing key")
	}
}

func TestTargetTrustPipesSSHKeyscanOutput(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/targets/tgt-abc/host-key"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusOK, targetView{
			ID: "tgt-abc", Name: "db-1", Port: 22, Fingerprint: "SHA256:abc",
		})
	})

	scanned := "# 10.0.0.4:22 SSH-2.0-OpenSSH_9.6\n10.0.0.4 ssh-ed25519 AAAAC3Nz\n"

	out, err := runWithStdin(t, strings.NewReader(scanned),
		"--endpoint", endpoint, "target", "trust", "--target", "tgt-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v (%s)", err, out)
	}

	sent, _ := received["host_key"].(string)
	if !strings.Contains(sent, "ssh-ed25519") {
		t.Fatalf("host_key = %q, want the scanned key", sent)
	}
	if !strings.Contains(out, "SHA256:abc") {
		t.Errorf("output does not show the pinned fingerprint: %s", out)
	}
}

func TestTargetTrustSendsReplaceOnlyWhenAsked(t *testing.T) {
	var received map[string]any

	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode: %v", err)
		}
		writeJSON(t, w, http.StatusOK, targetView{ID: "tgt-abc"})
	})

	if _, err := runAgainst(t, endpoint, "target", "trust",
		"--target", "tgt-abc", "--host-key", "ssh-ed25519 AAAA"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replace, _ := received["replace"].(bool); replace {
		t.Error("replace was sent true without the flag")
	}

	if _, err := runAgainst(t, endpoint, "target", "trust",
		"--target", "tgt-abc", "--host-key", "ssh-ed25519 AAAA", "--replace"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if replace, _ := received["replace"].(bool); !replace {
		t.Error("replace was not sent even with the flag")
	}
}

func TestTargetListShowsTheHostKeyColumn(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, targetListView{Targets: []targetView{
			{ID: "tgt-abc", Name: "db-1", Address: "10.0.0.4", Port: 22,
				Principals: []string{"deploy"}},
			{ID: "tgt-def", Name: "db-2", Address: "10.0.0.5", Port: 22,
				Principals: []string{"deploy"}, Fingerprint: "SHA256:abc"},
		}})
	})

	out, err := runAgainst(t, endpoint, "target", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "HOST KEY") {
		t.Errorf("output has no HOST KEY column: %s", out)
	}
	if !strings.Contains(out, "SHA256:abc") {
		t.Errorf("output does not show a pinned fingerprint: %s", out)
	}
	if !strings.Contains(out, "-") {
		t.Errorf("an unpinned target shows no placeholder, so it is hard to spot: %s", out)
	}
}

func TestSessionListShowsStateAndUser(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, sessionListView{Sessions: []sessionView{
			{ID: "ses-abc", Active: true, UserName: "alice", TargetName: "db-1",
				Principal: "deploy", StartedAt: "2026-08-25T10:00:00Z", RecordedBytes: 4096},
			{ID: "ses-def", Active: false, UserName: "bob", TargetName: "db-2",
				Principal: "postgres", StartedAt: "2026-08-25T09:00:00Z"},
		}})
	})

	out, err := runAgainst(t, endpoint, "session", "list")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"STATE", "active", "closed", "alice", "db-1", "4096"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestSessionGetShowsWhereTheRecordingIs(t *testing.T) {
	endpoint := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, sessionView{
			ID: "ses-abc", Active: false, UserName: "alice", TargetName: "db-1",
			Principal: "deploy", StartedAt: "2026-08-25T10:00:00Z",
			Recording: "/data/recordings/ses-abc.cast", Reason: "target exit status",
		})
	})

	out, err := runAgainst(t, endpoint, "session", "get", "ses-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "/data/recordings/ses-abc.cast") {
		t.Errorf("output does not say where the recording is: %s", out)
	}
	if !strings.Contains(out, "target exit status") {
		t.Errorf("output does not show why the session ended: %s", out)
	}
}

func TestSessionKillReportsWhetherASocketWasClosed(t *testing.T) {
	closed := fakeControlPlane(t, func(w http.ResponseWriter, r *http.Request) {
		if want := "/v1/sessions/ses-abc/kill"; r.URL.Path != want {
			t.Errorf("path = %q, want %q", r.URL.Path, want)
		}
		writeJSON(t, w, http.StatusOK, killView{Killed: true, Session: sessionView{ID: "ses-abc"}})
	})

	out, err := runAgainst(t, closed, "session", "kill", "ses-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "closed ses-abc") {
		t.Fatalf("output = %q, want a confirmation", out)
	}

	notClosed := fakeControlPlane(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, http.StatusOK, killView{
			Killed:  false,
			Session: sessionView{ID: "ses-abc"},
			Note:    "no socket for it is held here",
		})
	})

	out, err = runAgainst(t, notClosed, "session", "kill", "ses-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "not closed") || !strings.Contains(out, "no socket") {
		t.Fatalf("output = %q, want it to say nothing was closed and why. Printing a bare confirmation would tell an incident responder the session is gone when it is not", out)
	}
}
