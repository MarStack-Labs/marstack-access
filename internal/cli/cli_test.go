package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
