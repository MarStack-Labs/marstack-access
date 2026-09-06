package console

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func read(t *testing.T, name string) string {
	t.Helper()

	body, err := fs.ReadFile(assets, "assets/"+name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(body)
}

func matches(pattern, in string) []string {
	var found []string
	for _, m := range regexp.MustCompile(pattern).FindAllStringSubmatch(in, -1) {
		found = append(found, m[1])
	}
	sort.Strings(found)
	return found
}

func TestEveryElementTheScriptReachesForExists(t *testing.T) {
	page := read(t, "index.html")
	script := read(t, "console.js")

	declared := map[string]bool{}
	for _, id := range matches(`id="([^"]+)"`, page) {
		declared[id] = true
	}

	used := matches(`\$\("([^"]+)"\)`, script)
	if len(used) == 0 {
		t.Fatal("the script looks up no element, so this rule proves nothing")
	}

	for _, id := range used {
		if !declared[id] {
			t.Errorf("console.js looks up %q, which index.html does not declare. "+
				"getElementById returns null and the page dies on the first render, silently", id)
		}
	}
}

func TestEveryThemeTokenTheStylesheetUsesIsDefined(t *testing.T) {
	theme := read(t, "meridian.css")
	page := read(t, "console.css")

	defined := map[string]bool{}
	for _, token := range matches(`(--ms-[a-z0-9-]+)\s*:`, theme) {
		defined[token] = true
	}

	used := matches(`var\((--ms-[a-z0-9-]+)\)`, page)
	if len(used) == 0 {
		t.Fatal("console.css uses no theme token, so it is not on the design system")
	}

	for _, token := range used {
		if !defined[token] {
			t.Errorf("console.css uses %s, which meridian.css does not define. "+
				"An undefined custom property resolves to nothing and the rule is dropped silently", token)
		}
	}
}

func TestEveryThemeClassTheMarkupUsesIsDefined(t *testing.T) {
	stylesheets := read(t, "meridian.css") + read(t, "console.css")
	markup := read(t, "index.html") + read(t, "console.js")

	defined := map[string]bool{}
	for _, class := range matches(`\.(ms-[a-z0-9-]+)`, stylesheets) {
		defined[class] = true
	}

	seen := map[string]bool{}
	for _, class := range matches(`(ms-[a-z0-9]+(?:-[a-z0-9]+)*)`, markup) {
		if seen[class] || defined[class] {
			continue
		}
		seen[class] = true
		t.Errorf("the console uses the class %q, which no stylesheet defines. "+
			"A theme token of the same name is not a class: the element renders unstyled "+
			"and nothing reports it", class)
	}
}

func TestEveryToneTheScriptCanRenderHasAPill(t *testing.T) {
	script := read(t, "console.js")
	theme := read(t, "meridian.css")

	declared := matches(`const TONES = \[([^\]]+)\]`, script)
	if len(declared) != 1 {
		t.Fatal("console.js does not declare a single TONES list, so the tones it builds " +
			"class names from cannot be checked here")
	}

	tones := matches(`"([a-z]+)"`, declared[0])
	if len(tones) == 0 {
		t.Fatal("the TONES list is empty")
	}

	for _, tone := range tones {
		if !strings.Contains(theme, ".ms-pill-"+tone) {
			t.Errorf("the script can render the tone %q, but meridian.css has no .ms-pill-%s. "+
				"The class name is built at runtime, so nothing else would catch this", tone, tone)
		}
	}
}

func TestEveryFileThePageAsksForIsEmbedded(t *testing.T) {
	page := read(t, "index.html")

	referenced := append(
		matches(`<script src="([^"]+)"`, page),
		matches(`<link rel="stylesheet" href="([^"]+)"`, page)...)
	if len(referenced) == 0 {
		t.Fatal("the page references no asset, so this rule proves nothing")
	}

	for _, name := range referenced {
		if _, err := fs.ReadFile(assets, "assets/"+name); err != nil {
			t.Errorf("index.html loads %q, which is not embedded: %v", name, err)
		}
	}
}

func TestThePageCarriesNoInlineScriptOrHandler(t *testing.T) {
	page := read(t, "index.html")

	for _, body := range matches(`<script[^>]*>([^<]*)</script>`, page) {
		if strings.TrimSpace(body) != "" {
			t.Errorf("index.html carries inline script (%.40s). The policy has no unsafe-inline, "+
				"so the browser refuses to run it and the page is dead on arrival", body)
		}
	}
	if regexp.MustCompile(`\son[a-z]+\s*=`).MatchString(page) {
		t.Error("index.html carries an inline event handler, which the policy blocks")
	}
	if strings.Contains(page, "<style") {
		t.Error("index.html carries inline style, which the policy blocks")
	}
}

func TestThePolicyAllowsNothingOffThisOrigin(t *testing.T) {
	handler, err := Handler()
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, Prefix, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}

	got := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{
		"default-src 'self'",
		"base-uri 'none'",
		"frame-ancestors 'none'",
		"object-src 'none'",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("policy %q is missing %q", got, want)
		}
	}
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "https:", "*"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("policy %q allows %q", got, forbidden)
		}
	}
}

func TestTheConsoleRefusesAnythingButReading(t *testing.T) {
	handler, err := Handler()
	if err != nil {
		t.Fatalf("handler: %v", err)
	}

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(method, Prefix, nil))

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rec.Code)
		}
	}
}

func TestTheScriptSendsTheHeaderThatMakesTheCookieCount(t *testing.T) {
	script := read(t, "console.js")

	if !strings.Contains(script, "X-Marac-Console") {
		t.Fatal("the script never sends the console header, so every call it makes is unauthenticated")
	}
	if strings.Contains(script, "Authorization") {
		t.Error("the script builds an Authorization header, which means it holds the token. " +
			"The whole point of the cookie is that the page never sees the credential")
	}
	if strings.Contains(script, "localStorage") || strings.Contains(script, "sessionStorage") {
		t.Error("the script uses web storage, which is readable by any script on the page")
	}
}
