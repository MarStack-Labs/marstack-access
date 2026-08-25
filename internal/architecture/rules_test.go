package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/marstack-labs/marstack-access"

const selfPkg = "internal/architecture"

type sourceFile struct {
	pkg      string
	path     string
	imports  []string
	external []string
}

func repoRoot(t *testing.T) string {
	t.Helper()

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return root
}

func loadSources(t *testing.T) []sourceFile {
	t.Helper()

	root := repoRoot(t)
	fset := token.NewFileSet()
	var files []sourceFile

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name != "." && (strings.HasPrefix(name, ".") || name == "bin" || name == "data") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		parsed, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}

		rel, relErr := filepath.Rel(root, filepath.Dir(path))
		if relErr != nil {
			return relErr
		}

		sf := sourceFile{
			pkg:  filepath.ToSlash(rel),
			path: filepath.ToSlash(strings.TrimPrefix(path, root+string(filepath.Separator))),
		}
		for _, spec := range parsed.Imports {
			unquoted, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if strings.HasPrefix(unquoted, modulePath+"/") {
				sf.imports = append(sf.imports, strings.TrimPrefix(unquoted, modulePath+"/"))
			} else {
				sf.external = append(sf.external, unquoted)
			}
		}
		files = append(files, sf)
		return nil
	})
	if err != nil {
		t.Fatalf("walk sources: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no Go sources found")
	}
	return files
}

func platformModuleOf(pkg string) (string, bool) {
	const prefix = "internal/platform/"
	if !strings.HasPrefix(pkg, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(pkg, prefix)
	if rest == "" {
		return "", false
	}
	return strings.Split(rest, "/")[0], true
}

func TestKernelDoesNotDependOnPlatformOrApp(t *testing.T) {
	for _, f := range loadSources(t) {
		if !strings.HasPrefix(f.pkg, "internal/kernel/") {
			continue
		}
		for _, imp := range f.imports {
			if strings.HasPrefix(imp, "internal/platform/") || imp == "internal/app" || imp == "internal/store" {
				t.Errorf("%s imports %s: kernel must not depend on platform, app, or store", f.path, imp)
			}
		}
	}
}

func TestPlatformModulesDoNotImportEachOther(t *testing.T) {
	for _, f := range loadSources(t) {
		owner, ok := platformModuleOf(f.pkg)
		if !ok {
			continue
		}
		for _, imp := range f.imports {
			target, isPlatform := platformModuleOf(imp)
			if isPlatform && target != owner {
				t.Errorf("%s imports platform module %q: modules must not depend on each other directly", f.path, target)
			}
		}
	}
}

func TestPlatformDoesNotImportApp(t *testing.T) {
	for _, f := range loadSources(t) {
		if _, ok := platformModuleOf(f.pkg); !ok {
			continue
		}
		for _, imp := range f.imports {
			if imp == "internal/app" {
				t.Errorf("%s imports internal/app: the composition root must depend on modules, never the reverse", f.path)
			}
		}
	}
}

func TestStoreStaysInfrastructure(t *testing.T) {
	for _, f := range loadSources(t) {
		if f.pkg != "internal/store" {
			continue
		}
		for _, imp := range f.imports {
			if strings.HasPrefix(imp, "internal/platform/") || imp == "internal/app" {
				t.Errorf("%s imports %s: store must not know about platform modules", f.path, imp)
			}
		}
	}
}

func TestCommandOnlyWiresTheCLI(t *testing.T) {
	for _, f := range loadSources(t) {
		if !strings.HasPrefix(f.pkg, "cmd/") {
			continue
		}
		for _, imp := range f.imports {
			if imp != "internal/cli" {
				t.Errorf("%s imports %s: cmd must only wire internal/cli", f.path, imp)
			}
		}
	}
}

func TestDataPlaneDoesNotImportPlatformOrApp(t *testing.T) {
	for _, f := range loadSources(t) {
		if !strings.HasPrefix(f.pkg, "internal/dataplane/") {
			continue
		}
		for _, imp := range f.imports {
			if strings.HasPrefix(imp, "internal/platform/") || imp == "internal/app" || imp == "internal/store" {
				t.Errorf("%s imports %s: the data plane reaches the control plane through interfaces it declares, "+
					"because that seam becomes a network boundary the day the planes are split", f.path, imp)
			}
		}
	}
}

func TestPlatformDoesNotImportTheDataPlane(t *testing.T) {
	for _, f := range loadSources(t) {
		if _, ok := platformModuleOf(f.pkg); !ok {
			continue
		}
		for _, imp := range f.imports {
			if strings.HasPrefix(imp, "internal/dataplane/") {
				t.Errorf("%s imports %s: a control plane module must not depend on the thing that calls it", f.path, imp)
			}
		}
	}
}

func TestEveryPlatformRouteDeclaresWhoMayCallIt(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	checked := 0

	err := filepath.WalkDir(filepath.Join(root, "internal", "platform"),
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			parsed, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}

			ast.Inspect(parsed, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isMuxHandle(call) || len(call.Args) < 2 {
					return true
				}

				checked++
				if guardOf(call.Args[1]) == "" {
					t.Errorf("%s:%d registers a route whose handler is not wrapped in Require or Public. "+
						"An endpoint is unreachable until it declares who may call it, and silence is not a declaration",
						filepath.ToSlash(rel), fset.Position(call.Pos()).Line)
				}
				return true
			})
			return nil
		})
	if err != nil {
		t.Fatalf("walk platform: %v", err)
	}

	if checked == 0 {
		t.Fatal("no route registrations were found, so this rule proves nothing")
	}
}

func isMuxHandle(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Handle" {
		return false
	}
	receiver, ok := sel.X.(*ast.Ident)
	return ok && receiver.Name == "mux"
}

func guardOf(arg ast.Expr) string {
	found := ""

	ast.Inspect(arg, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sel.Sel.Name == "Require" || sel.Sel.Name == "Public" {
			found = sel.Sel.Name
			return false
		}
		return true
	})

	return found
}

func TestNoAuditSinkCanDeleteAnything(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	forbidden := []string{"Delete", "Remove", "Truncate", "Purge", "Rotate", "Prune", "Clear"}
	checked := 0

	err := filepath.WalkDir(filepath.Join(root, "internal", "kernel", "audit"),
		func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			parsed, parseErr := parser.ParseFile(fset, path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			checked++

			for _, decl := range parsed.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				for _, verb := range forbidden {
					if strings.Contains(fn.Name.Name, verb) {
						t.Errorf("%s:%d declares %s. An audit trail this process can shorten is not a trail. "+
							"Retention belongs to whatever stores the events, not to the thing that writes them",
							filepath.ToSlash(rel), fset.Position(fn.Pos()).Line, fn.Name.Name)
					}
				}
			}
			return nil
		})
	if err != nil {
		t.Fatalf("walk audit: %v", err)
	}

	if checked == 0 {
		t.Fatal("no audit sources were read, so this rule proves nothing")
	}
}

func TestRandomnessIsAlwaysCryptographic(t *testing.T) {
	for _, f := range loadSources(t) {
		if f.pkg == selfPkg {
			continue
		}
		for _, imp := range f.external {
			if imp == "math/rand" || imp == "math/rand/v2" {
				t.Errorf("%s imports %s: this repository generates ids, nonces, and keys, so crypto/rand is the only source of randomness — including in tests", f.path, imp)
			}
		}
	}
}

func TestHostKeyVerificationIsNeverDisabled(t *testing.T) {
	forbidden := []string{
		"InsecureIgnoreHostKey",
		"InsecureSkipVerify",
	}

	root := repoRoot(t)

	for _, f := range loadSources(t) {
		if f.pkg == selfPkg {
			continue
		}

		content, err := os.ReadFile(filepath.Join(root, f.path))
		if err != nil {
			t.Fatalf("read %s: %v", f.path, err)
		}

		for _, needle := range forbidden {
			if strings.Contains(string(content), needle) {
				t.Errorf("%s references %s: a target's identity is verified in every build, and a test that needs a host key generates one", f.path, needle)
			}
		}
	}
}
