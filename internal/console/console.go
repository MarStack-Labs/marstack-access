package console

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed assets
var assets embed.FS

const (
	Prefix = "/console/"

	policy = "default-src 'self'; base-uri 'none'; form-action 'none'; " +
		"frame-ancestors 'none'; object-src 'none'; img-src 'self' data:"
)

func Handler() (http.Handler, error) {
	root, err := fs.Sub(assets, "assets")
	if err != nil {
		return nil, err
	}

	files := http.FileServerFS(root)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Security-Policy", policy)
		http.StripPrefix(strings.TrimSuffix(Prefix, "/"), files).ServeHTTP(w, r)
	}), nil
}
