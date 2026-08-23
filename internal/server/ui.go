package server

import (
	"errors"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// handleUI serves the embedded Angular application.
//
// Any path that does not name a real file falls through to index.html, because the application routes
// client-side and a browser loading /hosts/01J9ABC directly must get the application rather than a 404.
// Paths under /api and /agent never reach here: routes() registers a subtree pattern for each of those
// prefixes, which Go's ServeMux prefers over this one, so the fallback cannot swallow a mistyped API
// call and return HTML — and 200 HTML — where a client expected a JSON problem document.
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	if !s.hasUI {
		s.writeUIPlaceholder(w)
		return
	}

	name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if name == "" || name == "." {
		name = "index.html"
	}

	f, err := s.assets.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			http.Error(w, "could not read the application", http.StatusInternalServerError)
			return
		}
		name = "index.html"
		f, err = s.assets.Open(name)
		if err != nil {
			s.writeUIPlaceholder(w)
			return
		}
	}
	defer func() { _ = f.Close() }()

	info, err := f.Stat()
	if err != nil || info.IsDir() {
		s.writeUIPlaceholder(w)
		return
	}
	readSeeker, ok := f.(interface {
		Read([]byte) (int, error)
		Seek(int64, int) (int64, error)
	})
	if !ok {
		http.Error(w, "could not read the application", http.StatusInternalServerError)
		return
	}

	// Hashed asset filenames are immutable, so they can be cached hard; index.html must not be, or a
	// deploy leaves browsers on the previous bundle until they happen to hard-refresh.
	if name == "index.html" {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	http.ServeContent(w, r, name, info.ModTime(), readSeeker)
}

// uiPlaceholder is served when no built application is embedded.
//
// A blank page or a 404 here sends somebody to the issue tracker; a page that says which command to run
// sends them to the terminal. The build is a separate step because the Go toolchain cannot run it, and
// that is worth explaining once rather than being discovered.
const uiPlaceholder = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Farrier</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.6 system-ui, sans-serif; max-width: 46rem; margin: 4rem auto; padding: 0 1.5rem; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .9em; }
  pre { padding: 1rem; border-radius: .5rem; background: rgba(127,127,127,.14); overflow-x: auto; }
  h1 { font-size: 1.5rem; }
</style>
</head>
<body>
<h1>Farrier control plane</h1>
<p>The API is running. The web application is not embedded in this build.</p>
<pre>make web &amp;&amp; make build</pre>
<p>
  <code>make web</code> builds the Angular application and copies it into
  <code>internal/server/assets</code>, where <code>embed.FS</code> picks it up, so that
  <code>farrier-server</code> ships as a single binary with the interface inside it.
</p>
<p>
  In the meantime the API is usable directly. <code>GET /api/v1/hosts</code> returns the fleet and
  <code>GET /api/v1/catalogue</code> returns the complete set of operations this control plane can ask
  a host to perform — both need an <code>Authorization: Bearer</code> header.
</p>
</body>
</html>
`

// writeUIPlaceholder serves the built-in page explaining how to build the application.
func (s *Server) writeUIPlaceholder(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(uiPlaceholder))
}
