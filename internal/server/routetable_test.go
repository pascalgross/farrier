package server_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"slices"
	"sort"
	"strings"
	"testing"
)

// requireWrappers are the middleware methods that establish who a caller is.
//
// Six, and the list is here rather than derived because deriving it is the mistake: a test that
// discovered the wrappers by name pattern would accept a `requireNothing` somebody wrote in a hurry.
var requireWrappers = []string{
	"requireAgent",
	"requireOperator",
	"requireIdentity",
	"requirePlatform",
	"requireAccount",
	"requireShare",
}

// unauthenticatedRoutes are the routes that answer without a credential, and why each may.
//
// This is the expected-set literal, in the same spirit as the intent catalogue's: a route that answers
// anybody is a decision, and adding one here is the moment somebody has to write the sentence that
// justifies it. The sentences are not decoration — they are what a reviewer reads instead of
// reconstructing the argument from the handler.
//
// The keys are the pattern expressions as they are written in routes(), rather than the strings they
// evaluate to, because half of them are constants and a test that resolved constants would be a small
// interpreter nobody wants to maintain. Spelling them as the source spells them also means the failure
// message can name something a reader can find with a search.
var unauthenticatedRoutes = map[string]string{
	"protocol.PathEnroll": "enrolment is where an agent's credential comes from, so it cannot require " +
		"one; the token in the body is the credential and the handler rate limits it",
	"CACertificatePath": "a CA certificate is handed to every enrolling agent before that agent has any " +
		"credential at all, so it is already a public document",
	`"/api/v1/session"`: "signing in is where an operator's credential comes from, and signing out has " +
		"to work for a session that has already stopped authenticating",
	`"/api/v1/wallboard/public/unlock"`: "the unlock is where a screen's credential comes from; the key " +
		"in the Authorization header is what it is proving a passphrase against, and the handler rate " +
		"limits it per link and refuses everything with one answer",
}

// muxCatchAlls are the patterns registered directly on the mux rather than through route().
//
// They are the fallbacks rather than routes: two that turn a mistyped API call into a JSON problem
// document, one that serves the application, and the health check, which predates route() and answers
// no path the miss handler would reach. Everything else must go through route(), or the method table
// that produces 405s and the Allow header is left behind by the edit that added it.
var muxCatchAlls = []string{
	`"GET /healthz"`,
	`"/api/"`,
	`"/agent/"`,
	`"/"`,
}

// TestEveryRouteDeclaresTheCredentialItRequires reads routes() and refuses a route that names no
// credential.
//
// Nothing else in this package checks this. The middleware is applied by hand, one call per route, so a
// route registered with the wrong wrapper — or with none — compiles, serves, and looks exactly like its
// neighbours in a diff. That was tolerable while every route under /api/v1 but two was behind
// requireOperator; it stopped being tolerable when a screen with no account started reaching one.
//
// It walks the syntax tree rather than making requests, for the reason internal/intent's source
// guarantee does: a table of requests proves things about the routes somebody remembered to add to the
// table, and this has to prove something about the ones they did not.
func TestEveryRouteDeclaresTheCredentialItRequires(t *testing.T) {
	body := routesFunction(t)

	seen := map[string]bool{}
	var problems []string

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "route" || len(call.Args) != 3 {
			return true
		}

		pattern := render(t, call.Args[1])
		seen[pattern] = true
		if wrapper, wrapped := requireWrapper(call.Args[2]); wrapped {
			if !slices.Contains(requireWrappers, wrapper) {
				problems = append(problems, pattern+" is wrapped in "+wrapper+
					", which is not one of this server's credential checks")
			}
			return true
		}
		if _, expected := unauthenticatedRoutes[pattern]; expected {
			return true
		}
		problems = append(problems, "route "+pattern+" is registered with no require* wrapper. "+
			"Pick one, or add the pattern to `unauthenticatedRoutes` in this file together with the "+
			"sentence that justifies it — a route that answers without a credential is a decision, "+
			"not a default")
		return true
	})

	// The other half: a route registered straight on the mux never reaches the check above, so without
	// this the whole test is bypassable by writing `s.mux.Handle` instead of `s.route`.
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc" {
			return true
		}
		receiver, ok := selector.X.(*ast.SelectorExpr)
		if !ok || receiver.Sel.Name != "mux" || len(call.Args) == 0 {
			return true
		}
		pattern := render(t, call.Args[0])
		if slices.Contains(muxCatchAlls, pattern) {
			return true
		}
		problems = append(problems, "pattern "+pattern+" is registered directly on the mux. Register "+
			"it with s.route so that it acquires a credential check and a method table, or add it to "+
			"`muxCatchAlls` in this file if it really is a fallback")
		return true
	})

	// An entry that no longer matches a route is worth failing on too: an unauthenticated route that
	// was later put behind a credential should not leave its excuse behind for the next one to inherit.
	for pattern := range unauthenticatedRoutes {
		if !seen[pattern] {
			problems = append(problems, "`unauthenticatedRoutes` names "+pattern+
				", which routes() no longer registers; remove the entry rather than leaving a "+
				"justification for a route that does not exist")
		}
	}

	sort.Strings(problems)
	for _, problem := range problems {
		t.Error(problem)
	}
}

// TestTheUnauthenticatedRoutesAreTheOnesTheDocumentationNames pins the count as well as the set.
//
// The map above fails when a route is added without an entry, and this fails when an entry is added
// without anybody noticing the total moved. The number is small enough to be memorable and that is the
// point: "this control plane answers four requests with no credential" is a sentence somebody can hold,
// and a fifth should require deciding to change it.
func TestTheUnauthenticatedRoutesAreTheOnesTheDocumentationNames(t *testing.T) {
	const want = 4
	if len(unauthenticatedRoutes) != want {
		t.Fatalf("this server has %d unauthenticated routes; it had %d. If that is deliberate, change "+
			"the number here and say why in the commit message",
			len(unauthenticatedRoutes), want)
	}
	for pattern, why := range unauthenticatedRoutes {
		if len(why) < 40 {
			t.Errorf("%s is justified by %q, which is not a reason", pattern, why)
		}
	}
}

// routesFunction parses server.go and returns the body of routes().
//
// It reads the file from disk rather than using go/packages, because the only thing being asked about
// is the shape of one function's source and the standard library parser answers that with no build
// step and no module resolution.
func routesFunction(t *testing.T) *ast.BlockStmt {
	t.Helper()

	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, "server.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing server.go: %v", err)
	}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "routes" || fn.Recv == nil {
			continue
		}
		return fn.Body
	}
	t.Fatal("server.go has no routes() method; this test is looking in the wrong place")
	return nil
}

// requireWrapper reports the middleware method a handler expression is wrapped in, if it is.
//
// It matches `s.requireX(...)` and nothing else. A handler built some other way — a bare
// http.HandlerFunc, a helper that returns one — is deliberately not recognised, because the whole
// question is which credential the route requires and only these six answer it.
func requireWrapper(handler ast.Expr) (string, bool) {
	call, ok := handler.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "require") {
		return "", false
	}
	return selector.Sel.Name, true
}

// render prints one expression back as the source spells it, so a failure names something searchable.
func render(t *testing.T, expr ast.Expr) string {
	t.Helper()

	var out bytes.Buffer
	if err := printer.Fprint(&out, token.NewFileSet(), expr); err != nil {
		t.Fatalf("rendering an expression from server.go: %v", err)
	}
	return out.String()
}
