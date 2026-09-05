// Command doccheck enforces HostSeal's rule that every type and every function carries a doc comment.
//
// It exists because no off-the-shelf Go linter does this. revive's exported rule stops at exported
// declarations, which is the opposite of what this project needs: the code a reviewer most needs
// context for is the unexported helper whose reason for existing is not visible from its signature.
//
// The tool checks presence and shape only — that a comment exists, and that it starts with the name of
// the thing it documents. Whether the comment explains *why* the declaration exists is left to code
// review, deliberately. That split is stated in CONTRIBUTING.md rather than pretended away, because a
// linter claiming to check for meaning would only teach people to write sentences that satisfy it.
//
// Usage:
//
//	doccheck [flags] [path...]
//
// Paths default to the current directory and are walked recursively. Exit status is 1 if anything is
// undocumented, so it can be a required CI check without a wrapper.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// skippedDirs are directory names never walked.
//
// They are matched by base name rather than by path so that the tool behaves the same whether it is
// invoked from the repository root or from inside a package, which is how people actually run it while
// iterating on one file.
var skippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"testdata":     true,
	"dist":         true,
	".angular":     true,
}

// finding is one undocumented or badly documented declaration.
//
// It carries the position as separate fields rather than a formatted string so that the output can be
// sorted stably by file and line; CI diffs are much easier to read when a new finding appears in
// place instead of shuffling the whole list.
type finding struct {
	file string
	line int
	kind string
	name string
	why  string
}

// String renders the finding in the file:line:message form editors and CI annotators understand.
func (f finding) String() string {
	return fmt.Sprintf("%s:%d: %s %s %s", f.file, f.line, f.kind, f.name, f.why)
}

// config holds the tool's resolved command-line options.
//
// It is a struct passed explicitly rather than a set of package-level flag variables so that the
// checking functions can be exercised from a test without going through flag parsing, which is the
// difference between this tool having tests and not having them.
type config struct {
	// includeTests reports whether _test.go files are checked.
	includeTests bool

	// minWords is the smallest acceptable number of words in a doc comment, or 0 to not check.
	//
	// It is off by default and documented as a blunt instrument. A five-word comment is usually a
	// restatement of the signature, but "usually" is not a standard a required check should enforce,
	// and the honest place for that judgement is review.
	minWords int
}

// main parses flags, walks the given paths, and exits non-zero if anything is undocumented.
func main() {
	cfg := config{}
	flag.BoolVar(&cfg.includeTests, "tests", true, "check _test.go files too")
	flag.IntVar(&cfg.minWords, "min-words", 0, "minimum words in a doc comment; 0 disables the check")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: doccheck [flags] [path...]\n\n"+
			"Reports every type, function and method without a doc comment, exported or not.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	var findings []finding
	for _, root := range paths {
		f, err := checkPath(root, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "doccheck: %v\n", err)
			os.Exit(2)
		}
		findings = append(findings, f...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].file != findings[j].file {
			return findings[i].file < findings[j].file
		}
		return findings[i].line < findings[j].line
	})
	for _, f := range findings {
		fmt.Println(f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\ndoccheck: %d undocumented declaration(s).\n"+
			"HostSeal requires a doc comment on every type and every function, exported or not, saying "+
			"what it does and why it exists. See CONTRIBUTING.md.\n", len(findings))
		os.Exit(1)
	}
}

// checkPath walks one file or directory and returns every finding below it.
func checkPath(root string, cfg config) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if !cfg.includeTests && strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, ferr := checkFile(path, cfg)
		if ferr != nil {
			return ferr
		}
		out = append(out, f...)
		return nil
	})
	return out, err
}

// checkFile parses one Go file and returns the declarations in it that lack an acceptable doc comment.
//
// Generated files are skipped on the conventional first-line marker. Requiring hand-written rationale
// on generated code would mean either editing the generator's output, which the next run discards, or
// adding an exemption comment to every file, and the first exemption is how a rule like this stops
// being taken seriously.
func checkFile(path string, cfg config) ([]finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if isGenerated(file) {
		return nil, nil
	}

	var out []finding
	report := func(pos token.Pos, kind, name string, doc *ast.CommentGroup) {
		p := fset.Position(pos)
		if why := docProblem(doc, name, cfg); why != "" {
			out = append(out, finding{file: path, line: p.Line, kind: kind, name: name, why: why})
		}
	}

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			kind := "function"
			name := d.Name.Name
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind = "method"
				name = receiverName(d.Recv.List[0].Type) + "." + d.Name.Name
			}
			report(d.Pos(), kind, name, d.Doc)

		case *ast.GenDecl:
			if d.Tok != token.TYPE {
				continue
			}
			for _, spec := range d.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				doc := ts.Doc
				if doc == nil && len(d.Specs) == 1 {
					doc = d.Doc
				}
				report(ts.Pos(), "type", ts.Name.Name, doc)

				// Interface methods are declarations in every sense that matters to a reader: they are
				// the contract a caller programs against, and the place where "why does this exist"
				// most often has a non-obvious answer.
				iface, ok := ts.Type.(*ast.InterfaceType)
				if !ok || iface.Methods == nil {
					continue
				}
				for _, m := range iface.Methods.List {
					for _, n := range m.Names {
						report(n.Pos(), "interface method", ts.Name.Name+"."+n.Name, m.Doc)
					}
				}
			}
		}
	}
	return out, nil
}

// docProblem returns a description of what is wrong with a doc comment, or "" if it is acceptable.
//
// The name check — that the comment starts with the identifier — is not pedantry about godoc
// formatting. It is the cheapest available signal that the comment was written for this declaration
// rather than copied from the one above it, which is the most common way a file ends up fully
// commented and completely unhelpful.
func docProblem(doc *ast.CommentGroup, name string, cfg config) string {
	if doc == nil || strings.TrimSpace(doc.Text()) == "" {
		return "has no doc comment"
	}
	text := strings.TrimSpace(doc.Text())

	// For a method the comment conventionally starts with the bare method name, not Type.Method.
	first := name
	if i := strings.LastIndex(name, "."); i >= 0 {
		first = name[i+1:]
	}
	if !strings.HasPrefix(text, first+" ") && !strings.HasPrefix(text, first+"\n") {
		return fmt.Sprintf("doc comment should begin with %q", first)
	}
	if cfg.minWords > 0 && len(strings.Fields(text)) < cfg.minWords {
		return fmt.Sprintf("doc comment is %d words, minimum %d", len(strings.Fields(text)), cfg.minWords)
	}
	return ""
}

// receiverName extracts the type name from a method receiver expression.
//
// It handles the pointer, value and generic forms without reporting an error for anything else,
// because a receiver this function cannot name is still a method that needs a comment, and failing to
// produce a pretty label is not a reason to skip the check.
func receiverName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return receiverName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr:
		return receiverName(v.X)
	case *ast.IndexListExpr:
		return receiverName(v.X)
	default:
		return "?"
	}
}

// isGenerated reports whether a file carries the conventional generated-code marker.
//
// The convention is specified in the Go toolchain's own documentation as a line matching
// "^// Code generated .* DO NOT EDIT\.$" before the package clause.
func isGenerated(file *ast.File) bool {
	for _, cg := range file.Comments {
		if cg.Pos() > file.Package {
			break
		}
		for _, c := range cg.List {
			line := strings.TrimSpace(c.Text)
			if strings.HasPrefix(line, "// Code generated ") && strings.HasSuffix(line, " DO NOT EDIT.") {
				return true
			}
		}
	}
	return false
}
