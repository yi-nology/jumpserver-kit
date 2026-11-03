package jmsapi

// The guard for the protocol boundary.
//
// The layer above the protocol must not speak HTTP: it asks for a RESOURCE,
// and the gateway turns that into a call. Two things break that rule, and
// both are easy to introduce by accident:
//
//   - a string literal that spells out an API path;
//   - a call to the raw transport (Do, ListAll) instead of the gateway.
//
// Neither is visible to the compiler. A wrong path is a 404 at runtime, and a
// raw call is perfectly legal Go that happens to leak the transport into the
// tool layer. So the rule is checked mechanically instead: the server's own
// test calls ProtocolViolations over its tool directory, and the build fails
// when the boundary starts eroding.
//
// The check is deliberately narrow. It looks at string LITERALS (so a path
// mentioned in a comment or in a tool description is not a violation) and at
// calls whose receiver is not an imported package (so a call into another
// package is not a violation either).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// apiPath is the shape of a bastion endpoint: a lowercase path with at least
// two segments.
var apiPath = regexp.MustCompile(`^/[a-z][a-z0-9\-]*/[a-z0-9\-/]*$`)

// rawCalls are the transport methods a layer above the protocol must not
// call. They take or return a path, which is exactly what the gateway
// exists to hide.
var rawCalls = map[string]bool{
	"Do":           true,
	"ListAll":      true,
	"ListAllQuery": true,
	"ListIntoPath": true,
}

// ProtocolViolations scans the Go files of a directory and reports the places
// where the protocol boundary was broken.
//
// It returns one line per violation, ready to be printed as a test failure.
func ProtocolViolations(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		v, err := violationsIn(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, v...)
	}
	return out, nil
}

func violationsIn(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// The names the file imports are not receivers: a call into another
	// package is not a leak of the transport.
	imported := map[string]bool{}
	for _, imp := range f.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		imported[name] = true
	}

	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind != token.STRING {
				return true
			}
			text := strings.Trim(v.Value, `"`)
			if apiPath.MatchString(text) {
				out = append(out, fmt.Sprintf("%s:%d: spells out the API path %q; "+
					"ask for a resource instead", filepath.Base(path),
					fset.Position(v.Pos()).Line, text))
			}
		case *ast.CallExpr:
			sel, ok := v.Fun.(*ast.SelectorExpr)
			if !ok || !rawCalls[sel.Sel.Name] {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || imported[recv.Name] {
				return true
			}
			out = append(out, fmt.Sprintf("%s:%d: calls the raw transport %s.%s; "+
				"use the gateway instead", filepath.Base(path),
				fset.Position(v.Pos()).Line, recv.Name, sel.Sel.Name))
		}
		return true
	})
	return out, nil
}
