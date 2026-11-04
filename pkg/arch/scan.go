// Package arch holds the MECHANICALS of the architecture guards.
//
// ⚠️ Why the mechanics live here and the guards do not: the guards are
// tests, and a test cannot be imported by another module. The guards live
// in each repository's own `internal/arch/`; the parts they share — how to
// list Go files, how to read a file's imports, how to turn a file path
// into the import path a reader would write — live HERE, in one place.
//
// The alternative was three copies of the same helpers. Copies drift: this
// repository has been bitten by exactly that twice (two copies of the
// redaction word list, which ended up disagreeing on 14 words; two copies
// of the audit-trail check, which reported different things). The rule here
// is the one the repository already wrote down: **a shared DEFINITION used
// by one consumer is still shared; a whole PACKAGE that only one consumer
// reaches is that consumer's private code wearing a shared name.**
//
// This package is deliberately dependency-free (go/parser, go/ast and the
// standard library) so that the guards can use it without pulling anything
// in.
package arch

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GoFiles lists the Go files under a directory.
//
// ⚠️ `.git` is not ours, and `legacy/` is a separate repository kept for
// reference (an early Python-era implementation) — neither is part of any
// build, so neither is scanned.
func GoFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "legacy" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".go") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ImportsOf reads the import paths of one file.
func ImportsOf(path string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(f.Imports))
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// IdlFiles lists the thrift files under a directory.
func IdlFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "legacy" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(path, ".thrift") {
			out = append(out, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PackagesNamed finds the directories under root whose Go package is called
// name.
func PackagesNamed(root, name string) ([]string, error) {
	seen := map[string]bool{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "legacy" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		dir := filepath.Dir(path)
		if filepath.Base(dir) != name {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
		if err != nil || f.Name.Name != name {
			return nil
		}
		seen[dir] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	return out, nil
}

// PackageNameOf returns the package clause of a Go file.
//
// ⚠️ It reads the clause, not the directory name: a directory and the
// package inside it are allowed to differ (that happens on purpose in this
// repository: a directory is renamed and the package keeps its old name
// until the rename is finished). A guard that asked the directory would
// answer a different question than the one it means to ask.
func PackageNameOf(path string) (string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.PackageClauseOnly)
	if err != nil {
		return "", err
	}
	return f.Name.Name, nil
}

// PackageOf returns the package name of an import path — the last element,
// with the major-version suffix removed (".../model/jms/v2" → "jms").
func PackageOf(importPath string) string {
	p := importPath
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	// A major-version suffix is part of the path, not of the package name.
	if len(p) > 1 && p[0] == 'v' {
		if _, err := strconv.Atoi(p[1:]); err == nil {
			if i := strings.LastIndex(importPath, "/"); i >= 0 {
				p = importPath[i+1:]
			}
		}
	}
	return p
}

// ImportPathOf turns a file's location into the import path a reader would
// write to reach it.
//
// ⚠️ The boundaries are stated in import paths, so they have to be compared
// in import paths — a file path and an import path are different languages.
// The module path is a parameter because the module path is per-repository.
func ImportPathOf(modulePath, root, path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return path
	}
	r, err := filepath.Rel(root, abs)
	if err != nil {
		return path
	}
	r = strings.TrimSuffix(r, ".go")
	return modulePath + "/" + filepath.ToSlash(r)
}

// RepoRoot returns the repository root of a guard directory.
//
// ⚠️ The guards live in `<repo>/internal/arch/`, so the root is two levels
// up. It is derived from the caller's own path rather than from the working
// directory, so it does not depend on where the test was started from.
func RepoRoot(dir string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Dir(filepath.Dir(wd)), nil
}

// Relative renders a path relative to a root, for readable output.
func Relative(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return filepath.ToSlash(r)
}

// IsImportOf reports whether an import path belongs to the given module.
func IsImportOf(importPath, modulePath string) bool {
	return importPath == modulePath || strings.HasPrefix(importPath, modulePath+"/")
}

// ASTFiles parses the given files and returns their syntax trees.
//
// It is the shared way to look INSIDE a file: the guards have to read what
// the code says, not what a comment claims it says (this repository has
// been bitten by a comment that asserted something the measurement
// contradicted).
func ASTFiles(paths []string) (map[string]*ast.File, error) {
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		out[p] = f
	}
	return out, nil
}
