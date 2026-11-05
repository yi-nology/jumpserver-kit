package arch

// The self-test of the IDL vocabulary-naming guard: both layouts, plus the
// ways each can lie.
//
// ⚠️ The fixtures live in t.TempDir(), NEVER in this repository: the guard
// reads the working tree, so a fixture that sat in the tree would be read
// by the guard as a real violation — and the guard would (correctly) fail
// on its own test data.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeThrift writes one fixture thrift file.
func writeThrift(t *testing.T, root, rel, ns string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(p), err)
	}
	body := "namespace go " + ns + "\n\n// fixture\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// writeGoPkg writes one fixture Go package.
func writeGoPkg(t *testing.T, root, rel, name string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(p), err)
	}
	body := "package " + name + "\n\n// fixture\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

// hasErr reports whether one violation line mentions want.
func hasErr(errs []string, want string) bool {
	for _, e := range errs {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}

func TestContractVocabularyNaming(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T, root string)
		want    []string // each must appear in some violation line
		wantLen int      // exact violation count when > 0
	}{
		{
			name: "nested layout, consistent",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/jmsexec/run.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},
		},
		{
			name: "flat layout, consistent",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},
		},
		{
			name: "flat layout, missing entry file",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/main.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},
			want: []string{"no", "entry", "jmsexec.thrift"},
		},
		{
			name: "flat layout, two namespaces in one directory",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "otherpkg")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
				writeGoPkg(t, root, "biz/model/otherpkg/x.go", "otherpkg")
			},
			want: []string{"speaks ONE package"},
		},
		{
			name: "flat layout, a file declares no namespace",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},
			want: []string{"declares no `namespace go`"},
		},
		{
			// The historical accident the guard was written for:
			// idl/exec/*..thrift declaring package jmsexec. The directory
			// no longer names the package, so the catch moves — the entry
			// file must now be named after the DECLARED package, and
			// exec.thrift is not.
			name: "nested drift: the directory and the namespace disagree",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/exec/exec.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},
			want: []string{"namespace go jmsexec", "package is exec"},
		},
		{
			name: "the contract is declared but the package does not exist",
			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "jmsexec")
			},
			want: []string{"nowhere to be found"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.build(t, root)
			errs := contractVocabularyNaming(t, root, "example.com/fixture")
			if len(c.want) == 0 {
				if len(errs) != 0 {
					t.Fatalf("no violation wanted, got: %v", errs)
				}
				return
			}
			if len(errs) == 0 {
				t.Fatalf("violations wanted (%v), got none", c.want)
			}
			for _, w := range c.want {
				if !hasErr(errs, w) {
					t.Errorf("no violation mentions %q: %v", w, errs)
				}
			}
		})
	}
}
