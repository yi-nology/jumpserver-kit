package arch

// The self-test of the doc-table guard: both directions, the conditional
// exception, the prose-outside-markers rule, and the no-markers case.
// Fixtures in t.TempDir(), never in the tree — the guard reads the working
// tree, so a fixture in the tree would be read as a real doc (and would,
// correctly, fail).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeMd(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestToolTableViolations(t *testing.T) {
	const block = "<!-- jms-tools -->\njmsx_exec / jmsx_put_dir\n<!-- /jms-tools -->"
	cases := []struct {
		name    string
		docs    string
		reg     []string
		cond    []string
		wantErr []string // substrings that must appear in violations
	}{
		{
			name: "consistent",
			docs: "# x\n\n" + block + "\n",
			reg:  []string{"jmsx_exec", "jmsx_put_dir"},
		},
		{
			name:    "registered tool not in docs",
			docs:    "# x\n\n" + block + "\n",
			reg:     []string{"jmsx_exec", "jmsx_put_dir", "jmsx_run"},
			wantErr: []string{"jmsx_run"},
		},
		{
			name:    "docs name a tool nothing registers",
			docs:    "# x\n\n<!-- jms-tools -->\njmsx_exec jmsx_ghost\n<!-- /jms-tools -->\n",
			reg:     []string{"jmsx_exec"},
			wantErr: []string{"jmsx_ghost"},
		},
		{
			name: "conditional tools may live only in the docs",
			docs: "# x\n\n<!-- jms-tools -->\njmsx_exec jmsx_inventory\n<!-- /jms-tools -->\n",
			reg:  []string{"jmsx_exec"},
			cond: []string{"jmsx_inventory"},
		},
		{
			name: "prose outside markers is never scanned",
			docs: "# x\n\njmsx_ghost 在散文里出现不算数。\n\n" + block + "\n",
			reg:  []string{"jmsx_exec", "jmsx_put_dir"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeMd(t, root, "README.md", c.docs)
			errs := toolTableViolations(root, c.reg, c.cond)
			for _, want := range c.wantErr {
				found := false
				for _, e := range errs {
					if strings.Contains(e, want) {
						found = true
					}
				}
				if !found {
					t.Errorf("no violation mentions %q: %v", want, errs)
				}
			}
			if len(c.wantErr) == 0 && len(errs) != 0 {
				t.Errorf("no violation wanted, got: %v", errs)
			}
		})
	}
}

func TestToolTableViolationsNoMarkers(t *testing.T) {
	root := t.TempDir()
	writeMd(t, root, "README.md", "# no markers here\n")
	if errs := toolTableViolations(root, []string{"jmsx_exec"}, nil); len(errs) == 0 {
		t.Error("a tree with no markers must fail — an unchecked guard is a fake guard")
	}
}

// The scanner's vocabulary is the two fleet prefixes — pinned both ways:
// a third prefix is NOT a tool name (the guard must not claim things it
// does not track), and the two real prefixes must never stop matching.
func TestToolNameRegexVocabulary(t *testing.T) {
	yes := []string{"jmsx_exec", "jms_user_groups_list", "jms_file_transfers"}
	no := []string{"other_tool", "jms", "jmsx", "jmsx_"} // bare prefixes are not names
	for _, n := range yes {
		if !toolNameRE.MatchString(n) {
			t.Errorf("toolNameRE must match %q", n)
		}
	}
	for _, n := range no {
		if toolNameRE.MatchString(n) {
			t.Errorf("toolNameRE must NOT match %q — the vocabulary is jms_/jmsx_ only", n)
		}
	}
}
