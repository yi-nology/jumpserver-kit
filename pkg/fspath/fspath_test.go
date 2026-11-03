package fspath

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory to expand to")
	}
	cases := []struct{ in, want string }{
		{"", ""},
		{"/etc/passwd", "/etc/passwd"},
		{"relative/path", "relative/path"},
		{"~", home},
		{"~/audit", filepath.Join(home, "audit")},
	}
	for _, c := range cases {
		if got := ExpandHome(c.in); got != c.want {
			t.Errorf("ExpandHome(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
