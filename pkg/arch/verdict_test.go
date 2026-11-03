package arch

// 守卫的自检：它自己看得见那些字段名吗？
//
// ⚠️ 这一份自检是从原仓 internal/arch/verdict_test.go 搬过来的，**逐字**。
// 它守的是那条判定的**前提**：守卫靠**按名字**找字段（反射按 Go 名字、
// 线上按 JSON 名字）。如果解析器看不见这些名字，底下那些规则一条都
// 匹配不到，守卫对**任何**契约都放行，而且放行得悄无声息。
//
// 搬过来之后它必须**仍然看得见**——不是恒绿，是真的读出那六个名字。
import (
	"os"
	"path/filepath"
	"testing"
)

// TestTheGuardActuallySeesTheFieldNames keeps the guard itself honest.
//
// This file's first version read the JSON name by cutting the raw tag text,
// and the cut took "`"dry_run,omitempty"`" for the name. Every lookup for
// "`"dry_run"`" then missed — the rules below never matched anything, the
// guard passed on ANY contract, and it did so silently. A mutation test
// caught it (changing a contract field from *bool to bool did not make the
// guard red); nothing else would have.
//
// So the parser gets its own test: it must see the field names the way the
// reflection and the JSON encoder do — the name, without the options.
func TestTheGuardActuallySeesTheFieldNames(t *testing.T) {
	src := `package sample

type Answer struct {
	DryRun       *bool   ` + "`" + `json:"dry_run,omitempty"` + "`" + `
	Blocked      *string ` + "`" + `json:"blocked,omitempty"` + "`" + `
	WouldExecute *bool   ` + "`" + `json:"would_execute,omitempty"` + "`" + `
}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "sample.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write sample: %v", err)
	}
	types := contractTypes(t, path)
	if len(types) != 1 {
		t.Fatalf("parsed %d struct types, want 1", len(types))
	}
	ct := types[0]
	for _, c := range []struct{ name, typ string }{
		{"DryRun", "*bool"},
		{"Blocked", "*string"},
		{"WouldExecute", "*bool"},
	} {
		typ, ok := ct.goFields[c.name]
		if !ok {
			t.Errorf("the guard does not see the Go field %q; it sees %v", c.name, ct.goFields)
			continue
		}
		if typ != c.typ {
			t.Errorf("Go field %q has type %q, want %q", c.name, typ, c.typ)
		}
	}
	for _, c := range []struct{ name, typ string }{
		{"dry_run", "*bool"},
		{"blocked", "*string"},
		{"would_execute", "*bool"},
	} {
		typ, ok := ct.jsonFields[c.name]
		if !ok {
			t.Errorf("the guard does not see the JSON field %q; it sees %v", c.name, ct.jsonFields)
			continue
		}
		if typ != c.typ {
			t.Errorf("JSON field %q has type %q, want %q", c.name, typ, c.typ)
		}
	}
}
