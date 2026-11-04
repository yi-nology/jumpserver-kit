package contractscan

// The shared guard body: the part of 「契约类型写了没人产出 = 契约不存在」
// that is the SAME wherever the guard stands.
//
// Three guards stand on this body (the two per-plane models and the shared
// vocabulary). They used to carry a copy each — and copies drift: one of
// them had already grown a doubled comment sentence, and the "generated
// file" vs "generated model" wording had parted ways. What actually
// differs between the guards is the JUDGMENT, and that stays at each guard
// — as the Scope it passes in.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Scope is the judgment a guard brings:
//
//   - what its world is (where the producers live, and the one base name
//     the scan root must have);
//   - what is NOT a producer (the generated model is not a producer of
//     itself);
//   - whether a thrift enum counts as a declared type.
//
// Everything else about the three guards is the same, and lives here.
type Scope struct {
	// World names what the scan root IS, for the failure messages: "the
	// execution plane", "the management plane", "the repository".
	World string

	// RootBase is the ONE base name the scan root's directory must have.
	//
	// ⚠️ The root is asserted because one level too high would scan the
	// wrong tree: slow, and it would count somebody else's package as a
	// producer (a contract that only the OTHER plane produces would look
	// produced here too — the guard would pass for the wrong reason).
	//
	// ⚠️ 目录名只是**兜底**的认法：它认的是「这��目录该叫什么」，
	// 而 CI 的 checkout 目录名是 CI 决定的 ⇒ 认树认 Module（module path）。
	RootBase string

	// Module is the module path the scan root must declare in its go.mod.
	//
	// ⚠️ 它**优先于** RootBase：module path 才是树的身份 —— 仓被 checkout 到
	// 什么目录名、放在哪个盘符下，它都是同一个 module。
	//
	// ⚠️ 它只对**module 根**成立（根目录里有 go.mod）。服务仓的那份契约守卫
	// 的根是 `biz` 这样的**子目录**（契约模型在 `biz/model/<pkg>/`）
	// ⇒ 那里用 RootBase。
	Module string

	// Roots are the EXTRA trees to scan, on top of this repository's own
	// root (which is ../.. and is checked against RootBase).
	//
	// ⚠️ It exists because the world changed: the shared vocabulary's
	// producers live in the two SERVICE repositories, not in the one that
	// declares it ⇒ scanning only the declaring tree says "nobody produces
	// this" for every shared type, and the guard goes red for a reason
	// that has nothing to do with the contracts.
	//
	// ⚠️ An empty Roots keeps the OLD behaviour exactly: one tree, the one
	// the guard stands in. The two per-plane guards are unchanged.
	Roots []Root

	// NotAProducer says which files never produce a contract type. The
	// default (a nil here) is IsGenerated: the generated files reference
	// each other (a domain type carries another domain's type in its
	// fields), and that is not a producer.
	//
	// ⚠️ The skip is by PATH, not by name: the handler package has a file
	// called exec.go too, and skipping it by name would hide the
	// references it makes.
	NotAProducer func(path string) bool

	// EnumsDeclared says whether a thrift enum counts as a declared
	// type. The per-plane model guards say NO ("nobody produces the
	// enum" is not the failure they are about); the shared vocabulary's
	// guard says YES — its first cross-layer enum (Delivery, "did the
	// command reach the machine") was declared in the IDL, and nothing
	// would have gone red if nobody had ever produced it. A type that
	// nobody builds is a promise nobody keeps, and an enum is a type.
	EnumsDeclared bool
}

// Root is one tree to scan: where it is, what its directory must be
// called, and who it is (for the failure messages).
type Root struct {
	// Path is the directory to scan.
	Path string
	// Base is the name that directory MUST have. It is asserted because
	// one level too high would scan the wrong tree — and a contract that
	// only another tree produces would look produced here too, so the
	// guard would pass for the wrong reason.
	//
	// ⚠️ 兜底认法；优先用 Module（module path）—— 目录名是 CI 决定的。
	Base string
	// Module is the module path that directory must declare in its go.mod.
	// It takes precedence over Base.
	Module string
	// World names the tree in the failure messages.
	World string
}

// CheckProduced fails t when the generated model declares a contract type
// that no tool produces.
//
// A type in the IDL that no tool produces is a comment, not a contract: it
// promises a shape that nothing answers with, and the next person to read
// the IDL believes the promise. A contract nobody produces is how a tool's
// output and its declared schema drift apart without anybody noticing.
//
// The check is mechanical on purpose: it is the kind of thing that has to
// be true at every commit, not something a reviewer should have to
// remember.
//
// ⚠️ "Produced" is not "named in a tool". A row type that appears only as
// the element type of another type's field IS produced — the tool builds
// that field's rows, and the schema checks them. So the check follows the
// references transitively (Produced), and a type nobody references at all
// is the one that fires.
func CheckProduced(t *testing.T, scope Scope) {
	t.Helper()
	declared, fields := scope.declared(t)
	if len(declared) == 0 {
		t.Fatal("no contract types found; the generated model moved?")
	}
	roots := scope.referencedOutside(t, declared)
	if len(roots) == 0 {
		t.Fatal("no contract type is referenced outside the generated model; " +
			"the tools are not producing the contract at all")
	}
	produced := Produced(fields, roots)
	for _, name := range declared {
		if !produced[name] {
			t.Errorf("contract type %s is declared but never produced: "+
				"no tool builds one, so the IDL promises a shape nobody answers with", name)
		}
	}
}

// Produced closes over the references: a type used as a field of a produced
// type is produced too. roots are the types a tool builds directly.
func Produced(fields map[string][]string, roots []string) map[string]bool {
	produced := map[string]bool{}
	queue := make([]string, 0, len(roots))
	for _, n := range roots {
		produced[n] = true
		queue = append(queue, n)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, dep := range fields[n] {
			if !produced[dep] {
				produced[dep] = true
				queue = append(queue, dep)
			}
		}
	}
	return produced
}

// declared reads the type names out of the generated model, and the types
// each one mentions in its fields.
func (s Scope) declared(t *testing.T) ([]string, map[string][]string) {
	t.Helper()
	types, err := Declared(generatedFiles(t))
	if err != nil {
		t.Fatalf("read the generated model: %v", err)
	}
	var names []string
	fields := map[string][]string{}
	for _, ty := range types {
		// Structs only unless the guard says an enum is a declared type
		// too (Scope.EnumsDeclared, which carries the why).
		if !s.EnumsDeclared && !ty.Struct {
			continue
		}
		names = append(names, ty.Name)
		fields[ty.Name] = ty.Refs
	}
	return names, fields
}

// generatedFiles is where the types are DECLARED. The producers are
// everywhere else. (The model is split into several generated files — one
// per IDL domain — so "the generated file" is a SET: found by thriftgo's
// header, not by a name list that would rot the moment a domain file is
// added.)
func generatedFiles(t *testing.T) []string {
	t.Helper()
	files, err := GeneratedFiles(".")
	if err != nil {
		t.Fatalf("read the model directory: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("no thriftgo output in the model directory; the generated model moved?")
	}
	return files
}

// referencedOutside finds the contract types mentioned anywhere but in the
// generated model — the tools and the composed outputs.
//
// ⚠️ It walks EVERY scan root and merges the answers: a type produced in ANY
// of them is produced. The per-plane guards have exactly one root (their
// own repository), which is the behaviour they always had.
func (s Scope) referencedOutside(t *testing.T, declared []string) []string {
	t.Helper()
	skip := s.NotAProducer
	if skip == nil {
		skip = IsGenerated
	}
	refs := map[string][]string{}
	for _, root := range s.scanRoots(t) {
		found, err := References(root.Path, skip, declared)
		if err != nil {
			t.Fatalf("walk %s: %v", root.World, err)
		}
		for w, files := range found {
			refs[w] = append(refs[w], files...)
		}
	}
	var out []string
	for _, n := range declared {
		if len(refs[n]) > 0 {
			out = append(out, n)
		}
	}
	return out
}

// scanRoots returns the trees to scan: this repository's own root (checked
// against RootBase / Module) plus the extra ones.
//
// ⚠️ The own root is checked because one level too high would scan the
// wrong tree: slow, and it would count somebody else's package as a
// producer (a contract that only the OTHER plane produces would look
// produced here too — the guard would pass for the wrong reason).
func (s Scope) scanRoots(t *testing.T) []Root {
	t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs the scan root: %v", err)
	}
	assertTree(t, root, s.RootBase, s.Module, s.World)
	out := []Root{{Path: root, Base: s.RootBase, Module: s.Module, World: s.World}}
	for _, extra := range s.Roots {
		p, err := filepath.Abs(extra.Path)
		if err != nil {
			t.Fatalf("abs the scan root %s: %v", extra.Path, err)
		}
		assertTree(t, p, extra.Base, extra.Module, extra.World)
		out = append(out, Root{Path: p, Base: extra.Base, Module: extra.Module, World: extra.World})
	}
	return out
}

// assertTree says which tree this directory is — and refuses it if it isn't.
//
// ⚠️ **目录名不是树的身份**：CI 把仓 checkout 到什么目录名是 CI 决定的
// （GitHub Actions 里有同名仓，也有把 kit checkout 成 `kit/` 的），
// 而目录名一变守卫就报「这个目录搬走了」—— 一次与契约毫无关系的红。
// ⇒ 认树认 **module path**（go.mod 里那一行）：那是树的身份，搬到哪里都一样。
//
// ⚠️ 但**服务仓的守卫根不是 module 根**（它是 `biz` 这种子目录），
// 那里没有 go.mod ⇒ 那种树仍然按目录基名认（RootBase）。
func assertTree(t *testing.T, path, base, module, world string) {
	t.Helper()
	if module != "" {
		got := moduleOf(t, path)
		if got != module {
			t.Fatalf("the scan root is %s, but its go.mod declares module %s, not %s: "+
				"this is the wrong tree, and the guard would be looking at the wrong world (%s)",
				path, got, module, world)
		}
		return
	}
	if base == "" {
		return
	}
	if got := filepath.Base(path); got != base {
		t.Fatalf("the scan root is %s, not %s: this directory "+
			"moved, and the guard would be looking at the wrong tree", path, base)
	}
}

// moduleOf 读一个目录的 go.mod 里声明的 module path。
func moduleOf(t *testing.T, dir string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Join(dir, "go.mod"), err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "module" {
			return fields[1]
		}
	}
	t.Fatalf("%s declares no module path: the scan root is not a module root", dir)
	return ""
}
