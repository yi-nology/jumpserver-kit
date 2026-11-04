package arch

// 从原仓 internal/arch/arch_test.go 搬来的守卫体。
//
// ⚠️ 判据与失败文案逐字保留：原文案是仓里踩坑沉淀出来的教训，
// 改写等于丢教训。路径按新仓布局调整（三个仓的内部布局不一样了），
// 但「这句话说的是什么事」不许变。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// CheckNoBareGoroutines 保持 oekit 矩阵里的那条防 panic 规则。
//
// 一个裸 `go func()` 没有 recover：里面的 panic 会把整个进程带走。
// 对一个 MCP 服务来说，那意味着会话连同**两个服务**一起没了，而留痕的
// 写盘进程也在里面。concurrency/async 是矩阵给的答案——它 recover、
// 记栈，然后让剩下的活继续。
func CheckNoBareGoroutines(t *testing.T, root string) {
	t.Helper()
	root = absRoot(t, root)
	for _, f := range goFilesOrFatal(t, root) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		for _, line := range bareGoroutines(t, f) {
			t.Errorf("%s:%d: a bare goroutine: %s\n"+
				"  a panic in it would take the whole server down; "+
				"use concurrency/async (GoSafe / GoSafeLabeled / GoSafeWithErr)",
				relToInternal(root, f), line, "go ...")
		}
	}
}

// bareGoroutines 找出一个文件里没有 recover 就起的 goroutine。
func bareGoroutines(t *testing.T, path string) []int {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []int
	ast.Inspect(f, func(n ast.Node) bool {
		stmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		switch stmt.Call.Fun.(type) {
		case *ast.FuncLit, *ast.Ident:
			out = append(out, fset.Position(stmt.Pos()).Line)
		}
		return true
	})
	return out
}

// CheckBinariesAreOutermost 让入口层不要变成一个别人依赖的库。
//
// ⚠️ 原仓的这条守卫是「cmd/ 谁都不许 import」。拆仓之后它按 module path
// 说：某个仓的 cmd/ 只有它自己许 import。
//
// ⚠️ **入口层搬到仓根之后**（main.go / server.go / init.go / workers.go /
// shutdown.go 是仓根那个 package main，子命令在 cmd/ 下），「最外层」
// 变成**两处**：仓根本身与 cmd/。⇒ 判据跟着变成：这两处只许向里叫，
// 谁都不许 import 它们。
//
// ⚠️ 为什么仓根本身也要算进去：仓根那个 package 是 `main`，Go 本来就不许
// import 它 ⇒ 那一条在编译器那里已经成立。但**写出来**是有用的：它把
// 「最外层是哪几处」这件事说成一句话，而不是让读者从两处代码里推。
// 而 cmd/ 下的子命令包是**普通的包**（入口层 import 它们），它们**能**
// 被 import ⇒ 那一条编译器不管 ⇒ 它才是这条守卫真正的牙齿。
//
// ⚠️ kit 没有 cmd/、仓根也没有 package main（kit 是库）⇒ 这条守卫在 kit
// 上是空的。kit 那边的「不许有入口层」是 kit 自己的判据，留在 kit 的守卫里，
// 不在这里编。
func CheckBinariesAreOutermost(t *testing.T, root, modulePath string) {
	t.Helper()
	root = absRoot(t, root)
	tree := Tree{Root: root, ModulePath: modulePath}
	cmdPrefix := modulePath + "/cmd/"
	for _, f := range goFilesOrFatal(t, root) {
		// The entry layer may call inward.
		self := tree.PackagePath(f)
		if self == modulePath || strings.HasPrefix(self, cmdPrefix) {
			continue
		}
		for _, imp := range importsOrFatal(t, f) {
			if imp == modulePath || strings.HasPrefix(imp, cmdPrefix) {
				t.Errorf("%s imports a binary entry point (%s): "+
					"the entry layer (the repository root and cmd/) is the outermost layer; "+
					"it calls inward, never the other way",
					relToInternal(root, f), imp)
			}
		}
	}
}

// CheckTheEntryLayerIsOneBinaryAtTheRoot 让入口层是**仓根那一个** package main。
//
// ⚠️ 入口层搬到仓根之后，这一层有两件事要钉住：
//
//  1. **二进制只有一个**，在**仓根**（`go install …@latest` 装出来的就是它）；
//  2. `cmd/` 下**没有** package main —— 那些是**子命令**（入口层 import
//     的普通包），不是各自的二进制。
//
// ⚠️ 为什么第 2 条要写出来：编译器会挡住「cmd/ 下的 main 被仓根 import」
// （main 包不可 import），但**挡不住**「cmd/ 下多了一个二进制」——
// `go build ./...` 会把它一起编出来，于是仓里就有了第二个入口，
// 而发版脚本只发一个 ⇒ 那个二进制永远没人拿到，却已经躺在源码树里。
//
// ⚠️ 「仓根那个 package main」是**唯一**的 main：它一多（有人在子目录里
// 又开了一个 main），发版脚本发的那个就不是全部了 ⇒ 而「哪些是全部」
// 这件事没有人会记得去查。
func CheckTheEntryLayerIsOneBinaryAtTheRoot(t *testing.T, root, modulePath string) {
	t.Helper()
	root = absRoot(t, root)
	mains := map[string]bool{}
	for _, f := range goFilesOrFatal(t, root) {
		name, err := PackageNameOf(f)
		if err != nil {
			t.Fatalf("parse %s: %v", Relative(root, f), err)
		}
		if name != "main" {
			continue
		}
		mains[filepath.Dir(f)] = true
	}
	if len(mains) == 0 {
		t.Fatalf("this repository has no package main: the entry layer of a service " +
			"repository is its root (main.go / server.go / init.go / workers.go / shutdown.go)")
	}
	for dir := range mains {
		if dir == root {
			continue
		}
		t.Errorf("%s is a package main, but this repository has exactly one binary and it "+
			"lives at the root: cmd/ holds subcommands (packages the entry layer calls), "+
			"not binaries of their own",
			Relative(root, dir))
	}
}

// CheckContractVocabularyNaming 让 IDL、生成包与模型目录始终同名。
//
// 这三样是同一件东西的三个侧面：说形状的 thrift 文件、带着它的 Go 包、
// 以及它住的目录。它们一漂，找一个工具的契约就得猜哪个名字是真的——
// 执行面当年就是这样（idl/exec/exec.thrift 生成 package jmsexec）。
//
// 一个词汇可以在一个目录里拆成好几份 thrift（入口 include 各域），
// 但目录仍然只说**一个**词汇：入口文件是 <pkg>.thrift，目录里每一份文件
// 都声明 `namespace go <pkg>`——拆的是文件，不是词汇。
//
// 模型目录按**名字**找，不按固定距离找：hz 布局里服务的模型在
// biz/<service>/model/，共用在 model/，没有一个统一的路径算术了——
// 但**名字**仍然得只说一件事，这就是这里查的。
func CheckContractVocabularyNaming(t *testing.T, root, modulePath string) {
	t.Helper()
	root = absRoot(t, root)
	dirs := map[string][]string{}
	for _, idl := range idlFilesOrFatal(t, root) {
		dir := filepath.Dir(idl)
		dirs[dir] = append(dirs[dir], idl)
	}
	names := make([]string, 0, len(dirs))
	for dir := range dirs {
		names = append(names, dir)
	}
	sort.Strings(names)
	for _, dir := range names {
		idls := dirs[dir]
		base := filepath.Base(dir)
		entry := filepath.Join(dir, base+".thrift")
		if _, err := os.Stat(entry); err != nil {
			t.Errorf("%s: the IDL directory has no entry file named after it: "+
				"idl/%s/%s.thrift is the convention", relToInternal(root, dir), base, base)
			continue
		}
		ok := true
		for _, idl := range idls {
			ns := namespaceGo(t, idl)
			switch ns {
			case base:
				// every file speaks for the directory's package ✓
			case "":
				t.Errorf("%s: declares no `namespace go` at all: every file in "+
					"an IDL directory speaks for the package the directory names",
					relToInternal(root, idl))
				ok = false
			default:
				t.Errorf("%s: declares namespace go %s, but the directory is %s: "+
					"every file in an IDL directory speaks for the package the "+
					"directory names", relToInternal(root, idl), ns, base)
				ok = false
			}
		}
		if !ok {
			continue
		}
		found := packagesNamed(t, root, base, modulePath)
		switch len(found) {
		case 0:
			t.Errorf("%s: no package called %s anywhere in the repository: "+
				"the contract is declared but nowhere to be found", relToInternal(root, entry), base)
		case 1:
			// the one package is named after the IDL directory ✓
		default:
			t.Errorf("%s: %d packages are called %s (%s): the name has to mean "+
				"one thing", relToInternal(root, entry), len(found), base, strings.Join(found, ", "))
		}
	}
}

// packagesNamed 找出仓里包名叫 name 的目录（路径按相对 internal/ 写）。
//
// ⚠️ 包名按 **import 路径**算（不是按目录名）：边界是用 import 路径说的，
// 文件路径与 import 路径是两种语言，不能混着比。
func packagesNamed(t *testing.T, root, name, modulePath string) []string {
	t.Helper()
	dirs, err := PackagesNamed(root, name)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	out := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		if PackageOf(ImportPathOf(modulePath, root, dir)) != name {
			continue
		}
		out = append(out, relToInternal(root, dir))
	}
	sort.Strings(out)
	return out
}

// CheckNoForbiddenImport 不许 import 某些模块。
//
// ⚠️ 它是两条原守卫的共同形状：
//
//   - 两个服务不得互相 import（它们回答的不是同一个问题，部署配置也不同）；
//   - 底座不得依赖任何一个服务（底座一旦伸手进某个服务，就不再是共用的）。
//
// ⚠️ 底座与服务说**不同的话**，所以文案也不同：服务越界时说「两个服务
// 回答的不是同一个问题」，底座越界时说「底座在两个服务之下」。
//
// ⚠️ forbidden 里写的是 module path，判定必须带尾斜杠（IsImportOf）：
// …/jumpserver-mcp 是 …/jumpserver-mcp-exec 的字符串前缀，差一个 "-"，
// 不带斜杠比就会把执行面当成管理面的一部分。
// CheckNoForbiddenRequire 让 go.mod 不 require 任何一个被禁的模块。
//
// ⚠️ 为什么光扫源码不够：两个服务是**不同的 module**，互相 import 编译期就断了
// （编译器接手了那条边界）。但 go.mod 里如果 require 了对方，依赖关系就**写下**了 ——
// 依赖图上写着「我需要它」，而 require 里的版本号是一个**承诺**。
// ⇒ 源码与 go.mod 两头都要查：源码查「真的伸手了没有」，go.mod 查「承诺了没有」。
//
// ⚠️ 判定用**精确相等**（module path 不会带子路径），别用前缀：
// …/jumpserver-mcp 是 …/jumpserver-mcp-exec 的字符串前缀（差一个 "-"），
// 前缀比会把执行面当成管理面的一部分。
func CheckNoForbiddenRequire(t *testing.T, root, modulePath string, forbidden []string) {
	t.Helper()
	root = absRoot(t, root)
	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	requires := parseRequirePaths(string(body))
	for _, mod := range forbidden {
		if _, ok := requires[mod]; ok {
			t.Errorf("go.mod requires %s: %s",
				mod, forbiddenWhy(modulePath))
		}
	}
}

// parseRequirePaths 读出 go.mod 里 require 的所有 module path。
//
// ⚠️ 认两种写法：`require ( … )` 块与单行的 `require path version`。
// 块外的行（module / go / replace / exclude）不算。
func parseRequirePaths(body string) map[string]bool {
	out := map[string]bool{}
	inBlock := false
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		if inBlock {
			if trimmed == ")" {
				inBlock = false
				continue
			}
			fields := strings.Fields(trimmed)
			if len(fields) >= 1 {
				out[fields[0]] = true
			}
			continue
		}
		if trimmed == "require (" {
			inBlock = true
			continue
		}
		if strings.HasPrefix(trimmed, "require ") {
			fields := strings.Fields(trimmed)
			if len(fields) >= 2 {
				out[fields[1]] = true
			}
		}
	}
	return out
}

// CheckNoForbiddenImport 让本仓不 import 任何一个被禁的模块。
//
// ⚠️ 两条规则（底座不得依赖服务 / 两个服务不得互相 import）合并在这一个体里：
// 它们说的是同一件事的两个方向，失败文案按角色分开。
//
// ⚠️ 底座与服务说**不同的话**，所以文案也不同：服务越界时说「两个服务
// 回答的不是同一个问题」，底座越界时说「底座在两个服务之下」。
//
// ⚠️ forbidden 里写的是 module path，判定必须带尾斜杠（IsImportOf）：
// …/jumpserver-mcp 是 …/jumpserver-mcp-exec 的字符串前缀，差一个 "-"，
// 不带斜杠比就会把执行面当成管理面的一部分。
func CheckNoForbiddenImport(t *testing.T, root, modulePath string, forbidden []string) {
	t.Helper()
	root = absRoot(t, root)
	for _, f := range goFilesOrFatal(t, root) {
		for _, imp := range importsOrFatal(t, f) {
			for _, mod := range forbidden {
				if !IsImportOf(imp, mod) {
					continue
				}
				t.Errorf("%s imports %s (%s): %s",
					relToInternal(root, f),
					forbiddenLabel(mod, modulePath), imp,
					forbiddenWhy(modulePath))
			}
		}
	}
}

// forbiddenLabel 说出被禁止的那个模块是谁。
func forbiddenLabel(mod, modulePath string) string {
	if modulePath == ModuleKit {
		return "a service"
	}
	switch mod {
	case ModuleManagement:
		return "the management plane"
	case ModuleExecution:
		return "the execution plane"
	default:
		return "a service"
	}
}

// forbiddenWhy 说出为什么不许越界。
func forbiddenWhy(modulePath string) string {
	if modulePath == ModuleKit {
		return "the shared base is below both services, not above either"
	}
	return "the two services answer different questions and are deployed with different configuration"
}
