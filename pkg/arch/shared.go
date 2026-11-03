package arch

// 从原仓 internal/arch/arch_test.go 搬来的守卫体：底座必须被两个服务都用。
//
// ⚠️ 底座是「**两个服务都用的东西**」。只有一个够得到的包，是那个服务的
// 私有代码披着共享的名字——而另一个服务迟早会伸手进去，于是两者就在
// **没有人决定过**的情况下耦上了。
//
// ⚠️ 词表是另一回事，这里**故意不**管：`pkg/redact.IsCredentialKey` 是
// 留痕的擦洗器与各面答复的擦洗器都会问的那**一份**词表。一个被一个服务
// 用着的共享**定义**仍然是共享的（抄两份就会漂——那正是重点）；不许发生
// 的是一整个**包**只有一个服务够得到。
//
// ⚠️ 规则是按**包**算的，不是按符号算，而且它算的是**可达性**而不是直接
// import：执行面是通过 `pkg/reg` 与 `pkg/audit` 够到 `pkg/redact` 的
// （它自己不 import 它）⇒ 按直接 import 读，就会把 `pkg/redact` 判成管理面
// 的私有包，而它不是。
//
// ⚠️ 拆仓之后这条规则必须**跨仓**看：管理面的 import 图 → kit 的包 →
// kit 的 import 图 ⇒ 三棵源码树要同时在手。找不到兄弟仓就**跳过**（并说明
// 缺哪棵树），CI 用 JMS_REQUIRE_SIBLINGS=1 让「跳过」变成失败。
import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// CheckBaseSharedByBoth 守住「底座是被两个服务共用的」。
func CheckBaseSharedByBoth(t *testing.T, base Tree, services []Tree) {
	t.Helper()
	// The base packages, and who reaches them.
	all := map[string]map[string]bool{} // package -> service -> reached
	for _, svc := range services {
		for pkg := range reachableBasePackages(t, base, services, svc) {
			if all[pkg] == nil {
				all[pkg] = map[string]bool{}
			}
			all[pkg][svc.Name] = true
		}
	}
	// ⚠️ The base packages NOBODY reaches are in the list too: a package
	// in the shared base that no service uses is dead weight in the
	// base (or, worse, one service's private code that nobody wired up
	// yet) ⇒ the rule has to see it.
	for pkg := range basePackages(t, base) {
		if all[pkg] == nil {
			all[pkg] = map[string]bool{}
		}
	}
	if len(all) == 0 {
		t.Fatal("no service reaches the shared base at all; the layout is wrong")
	}
	for pkg, reached := range all {
		if len(reached) < len(services) {
			t.Errorf("%s is in the shared base but only %s reaches it: "+
				"it is that service's private code wearing a shared name — "+
				"move it under that service's own directory, or make both use it",
				pkg, whoReaches(reached, services))
		}
	}
}

// whoReaches names the services that reach a package.
func whoReaches(reached map[string]bool, services []Tree) string {
	switch {
	case len(reached) == 0:
		return "NO service"
	case len(reached) == 1:
		for name := range reached {
			return "the " + name + " service"
		}
		return "one service"
	case len(reached) == len(services):
		if len(services) == 2 {
			return "both services"
		}
		return fmt.Sprintf("all %d services", len(services))
	default:
		return fmt.Sprintf("%d of %d services", len(reached), len(services))
	}
}

// reachableBasePackages returns the base packages the given service reaches,
// directly or through anything in between.
//
// ⚠️ The walk follows the import graph of **all** the trees at once, not
// just the base's own edges: a service reaches a base package when it
// imports it, or imports a package of its own that imports it — and that
// "package of its own" includes `internal/<service>/…` (the service's own
// infrastructure layer) ⇒ walking only the base's edges would let a
// private base package hide behind an `internal/` hop.
//
// ⚠️ The keys are the package's IMPORT PATH — the same shape as the import
// paths the walk starts from (a relative key would never match an absolute
// import path).
func reachableBasePackages(t *testing.T, base Tree, services []Tree, svc Tree) map[string]bool {
	t.Helper()
	// The import graph of every tree, keyed by package import path.
	imports := map[string][]string{}
	for _, tree := range append([]Tree{base}, services...) {
		root := absRoot(t, tree.Root)
		for _, f := range goFilesOrFatal(t, root) {
			// ⚠️ 底座自己的**测试文件**不产生边。
			//
			// ⚠️ 为什么：原仓是一个仓，底座的测试文件与服务的测试文件混在
			// 一起，谁产生边没人在意。拆仓之后必须分开——底座某个包的
			// 「被两个服务共用」不能被**底座自己的守卫** import 它这件事
			// 假象满足（kit 的 model/jms 契约守卫 import 了底座的守卫机械，
			// 那条边会让 pkg/arch 看起来是两个服务都在用的，而其实一个都
			// 没有）。
			//
			// ⇒ 这条规则因此**更严**了一点（不是更松）：一个只有底座自己
			// 的测试在用的底座包，现在会被算成「没人用」。
			if tree.ModulePath == base.ModulePath && strings.HasSuffix(f, "_test.go") {
				continue
			}
			pkg := tree.PackagePath(f)
			for _, imp := range importsOrFatal(t, f) {
				if !belongsToAny(imp, append([]Tree{base}, services...)) {
					continue
				}
				imports[pkg] = append(imports[pkg], imp)
			}
		}
	}
	// The service's direct imports, walked through the graph.
	reached := map[string]bool{}
	var walk func(imp string)
	walk = func(imp string) {
		if reached[imp] {
			return
		}
		reached[imp] = true
		for _, next := range imports[imp] {
			walk(next)
		}
	}
	// ⚠️ The seeds are EVERY file of the service — not just the ones under
	// "biz/": a service spans "biz/", "conf/", "internal/" and "cmd/",
	// and a base package that only the BINARY reaches ("cmd/…") is exactly
	// the shape this rule is meant to catch ⇒ seeding only from "biz/" let
	// it escape.
	root := absRoot(t, svc.Root)
	for _, f := range goFilesOrFatal(t, root) {
		for _, imp := range importsOrFatal(t, f) {
			walk(imp)
		}
	}
	// ⚠️ Only the BASE packages count: the walk passes through the
	// service's own packages on the way.
	out := map[string]bool{}
	for imp := range reached {
		if isBasePackage(imp, base) {
			out[imp] = true
		}
	}
	return out
}

// belongsToAny reports whether an import path belongs to one of the trees.
func belongsToAny(imp string, trees []Tree) bool {
	for _, tree := range trees {
		if IsImportOf(imp, tree.ModulePath) {
			return true
		}
	}
	return false
}

// isBasePackage reports whether an import path is a package of the base.
func isBasePackage(imp string, base Tree) bool {
	return IsImportOf(imp, base.ModulePath+"/pkg") || IsImportOf(imp, base.ModulePath+"/model")
}

// guardMachinery 是**守卫自己的机械**，它不属于底座。
//
// ⚠️ 原仓里守卫住在 internal/arch/ —— 那里从来不是底座（底座 = pkg/ + model/）
// ⇒「底座被两个服务共用」这条规则从来不管守卫机械。拆仓之后守卫机械必须能被
// 两个服务 import（Go 的 internal 规则不许跨 module import internal/），
// 于是它搬到了 pkg/arch —— 但它**不是**底座：它是两个服务**共用**的守卫体，
// 而不是可能悄悄变成某个服务私有代码的底座代码。
//
// ⚠️ 所以这条规则的范围仍然是原仓那条范围（业务上的共用底座），
// 没有因为 Go 的可见性约束而扩大。
var guardMachinery = []string{ModuleKit + "/pkg/arch"}

// basePackages returns every package of the shared base.
func basePackages(t *testing.T, base Tree) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	root := absRoot(t, base.Root)
	for _, dir := range []string{"pkg", "model"} {
		files, err := GoFiles(filepath.Join(root, dir))
		if err != nil {
			t.Fatalf("walk %s: %v", filepath.Join(root, dir), err)
		}
		for _, f := range files {
			pkg := base.PackagePath(f)
			if isGuardMachinery(pkg) {
				continue
			}
			out[pkg] = true
		}
	}
	return out
}

// isGuardMachinery reports whether a package is the guards' own machinery.
func isGuardMachinery(importPath string) bool {
	for _, m := range guardMachinery {
		if importPath == m {
			return true
		}
	}
	return false
}
