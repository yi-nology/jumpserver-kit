package arch_test

// kit 仓自己的守卫。
//
// ⚠️ 这里只有**判据**：kit 是哪个仓、它的目录长什么样、它不许有什么。
// 守卫的**体**在 kit 的 pkg/arch 里（两个服务仓的守卫体也在那儿）——
// 抄三份必然漂，而漂的那份决定守卫认不认得出破契约。
//
// ⚠️ 拆仓之后有几条守卫**跨仓**：底座的包必须被两个服务都用、共用词汇
// 必须被产出、能力的措辞不许在别处重写 ⇒ 它们要三棵树同时在手。
// 找不到兄弟仓 ⇒ **跳过**（消息写清楚缺哪棵树、怎么补）；CI 用
// JMS_REQUIRE_SIBLINGS=1 ⇒ 缺树时**失败**而不是跳过（跳过 ≠ 通过）。
import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/arch"
)

// kitRoot 返回 kit 仓的根。
//
// ⚠️ 它从**测试自己的位置**推出来（internal/arch → 上两级），而不是从
// 工作目录推出来 ⇒ 从哪儿启动测试都不影响。
func kitRoot(t *testing.T) string {
	t.Helper()
	root, err := arch.RepoRoot(".")
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}
	return root
}

// kitTree 是 kit 这棵树。
func kitTree(t *testing.T) arch.Tree {
	t.Helper()
	return arch.Tree{Root: kitRoot(t), ModulePath: arch.ModuleKit, Name: "kit"}
}

// TestTheKitHasNoBareGoroutines 守住 oekit 矩阵的防 panic 规则。
func TestTheKitHasNoBareGoroutines(t *testing.T) {
	arch.CheckNoBareGoroutines(t, kitRoot(t))
}

// TestTheKitHasNoEntryLayer：kit 是**库**，不是程序。
//
// ⚠️ 原仓那条守卫是「cmd/ 谁都不许 import」；在 kit 上它没有对象
// （kit 没有 cmd/），所以 kit 自己的判据是**不许有入口层**：
//
//   - 不许有 cmd/（子命令层）；
//   - 仓根也不许有 package main（入口层搬到了仓根 ⇒ 那一条也得钉住）。
//
// ⚠️ 为什么仓根那一条要写出来：kit 是个库，它被**别人** import。
// 一旦仓根长出 package main，kit 就有了自己的二进制 ⇒ 它不再只是一个库，
// 而「谁 install 它」这件事会变成一个没人决定过的问题。
func TestTheKitHasNoEntryLayer(t *testing.T) {
	root := kitRoot(t)
	dir := filepath.Join(root, "cmd")
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("%s exists: the kit is a library, not a program; "+
			"cmd/ is the outermost layer of a service, and the kit must not have one",
			arch.Relative(root, dir))
	}
	files, err := arch.GoFiles(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	for _, f := range files {
		name, err := arch.PackageNameOf(f)
		if err != nil {
			t.Fatalf("parse %s: %v", arch.Relative(root, f), err)
		}
		if name != "main" {
			continue
		}
		t.Errorf("%s is a package main: the kit is a library, not a program; "+
			"the entry layer of a service lives at its repository root, and the kit "+
			"must not have one", arch.Relative(root, f))
	}
}

// TestTheKitBinariesAreOutermost 让入口层不要变成一个别人依赖的库。
//
// ⚠️ 在 kit 上这条守卫是空的（kit 没有入口层）⇒ 它在这儿是「不许有人
// 把 kit 当入口层用」的那一半：万一哪天有人在 kit 里 import 了某个
// package main，那条 import 会被这里挡住。
func TestTheKitBinariesAreOutermost(t *testing.T) {
	arch.CheckBinariesAreOutermost(t, kitRoot(t), arch.ModuleKit)
}

// TestTheContractVocabularyIsNamedTheSameEverywhere 让 IDL、生成包与模型
// 目录始终同名。
func TestTheContractVocabularyIsNamedTheSameEverywhere(t *testing.T) {
	arch.CheckContractVocabularyNaming(t, kitRoot(t), arch.ModuleKit)
}

// TestTheSharedBaseDoesNotDependOnAService 守住「底座在两个服务之下」。
//
// ⚠️ 判据是**别的 module path**：kit 不得 import 两个服务里的任何一个。
// 三个 module path 互为字符串前缀（…/jumpserver-mcp 是
// …/jumpserver-mcp-exec 的前缀，差一个 "-"）⇒ 判定必须带尾斜杠
// （pkg/arch.IsImportOf 就是这个形状）。
func TestTheSharedBaseDoesNotDependOnAService(t *testing.T) {
	arch.CheckNoForbiddenImport(t, kitRoot(t), arch.ModuleKit,
		[]string{arch.ModuleManagement, arch.ModuleExecution})
}

// TestTheDependenciesArePinned 让依赖的接线保持同步。
//
// ⚠️ kit 没有恢复脚本（它的依赖由两个服务仓一起恢复）⇒ 恢复脚本那一条
// 不跑，其余三条（go.sum 钉住、replace 不指向本机路径、module cache 里
// 已经解包）照跑。
func TestTheDependenciesArePinned(t *testing.T) {
	arch.CheckDependencyPinning(t, kitRoot(t), "")
}

// TestTheCapabilityVocabulary 守住能力模型的词汇，以及它带来的门禁。
func TestTheCapabilityVocabulary(t *testing.T) {
	arch.CheckCapabilityVocabulary(t, kitRoot(t), arch.ModuleKit)
}

// TestTheVersionDoesNotLeaveTheProtocolLayer 让发行版留在控制流之外。
func TestTheVersionDoesNotLeaveTheProtocolLayer(t *testing.T) {
	arch.CheckVersionDoesNotLeaveProtocolLayer(t, kitRoot(t), arch.ModuleKit)
}

// TestTheCapabilityWordingIsNotRewrittenElsewhere 让措辞只有一份。
//
// ⚠️ 跨仓：措辞在哪个仓里被重写都是重写 ⇒ 三棵树一起看。
func TestTheCapabilityWordingIsNotRewrittenElsewhere(t *testing.T) {
	siblings := arch.SiblingServiceTrees(t, kitRoot(t))
	trees := append([]arch.Tree{kitTree(t)}, siblings...)
	arch.CheckCapabilityWordingNotRewritten(t, trees)
}

// TestTheSharedBaseIsSharedByBoth 守住「底座是被两个服务共用的」。
//
// ⚠️ 跨仓：可达性要穿过两个服务仓的 import 图 ⇒ 三棵树同时在手。
func TestTheSharedBaseIsSharedByBoth(t *testing.T) {
	siblings := arch.SiblingServiceTrees(t, kitRoot(t))
	arch.CheckBaseSharedByBoth(t, kitTree(t), siblings)
}

// TestThePlaintextCredentialsAreNotInTheRepository 让凭据不进仓。
//
// ⚠️ 理由：写进文件里的凭据，一个 git push 就公开了 —— 而本仓的历史里
// 真的躺过一枚堡垒机管理员的令牌（在发布脚本与 e2e 测试里），直到有人
// 手工翻历史才发现它。构建抓不到它：脚本里的凭据是一个完全合法的程序，
// 它编译通过、它跑得动、它把活干完了。
func TestThePlaintextCredentialsAreNotInTheRepository(t *testing.T) {
	arch.CheckNoPlaintextCredentials(t, kitRoot(t))
}

// TestTheCapabilityGateHoldsInTheServiceRepos 让两个服务仓里的委派调用点
// 都先问能力。
//
// ⚠️ 跨仓：调用点在服务仓里（kit 的 pkg/jmsapi 里只有方案自己的 API）。
// 底座在 kit 里，所以这条守卫在 kit 这一侧跑 ⇒ 它看的是两个服务仓的树。
func TestTheCapabilityGateHoldsInTheServiceRepos(t *testing.T) {
	siblings := arch.SiblingServiceTrees(t, kitRoot(t))
	for _, svc := range siblings {
		arch.CheckCapabilityVocabulary(t, svc.Root, svc.ModulePath)
	}
}
