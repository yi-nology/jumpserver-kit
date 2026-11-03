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

// TestTheKitHasNoBinaryDirectory：kit 是**库**，不是程序。
//
// ⚠️ 原仓那条守卫是「cmd/ 谁都不许 import」；在 kit 上它没有对象
// （kit 没有 cmd/），所以 kit 自己的判据是**不许有 cmd/**：kit 一旦长出
// 入口层，它就开始有「谁把它当库用」的问题，而它是个库。
func TestTheKitHasNoBinaryDirectory(t *testing.T) {
	root := kitRoot(t)
	dir := filepath.Join(root, "cmd")
	if _, err := os.Stat(dir); err == nil {
		t.Errorf("%s exists: the kit is a library, not a program; "+
			"cmd/ is the outermost layer of a service, and the kit must not have one",
			arch.Relative(root, dir))
	}
}

// TestTheKitBinariesAreOutermost 让入口层不要变成一个别人依赖的库。
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
