package arch

// 兄弟仓在哪：环境变量优先，否则用同级目录的约定。
//
// ⚠️ 拆仓之后有三条守卫必须同时看三棵树（底座的可达性、共用词汇的产出者、
// 能力的措辞），所以「树在哪」得有个约定。三种情况：
//
//   - 环境变量 JMS_SIBLING_ROOTS 给了目录列表（":" 分隔）⇒ 用它；
//   - 没给 ⇒ 用同级目录 ../jumpserver-mcp 与 ../jumpserver-mcp-exec；
//   - 找到了 ⇒ **真跑**（不是跳过）。
//
// ⚠️ 找不到 ⇒ 跳过，但**跳过 ≠ 通过**：CI 用 JMS_REQUIRE_SIBLINGS=1
// ⇒ 缺树时**失败**而不是跳过。跳过的那条消息必须写清楚「缺哪棵树、
// 怎么补」，否则读的人只看到一句 SKIP，不知道这条守卫今天没跑。
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// SiblingRoots 返回兄弟仓的候选目录。
func SiblingRoots(kitRoot string) []string {
	if env := strings.TrimSpace(os.Getenv("JMS_SIBLING_ROOTS")); env != "" {
		var out []string
		for _, p := range filepath.SplitList(env) {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	base := filepath.Dir(strings.TrimRight(kitRoot, string(filepath.Separator)))
	return []string{
		filepath.Join(base, "jumpserver-mcp"),
		filepath.Join(base, "jumpserver-mcp-exec"),
	}
}

// SiblingServiceTrees 找到两个服务仓（管理面、执行面）。
//
// ⚠️ 它按 module path 认人，不按目录名：两个服务仓的 module path 只差一个
// "-"（…/jumpserver-mcp 与 …/jumpserver-mcp-exec），目录名认不出来。
//
// ⚠️ 缺树 ⇒ t.Skip（消息写清楚缺哪棵、怎么补）；JMS_REQUIRE_SIBLINGS=1
// ⇒ t.Fatal（CI 里不许把「没跑」当成「跑过了」）。
func SiblingServiceTrees(t *testing.T, kitRoot string) []Tree {
	t.Helper()
	found := map[string]Tree{}
	var unreadable []string
	for _, root := range SiblingRoots(kitRoot) {
		tr, err := TreeAt(root)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", root, err))
			continue
		}
		found[tr.ModulePath] = tr
	}
	want := []Tree{
		{ModulePath: ModuleManagement, Name: "management"},
		{ModulePath: ModuleExecution, Name: "execution"},
	}
	var out []Tree
	var missing []string
	for _, w := range want {
		tr, ok := found[w.ModulePath]
		if !ok {
			missing = append(missing, w.ModulePath)
			continue
		}
		tr.Name = w.Name
		out = append(out, tr)
	}
	if len(missing) > 0 {
		msg := fmt.Sprintf("the sibling repository %s is not here: this guard needs all "+
			"three trees at once (the base, the management plane and the execution plane), "+
			"and %d of them are missing (%s). Put the sibling repositories next to this "+
			"one (../jumpserver-mcp and ../jumpserver-mcp-exec), or point "+
			"JMS_SIBLING_ROOTS at them (colon-separated directories). %s",
			strings.Join(missing, ", "), len(missing), strings.Join(unreadable, "; "),
			requireSiblingsNote())
		if os.Getenv("JMS_REQUIRE_SIBLINGS") == "1" {
			t.Fatal(msg)
		}
		t.Skip(msg)
	}
	return out
}

// requireSiblingsNote 说明「跳过」在 CI 里意味着什么。
func requireSiblingsNote() string {
	if os.Getenv("JMS_REQUIRE_SIBLINGS") == "1" {
		return "JMS_REQUIRE_SIBLINGS=1 is set, so a missing tree is a FAILURE, not a skip."
	}
	return "Set JMS_REQUIRE_SIBLINGS=1 to turn this skip into a failure (CI does)."
}
