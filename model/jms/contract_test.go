package jms_test

// 共用词汇的契约守卫（「契约类型写了没人产出 = 契约不存在」）。
//
// ⚠️ **世界变了**：共用词汇的**产出者在两个服务仓里**，不在声明它的这个仓里。
// 只扫 kit 自己会一片红（每个共用类型都「没人产出」），而那片红与契约
// 无关——它只是因为产出者在隔壁。
//
// ⇒ 所以这条守卫扫**三棵树**：kit（声明）与两个服务仓（产出）。
//
// ⚠️ 守卫的**体**在 pkg/contractscan（机械 + 失败文案），**判据**是这里的
// Scope：三份守卫各问一个问题，不该合并；而「怎么读生成物、怎么抽字段、
// 怎么找 mention」是同一件事，抄三份就会漂——漂的那份决定守卫认不认得出
// 破契约。
//
// ⚠️ 找不齐服务仓时**跳过**（消息写清楚缺哪棵树、怎么补），CI 用
// JMS_REQUIRE_SIBLINGS=1 ⇒ 缺树时**失败**而不是跳过（跳过 ≠ 通过）。
import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/arch"
	"github.com/yi-nology/jumpserver-mcp-kit/pkg/contractscan"
)

func TestEveryContractTypeIsProduced(t *testing.T) {
	// The kit's own root: model/jms → up two levels.
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("abs the repository root: %v", err)
	}
	// The two services: the producers live there. Missing ⇒ skip (or fail
	// in CI, where a guard that did not run must not look like one that
	// passed).
	siblings := arch.SiblingServiceTrees(t, root)
	roots := make([]contractscan.Root, 0, len(siblings))
	for _, svc := range siblings {
		roots = append(roots, contractscan.Root{
			Path:  svc.Root,
			Base:  filepath.Base(svc.Root),
			World: svc.Name,
		})
	}
	contractscan.CheckProduced(t, contractscan.Scope{
		World:    "the kit",
		RootBase: "jumpserver-mcp-kit",
		// The producers are in the two service repositories.
		Roots: roots,
		// The generated file is not a reference to itself. legacy/ is a
		// separate repository kept for reference and is not part of any
		// build.
		NotAProducer: func(abs string) bool {
			return contractscan.IsGenerated(abs) ||
				strings.Contains(abs, string(filepath.Separator)+"legacy"+string(filepath.Separator))
		},
		// ⚠️ ENUMS count as declared types here. They used not to, and
		// the hole was real: the first cross-layer enum of the shared
		// vocabulary (Delivery — "did the command reach the machine")
		// was declared in the IDL, and nothing would have gone red if
		// nobody had ever produced it. A type that nobody builds is a
		// promise nobody keeps, and an enum is a type. (The per-plane
		// model guards say the opposite — see Scope.EnumsDeclared.)
		EnumsDeclared: true,
	})
}
