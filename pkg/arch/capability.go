package arch

// 从原仓 internal/arch/capability_test.go 搬来的守卫体。
//
// 能力模型赖以成立的两条结构规则——而它们之前**谁都没在守**。
//
// ⚠️ 两条都曾经只是 AGENTS.md 里的一句话，别的什么都没有：
//
//   - 「控制流里不许出现版本号」—— 代码问的是**能力**，不是某个发行版；
//   - 「措辞只有一份」—— 关于能力的那些句子住在能力声明里，不在调用点。
//
// ⇒ 一条只写下来的规则会烂掉：下一次重构把版本判断塞进一个 handler，
// 或者某个 doctor 长出自己的措辞，而没有任何东西会说话。
//
// ⚠️ 而且它们不是装饰：两条后面都有一个**实测**出来的故障。
//
//   - 措辞那条：两个 doctor 真的各自带着一份「这个部署没有……」的句子，
//     其中一个说「被当作可用」，而它自己那个面的委派工具会**拒绝**一个
//     认不出的方案；
//   - 版本那条：发行版词汇（VersionV4 / VersionV5）今天只存在于一个包里，
//     而这条守卫就是让它继续这样的东西。
//
// 能力模型是本仓对「v4 与 v5 有何不同」的回答。
// ⇒ 这两条守卫守的正是那个回答本身。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// 发行版词汇，逐字写出。
//
// ⚠️ 这些是**名字**，因为守卫读语法树。⇒ 这些名字由
// CheckCapabilityVocabulary 拿去对着 pkg/jmsapi 核对，于是那里的改名是
// 守卫里的一次响亮失败，而不是一次悄悄变弱的守卫。
var releaseNames = []string{"VersionV4", "VersionV5", "versionAuto"}

// CheckVersionDoesNotLeaveProtocolLayer 让发行版留在控制流之外。
//
// ⚠️ 规则不是「v4 这个词不许出现」——散文里提到某个发行版是允许的，
// 因为对一个人说「这台是 v4」比说「这台没有委派方案」更清楚。规则讲的是
// **控制流**：代码不许按「我正在跟**哪个发行版**说话」分支。
//
// ⇒ 为什么这件事要紧：工具层里的版本判断是那份差别的**第二份拷贝**，而
// 差别清单里已经有一份了。两份拷贝会漂——而漂的那一份决定会话以什么
// 权限跑。
func CheckVersionDoesNotLeaveProtocolLayer(t *testing.T, root, modulePath string) {
	t.Helper()
	root = absRoot(t, root)
	protocolPrefix := modulePath + "/pkg/jmsapi/"
	for _, f := range goFilesOrFatal(t, root) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		r := Relative(root, f)
		if strings.HasPrefix(ImportPathOf(modulePath, root, f), protocolPrefix) {
			continue // the protocol layer owns the release vocabulary
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", r, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			for _, name := range releaseNames {
				if id.Name != name {
					continue
				}
				t.Errorf("%s: %s names a JumpServer RELEASE — the release is what the operator "+
					"configures, and the code asks about CAPABILITIES instead; a version check here "+
					"is a second copy of the difference, and the difference list already holds it",
					r, id.Name)
			}
			return true
		})
	}
}

// CheckCapabilityWordingNotRewrittenElsewhere 让措辞只有一份。
//
// ⚠️ **陈述**某个能力状态的句子属于声明：「这个部署没有……」与「没能确定
// 这个部署有没有……」。⇒ 它们在这里由声明的**一个**名字造出来，于是新增
// 一个能力也被覆盖，不必有人再去加第二份清单。
//
// ⇒ 调用方仍然可以加自己的细节——「这里的会话只在……时才以 ai 账号跑」
// 是执行面自己的事。它**不可以**做的是用自己的话重述能力的状态，因为
// 两个 doctor 正是这样漂开的：一个说「没有委派方案」，另一个说「没有
// Chat AI 委派方案」，而第三处说的又是别的。
//
// ⚠️ 只查**字符串字面量**，不查注释：解释这条规则的注释没问题——
// 用自己的话**陈述**状态的注释才是通向下一次漂移的那条路。
//
// ⚠️ 它一次看**所有**树：措辞在哪个仓里被重写都是重写。
func CheckCapabilityWordingNotRewritten(t *testing.T, trees []Tree) {
	t.Helper()
	for _, decl := range jmsapi.CapabilityDeclarations() {
		phrases := []string{
			"this deployment has no " + decl.Name,
			"it could not be established whether this deployment has the " + decl.Name,
		}
		for _, tree := range trees {
			root := absRoot(t, tree.Root)
			protocolPrefix := tree.ModulePath + "/pkg/jmsapi/"
			for _, f := range goFilesOrFatal(t, root) {
				if strings.HasSuffix(f, "_test.go") {
					continue
				}
				r := Relative(root, f)
				if strings.HasPrefix(ImportPathOf(tree.ModulePath, root, f), protocolPrefix) {
					continue // the declaration owns the wording
				}
				file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
				if err != nil {
					t.Fatalf("parse %s: %v", r, err)
				}
				ast.Inspect(file, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					for _, p := range phrases {
						if strings.Contains(lit.Value, p) {
							t.Errorf("%s: a string literal re-states the %s capability in its own words "+
								"(%q) — the wording belongs to the declaration (jmsapi.Reason / Advice / "+
								"Explain), and a second copy is how the two doctors drifted apart",
								r, decl.Capability, p)
						}
					}
					return true
				})
			}
		}
	}
}
