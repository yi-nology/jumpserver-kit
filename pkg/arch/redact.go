package arch

// 从原仓 internal/arch/redact_test.go 搬来的守卫体。
//
// 仓自己的参数名不许被当成凭据。
//
// 留痕记录每次调用的参数，而参数带着本仓工具自己的参数名。脱敏器遮的是
// **名字**说「这值是凭据」的字段——一个被它错认成凭据的参数，就是留痕
// 从此不再记录的那个参数。
//
// 这不是纸上担心：本仓被这一类咬过两次。词表当年是按**子串**匹配的，
// 于是 "session"（在 jms_command_audit 上）与 "key_id"（在
// jms_user_sshkey_remove 上）被遮掉了 ⇒ 留痕不再说得清查的是**哪个**
// 会话、注册的是**哪把**钥匙——恰恰是它存在的意义。
//
// 所以词表是对着仓自己的参数**机械地**查的：脱敏器当成凭据的参数名集合，
// 必须正好是真正是凭据的那个集合。
//
// 它是源码扫描而不是运行期检查，这是有意的：运行期检查只在有人调用那个
// 工具时才响，而**没人调过的工具**恰恰是参数最容易漂掉的那个。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/redact"
)

// CheckCredentialParameters 用仓自己的参数表校住脱敏器的词表。
//
// ⚠️ known 是「本仓真的当成凭据的参数」——每个仓一份：
// 管理面有 password / secret，执行面一张空表（执行面没有凭据参数 ⇒
// 表空是**事实**，不是漏抄）。
//
// ⚠️ 表是故意很小的。加一个名字进去，就是留痕从此不再记录它，
// 所以它得**真是**一个凭据，而不是「看着像」。
func CheckCredentialParameters(t *testing.T, root string, handlerDirs []string, known map[string]string) {
	t.Helper()
	root = absRoot(t, root)
	found := map[string][]string{}

	for _, dir := range handlerDirs {
		abs := filepath.Join(root, dir)
		entries, err := os.ReadDir(abs)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			path := filepath.Join(abs, e.Name())
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok {
					return true
				}
				for _, field := range st.Fields.List {
					if field.Tag == nil {
						continue
					}
					name := jsonTagName(field.Tag.Value)
					if name == "" || !redact.IsCredentialKey(name) {
						continue
					}
					found[name] = append(found[name], Relative(root, path))
				}
				return true
			})
		}
	}

	for name, files := range found {
		if _, ok := known[name]; !ok {
			t.Errorf("the parameter %q looks like a credential to the scrubber, so the trail "+
				"stops recording it (%s) — add it to credentialParameters only if it really is one",
				name, strings.Join(files, ", "))
		}
	}
	// And the list must not rot: a name nobody uses any more is a name
	// that no longer needs to be masked.
	for name := range known {
		if len(found[name]) == 0 {
			t.Errorf("the parameter %q is listed as a credential, but no tool uses it any more",
				name)
		}
	}
}
