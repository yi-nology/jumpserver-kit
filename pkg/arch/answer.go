package arch

// 从原仓 internal/arch/answer_test.go 搬来的守卫体。
//
// 工具的答复就是契约。
//
// 每个工具都声明自己答复的形状（OutputSchema），服务器在把答复交给模型
// 之前按那个形状校验一遍。那道校验抓得住**值**错了（数字放在了字符串的
// 位置），抓不住**键**错了：多余的字段是故意放行的，所以一行少了个字段、
// 或者拼写与契约不同，都能通过校验，然后以一个「洞」的样子到模型面前。
//
// 治法不是更多校验，而是换一种写答复的方式：工具**产出**契约类型。
// 不存在的 struct 字段编译不过 ⇒ 工具许诺的形状与它交出去的形状
// 按构造就是同一件事。
//
// 这条守卫查的就是答复真是这么写出来的：
//
//   - 交给 render.Text 的值不是手搭的 map；
//   - 列表的行也不是手搭的 map。
//
// 它是源码扫描而不是运行期检查，这是有意的：运行期检查只在有人调用那个
// 工具时才响，而**没人调过的工具**恰恰是答复最容易漂掉的那个。
//
// 线上的形状是另一回事，这里**不**查：请求体与解码出来的响应是堡垒机
// 自己的形状，它们故意留在 map 里。这条规则管的是我们**交出去**的东西。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CheckToolAnswersAreContractTypes 让每个工具都守这条规矩：答复是契约类型，
// 不是手敲出来的 map。
//
// 这条守卫第一次跑的时候报了 82 处。那不是守卫错了：那些答复从契约落地
// 那天起就带着手写的键，只有 schema 说的不是。对 SDK 来说 map 答复与
// 契约答复分不出来——两者都序列化成同样的 JSON——所以除了这条规则，
// 没有任何东西能把它们分开。
func CheckToolAnswersAreContractTypes(t *testing.T, root string, handlerDirs []string) {
	t.Helper()
	root = absRoot(t, root)
	scanned := 0

	for _, dir := range handlerDirs {
		abs := filepath.Join(root, dir)
		entries, err := os.ReadDir(abs)
		if err != nil {
			t.Fatalf("read %s: %v", abs, err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(abs, name)
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				scanned++
				for _, bad := range scanFunction(fset, fn) {
					t.Errorf("%s:%d: %s\n\t%s",
						Relative(root, path), bad.line, bad.what, bad.how)
				}
			}
		}
	}
	// The sanity check is about the SCAN, not about the findings: a guard
	// that looks at nothing passes everything.
	if scanned == 0 {
		t.Fatal("no function was scanned: the guard is looking at nothing")
	}
}

// badAnswer 是一处「工具交回手搭的 map」。
type badAnswer struct {
	line int
	what string
	how  string
}

// scanFunction 在一个函数体里找手搭的答复。
//
// 先收集绑到 map 字面量的变量：`res := map[string]any{…}` 后面接
// `render.Text(res)` 是常见形状，而这两句离得很远。
func scanFunction(fset *token.FileSet, fn *ast.FuncDecl) []badAnswer {
	// 绑到 map 字面量的变量，以及绑定的那一行。
	//
	// 走的是**整个**函数体，不只是顶层语句：`if` 或 `for` 里的绑定
	// 同样是手搭的答复，只看顶层的扫描会把代码判成干净，而 map 还在那儿。
	mapVars := map[string]int{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 || len(assign.Lhs) != 1 {
			return true
		}
		if !isMapLiteral(assign.Rhs[0]) {
			return true
		}
		if id, ok := assign.Lhs[0].(*ast.Ident); ok {
			mapVars[id.Name] = fset.Position(assign.Rhs[0].Pos()).Line
		}
		return true
	})

	var out []badAnswer
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch {
		case isRenderText(call):
			if len(call.Args) != 1 {
				return true
			}
			switch arg := call.Args[0].(type) {
			case *ast.CompositeLit:
				if isMapLiteral(arg) {
					out = append(out, badAnswer{
						line: fset.Position(arg.Pos()).Line,
						what: "the answer is a hand-built map",
						how:  "build the contract type the tool declares and hand that over",
					})
				}
			case *ast.Ident:
				if line, ok := mapVars[arg.Name]; ok {
					out = append(out, badAnswer{
						line: line,
						what: "the answer is a hand-built map (" + arg.Name + ")",
						how:  "build the contract type the tool declares and hand that over",
					})
				}
			}
		case isAppend(call):
			// A row is appended as a map literal: the row is hand-built too.
			if len(call.Args) != 2 {
				return true
			}
			if lit, ok := call.Args[1].(*ast.CompositeLit); ok && isMapLiteral(lit) {
				out = append(out, badAnswer{
					line: fset.Position(lit.Pos()).Line,
					what: "a row of a list is a hand-built map",
					how:  "append the row type the list declares",
				})
			}
		}
		return true
	})
	return out
}

// isRenderText 报告这个调用是不是 render.Text(..)。
func isRenderText(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "render" && sel.Sel.Name == "Text"
}

// isAppend 报告这个调用是不是内置的 append(..)。
func isAppend(call *ast.CallExpr) bool {
	id, ok := call.Fun.(*ast.Ident)
	return ok && id.Name == "append"
}

// isMapLiteral 报告这个表达式是不是 map[string]any 字面量。
func isMapLiteral(e ast.Expr) bool {
	lit, ok := e.(*ast.CompositeLit)
	if !ok {
		return false
	}
	mt, ok := lit.Type.(*ast.MapType)
	if !ok {
		return false
	}
	key, kok := mt.Key.(*ast.Ident)
	val, vok := mt.Value.(*ast.Ident)
	return kok && vok && key.Name == "string" && val.Name == "any"
}
