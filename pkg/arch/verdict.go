package arch

// 从原仓 internal/arch/verdict_test.go 搬来的守卫体。
//
// 判定约定，机械地钉住。
//
// 留痕读一个工具的答复，靠**按名字找字段**来判断发生了什么：
// 一个叫 `blocked` 的字符串表示工具拒绝了，一个 `dry_run` 布尔表示它
// 演练了，一个 `would_execute` 说这次演练会不会真跑。这个约定背后没有
// 编译器——把 `blocked` 改名成 `refused` 编译得过，测试全过，而从那
// 以后**每一条被拦下的危险命令都被记成「它跑了」**。留痕于是安安静静地
// 在它唯一要回答的那个问题上给出了相反的答案。
//
// ⚠️ 有两个不同的名字要紧，而且它们不是同一对名字：
//
//   - **Go 字段名**（`Blocked`、`DryRun`、`WouldExecute`）是
//     `render.OutcomeOf` 用**反射**查的。它比的是 `f.Name == name`，
//     所以要紧的是 Go 名字——而 thriftgo 是从 IDL 名字推出 Go 名字的，
//     改 IDL 字段名会把两个一起挪走；
//   - **JSON 名字**（`blocked`、`dry_run`、`would_execute`）是 agent
//     在线上读到的。
//
// 所以两对都被钉在这里，对着生成出来的契约模型：
//
//   - 一个叫 `WouldExecute` 的 Go 字段必须是 *bool ——「没答」与「这次
//     不会跑」是两件事，普通 bool 说不出前一件；
//   - 一个能演练的类型（有 DryRun 字段）也得能拒绝（有 Blocked 字段）。
//     一个只有演练没有拒绝字段的形状，是留痕分不出「演练」与「拒绝」的形状；
//   - 一个能演练的类型也得说清这次演练会不会真跑（有 WouldExecute 字段），
//     而说了的那个也得能演练；
//   - 在一个作为工具**答复**的类型里，`Blocked` 字段必须是 *string ——
//     留痕只从字符串读拒绝，一个布尔的会被静默跳过；
//   - 在线上：一个带 `dry_run` 字段的答复必须带 `blocked` 字段。
//
// ⚠️ 说到「答复」的规则只管答复类型，而答复类型是**机械地**找出来的：
// 每个工具在它的 handler 里声明自己答复的形状（`render.Schema[jmsms.Xxx]()`），
// 所以扫 handler 拿到的就是精确的那一组。用字段去猜（有个 DryRun 字段
// 就是答复）会错两处：一个只是恰好带着某个字段的嵌套类型不是答复
// （管理面的 OffendingIP.Blocked 是布尔，意思是「这个地址被拉黑了」，
// 它不是拒绝），而一个只会**拒绝**的答复根本不会被抓到。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/contractscan"
)

// CheckVerdictConvention 钉住判定约定。
//
// models 是生成契约模型的目录，sources 是工具声明答复形状的 handler 目录，
// errorBearing 是「允许带 Error 字段」的答复清单（键是 "包名.类型名"）。
//
// ⚠️ 答复类型是从 sources 里扫出来的，扫的是 `render.Schema[...]`：
// `render.ListOf[...]` 里的是**行**不是答复（反射读的是信封），
// 嵌套类型也不是。
func CheckVerdictConvention(t *testing.T, root string, models, sources []string, errorBearing map[string]string) {
	t.Helper()
	root = absRoot(t, root)
	answers := answerTypes(t, root, sources, modelPackages(root, models))
	if len(answers) == 0 {
		t.Fatal("no answer type was found: the guard is looking at nothing")
	}
	contractModels := contractModelsOf(t, root, models)

	for key, st := range contractModels {
		_, hasDryRun := st.goFields["DryRun"]
		blocked, hasBlocked := st.goFields["Blocked"]
		would, hasWould := st.goFields["WouldExecute"]

		// The rules that hold for EVERY type that carries the field:
		// they are about the trail reading it, wherever it sits.
		if hasWould {
			if would != "*bool" {
				t.Errorf("%s.WouldExecute is %s, want *bool: a plain bool cannot "+
					"say \"not answered\", and the trail must not claim \"this rehearsal "+
					"would not have run\" on the tool's behalf", key, would)
			}
			if !hasDryRun {
				t.Errorf("%s has a WouldExecute field but no DryRun field: "+
					"\"would it have run\" is a question only a rehearsal can answer",
					key)
			}
		}
		if hasDryRun && !hasWould {
			t.Errorf("%s has a DryRun field but no WouldExecute field: the trail "+
				"cannot say whether the rehearsal would have run", key)
		}

		// The rules that hold for the ANSWERS.
		if !answers[key] {
			continue
		}
		if hasDryRun && !hasBlocked {
			t.Errorf("%s has a DryRun field but no Blocked field: the trail "+
				"cannot tell a rehearsal from a refusal in it", key)
		}
		if hasBlocked && blocked != "*string" {
			t.Errorf("%s.Blocked is %s, want *string: the trail reads a refusal "+
				"only from a string field, so a bool one would be skipped silently",
				key, blocked)
		}
		// The answer's own account of a failure, and how far the action
		// got: both are read by the trail, and both have to be strings.
		failure, hasFailure := st.goFields["Error"]
		if hasFailure && failure != "*string" {
			t.Errorf("%s.Error is %s, want *string: the trail reads a failure the "+
				"tool reported in its answer only from a string field", key, failure)
		}
		delivery, hasDelivery := st.goFields["Delivery"]
		if hasDelivery && delivery != "*string" {
			t.Errorf("%s.Delivery is %s, want *string: the delivery state is a word "+
				"(\"not_sent\" / \"maybe_sent\"), and the trail copies it as it is", key, delivery)
		}
		// A `Delivery` without an `Error` says "it may still be running"
		// without saying WHAT broke — and the trail's `failed` column
		// would not fire, so a sweep that half failed would read as one
		// that worked. The two go together.
		if hasDelivery && answers[key] && !hasFailure {
			t.Errorf("%s carries a Delivery field but no Error field: the trail "+
				"would say \"it may still be running\" without saying that "+
				"something broke", key)
		}
		// An `Error` field on an answer changes what the trail says about
		// that tool — so the set of such answers is a deliberate list.
		if hasFailure && answers[key] {
			if _, listed := errorBearing[key]; !listed {
				t.Errorf("%s carries an Error field, so the trail reads it as "+
					"\"this call did not fully work\" — but it is not on the "+
					"list of answers allowed to say that; add it deliberately "+
					"(and say what the failure means)", key)
			}
		}
		if _, hasDryRunWire := st.jsonFields["dry_run"]; hasDryRunWire {
			if _, hasBlockedWire := st.jsonFields["blocked"]; !hasBlockedWire {
				t.Errorf("%s has a dry_run field but no blocked field: the agent "+
					"cannot tell a rehearsal from a refusal in it", key)
			}
		}
	}
}

// AnswerTypes 返回「被工具当作答复契约交出去过」的类型集合。
//
// ⚠️ 键是 "<模型包名>.<类型名>"（如 "jmsexec.CommandResult"）。
//
// ⚠️ 为什么要把它导出：判定约定那条规则（CheckVerdictConvention）拿它当输入，
// 而「**这个集合本身对不对**」是每个服务仓自己的事 —— 哪个类型该是答复、
// 哪个只是嵌套的行类型、哪个是留痕的行类型（不是答复），这些名字是**各服务
// 自己的判据**，底座不知道 ⇒ 底座只负责把集合扫出来，判留给每个服务仓。
func AnswerTypes(t *testing.T, root string, models, sources []string) map[string]bool {
	t.Helper()
	root = absRoot(t, root)
	return answerTypes(t, root, sources, modelPackages(root, models))
}

// contractType 是生成契约模型里的一个 struct。
type contractType struct {
	pkg  string // 模型包名（jmsms / jmsexec / …）
	name string
	// goFields 把 **Go 字段名** 映射到字段的 Go 类型。这些是反射查的名字。
	goFields map[string]string
	// jsonFields 把 **JSON 名** 映射到字段的 Go 类型。这些是 agent 读的名字。
	jsonFields map[string]string
}

// contractModelsOf 解析生成的契约模型。
//
// map 的键是类型的全名——包名 + 类型名——因为光一个类型名在两个模型之间
// 不唯一，而分不清两个类型的守卫是在猜。
func contractModelsOf(t *testing.T, root string, models []string) map[string]contractType {
	t.Helper()
	out := map[string]contractType{}
	for _, dir := range models {
		for _, path := range generatedModelFiles(t, filepath.Join(root, dir)) {
			for _, ct := range contractTypes(t, path) {
				out[ct.pkg+"."+ct.name] = ct
			}
		}
	}
	return out
}

// modelPackages 说出契约模型包的包名（模型目录名的 basename）。
//
// ⚠️ 它是**从模型目录推出来的**，不是写死的一份名单：答复类型只认本仓
// 自己的契约模型包，写死名单会让新服务加进来时漏掉（而漏掉的方向是
// 「不检查」，正是最坏的方向）。
func modelPackages(root string, models []string) map[string]bool {
	out := map[string]bool{}
	for _, dir := range models {
		out[filepath.Base(filepath.Clean(dir))] = true
	}
	return out
}

// generatedModelFiles 列出一个模型目录里的 thriftgo 产物。
//
// 生成文件是按**文件头**认的，不是按名字：契约按 IDL 域拆成了若干文件，
// 这里写一份名单，就会在加一个域文件时烂掉。（机械在 pkg/contractscan ——
// 三份契约守卫共用的那套机械。）
func generatedModelFiles(t *testing.T, dir string) []string {
	t.Helper()
	out, err := contractscan.GeneratedFiles(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(out) == 0 {
		t.Fatalf("no thriftgo output under %s: the model moved, and the guard "+
			"would be reading nothing", dir)
	}
	sort.Strings(out)
	return out
}

// answerTypes 找出作为工具**答复**的契约类型。
//
// 它们是扫 handler 找出来的：每个工具都在那里声明自己答复的形状，
// 而只有**直接的**答复算数——`render.ListOf[...]` 里的行类型不是答复
// （反射读的是信封），嵌套类型也不是。
func answerTypes(t *testing.T, root string, sources []string, modelPkgs map[string]bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, dir := range sources {
		paths, err := filepath.Glob(filepath.Join(root, dir, "*.go"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		if len(paths) == 0 {
			t.Fatalf("no handler sources under %s", dir)
		}
		for _, path := range paths {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name, args := schemaCall(call.Fun)
				if name != "Schema" || len(args) == 0 {
					return true
				}
				pkg, typeName, ok := contractTypeRef(args[0], modelPkgs)
				if !ok {
					return true
				}
				out[pkg+"."+typeName] = true
				return true
			})
		}
	}
	return out
}

// schemaCall 读一个 `render.Schema[...]` / `render.ListOf[...]` 表达式，
// 交出名字与类型参数。
func schemaCall(fun ast.Expr) (string, []ast.Expr) {
	switch f := fun.(type) {
	case *ast.IndexExpr:
		sel, ok := f.X.(*ast.SelectorExpr)
		if !ok {
			return "", nil
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "render" {
			return "", nil
		}
		return sel.Sel.Name, []ast.Expr{f.Index}
	case *ast.IndexListExpr:
		sel, ok := f.X.(*ast.SelectorExpr)
		if !ok {
			return "", nil
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "render" {
			return "", nil
		}
		args := make([]ast.Expr, 0, len(f.Indices))
		for _, idx := range f.Indices {
			args = append(args, idx)
		}
		return sel.Sel.Name, args
	}
	return "", nil
}

// contractTypeRef 读一个契约类型的引用（`jmsms.Xxx`）。
//
// 它**不**往泛型信封里看：`render.ListOf[jmsms.Xxx]` 说的是列表里的**行**，
// 而答复是那个信封。
func contractTypeRef(e ast.Expr, modelPkgs map[string]bool) (string, string, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return "", "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	if !modelPkgs[pkg.Name] {
		return "", "", false
	}
	return pkg.Name, sel.Sel.Name, true
}

// contractTypes 解析一个生成的契约模型，返回它的 struct。
//
// 解析本身（哪些是 Go 名字、哪些是 JSON 名字、类型读起来什么样）在
// pkg/contractscan —— 三份契约守卫共用的那套机械。这里是**判据**：
// 只有 struct 带着判定，而判定按**名字**查。
func contractTypes(t *testing.T, path string) []contractType {
	t.Helper()
	types, err := contractscan.Declared([]string{path})
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []contractType
	for _, ty := range types {
		if !ty.Struct {
			continue
		}
		out = append(out, contractType{
			pkg:        ty.Pkg,
			name:       ty.Name,
			goFields:   ty.GoTypes(),
			jsonFields: ty.JSONTypes(),
		})
	}
	return out
}
