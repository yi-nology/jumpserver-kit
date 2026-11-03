package arch

// 从原仓 internal/arch/version_test.go 搬来的守卫体。
//
// 管的是 JumpServer 的**版本**——更准确地说，管的是部署**可能没有**的那些
// 能力。
//
// JumpServer v4 与 v5 在这里要紧的地方几乎一致：端点表、认证头、
// connection-token 的请求体、响应形状。不一致的是 Chat AI 委派方案
// （delegation scheme）——v4 压根没有它，而这一条差别有一个看得见的后果
// （v4 上的会话以 API 凭据的权限跑，因为没有更窄的凭据可用）。
//
// 所以差别只写**一遍**，写在 pkg/jmsapi/capability.go 里，这些守卫负责
// 保证两个面都不会悄悄地各自长出一份：
//
//   - 两个面都得暴露这个设置与那些凭据替代品，这样「管理面知道 v4 而
//     执行面不知道」就不可能发生；
//   - 能力方案的**调用点**必须先问部署**有没有**这个能力。
//
// 后一条才是厉害的那条，而且它是**控制流**的问题，不是文本的问题。
// 门禁就是一个 `if`，而一个没带门禁就加进来的调用点会产出一个
// 读起来像「凭据错了」的 401 ——从外面诊断这个错误非常贵。
//
// ⚠️ 监视名单来自 pkg/jmsapi 的能力声明，**不是**这里手抄的一份。
// 一份手抄的函数名清单正是那种会被重构落在后面的东西——而且它会**静默地**
// 落在后面：守卫不再报，而所有人都相信还有东西在被看着。
//
// ⚠️ 它仍然**抓不住**的东西：门禁在、位置也对，但效果被中和了
// （`MayPresent(...) || true`）。那是故意的破坏，没有便宜的机械检查能抓
// ——所以这里把它写出来，而不是假装没有。
import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/jmsapi"
)

// 一个能力的三个状态，守卫看到的样子。
//
// ⚠️ 它们是**名字**，因为守卫读的是语法树：它没法求值
// `jmsapi.CapabilityPresent` 并由此知道那意味着「存在」。
// ⇒ 这些名字由 CheckCapabilityVocabulary 拿去对着 pkg/jmsapi 核对，
// 于是那里的改名在这里是一次**响亮的失败**，而不是一次悄悄变弱的守卫。
const (
	// presentStateName 是「部署**有**这个能力」的那个状态。
	presentStateName = "CapabilityPresent"
	// absentStateName 是「部署**没有**这个能力」的那个状态。
	absentStateName = "CapabilityAbsent"
	// unknownStateName 是「**没能确定**」的那个状态。
	unknownStateName = "CapabilityUnknown"
)

// CheckVersionSettings 让两个面在版本设置上保持一致。
//
// 一个面知道而另一个面不知道的版本，是一个在某种部署上对、在另一种部署上
// 错的版本——而错的那一种，是会话以管理员权限跑、却没有人被告知的那一种。
//
// ⚠️ settings 是**列出来**的，不是推出来的：这条守卫的点就在于这些设置
// **存在**；从代码推出它们只能说明代码与它自己一致。
func CheckVersionSettings(t *testing.T, root string, planes map[string]string, settings []string) {
	t.Helper()
	root = absRoot(t, root)
	for name, dir := range planes {
		for _, setting := range settings {
			if !packageMentionsEnv(t, filepath.Join(root, dir), setting) {
				t.Errorf("the %s does not read %s: the two planes must agree on what "+
					"the deployment is and how it is reached", name, setting)
			}
		}
	}
}

// CheckCapabilityVocabulary 管住能力模型的那份**词汇**，以及它带来的门禁。
//
// ⚠️ 它做四件事：
//
//  1. 状态词汇（CapabilityPresent / CapabilityAbsent / CapabilityUnknown）
//     必须仍由协议层声明 —— 守卫读语法树，只能按**名字**认状态。
//  2. 版本词汇（VersionV4 / VersionV5 / versionAuto）必须仍由协议层声明。
//  3. 监视名单里的每个函数名都必须**真的存在** —— 否则守卫匹配不到任何
//     调用点，什么都不查，还报绿。
//  4. **门禁**：每个呈现能力凭据的调用点都必须先问部署有没有这个能力。
//
// ⚠️ 1–3 只在**本仓有协议层**时才有意义（协议层在 kit 里），4 在每个仓都
// 要跑（调用点在服务仓里）。
//
// ⚠️ 4 是原仓最厉害的一条守卫，规格的导出清单里没有单列它——放在这里，
// 是因为它必须**每个仓都跑**，而放哪儿都得有人记得调用它。
func CheckCapabilityVocabulary(t *testing.T, root, modulePath string) {
	t.Helper()
	root = absRoot(t, root)

	if f, ok := protocolLayerFile(t, root, modulePath, "capability.go"); ok {
		checkStateVocabulary(t, f)
		// ⚠️ 监视名单住在它所描述的能力**旁边** ⇒ 它由**声明能力的那棵树**
		// 来查。服务仓里没有那份声明，在那里查它只会得到「函数不存在」
		// 这种假失败（函数在 kit 的 pkg/jmsapi 里）。
		checkWatchListNamesRealFunctions(t, root)
	} else if hasProtocolLayer(t, root, modulePath) {
		// ⚠️ 这棵树**有**协议层，却没找到那份声明 ⇒ 守卫自己坏了。
		//    报绿的话，改掉 pkg/jmsapi 的状态词都不会有人听见。
		t.Errorf("the protocol layer is here (%s/pkg/jmsapi) but capability.go was not found: "+
			"the guard would check nothing, and it would say so in a log line nobody reads",
			modulePath)
	} else {
		t.Logf("this repository has no protocol layer (%s/pkg/jmsapi): the capability "+
			"vocabulary is declared in the kit, and this guard checks it there",
			modulePath)
	}
	if f, ok := protocolLayerFile(t, root, modulePath, "version.go"); ok {
		checkReleaseVocabulary(t, f)
	} else if hasProtocolLayer(t, root, modulePath) {
		t.Errorf("the protocol layer is here (%s/pkg/jmsapi) but version.go was not found: "+
			"the release vocabulary would not be checked at all", modulePath)
	}
	checkCapabilityGates(t, root)
}

// checkStateVocabulary 让守卫的名字保持诚实。
//
// ⚠️ 守卫读语法树，所以只能按**名字**认一个状态——它没法求值
// `jmsapi.CapabilityPresent` 并知道那意味着「存在」。⇒ 如果 pkg/jmsapi
// 改了状态的名字，守卫就认不出那些拿它做比较的门禁了。
//
// ⇒ 所以名字在这里被核对：pkg/jmsapi 里的改名是守卫里的一次**响亮的
// 失败**，而不是一次悄悄变弱的守卫。（失败的方向要紧：守卫看不见的门禁
// 会被报成「没有门禁」，那是安全的；但守卫也会因此**不再抓住**一个拿错了
// 状态做比较的门禁，那不是安全的。）
func checkStateVocabulary(t *testing.T, file string) {
	t.Helper()
	declared := constNames(t, file)
	for _, name := range []string{presentStateName, absentStateName, unknownStateName} {
		if !declared[name] {
			t.Errorf("the guard expects a state named %q, and pkg/jmsapi does not declare it: "+
				"the guard would stop recognising the gates that compare against it, and would "+
				"stop catching a gate that compares against the wrong one", name)
		}
	}
}

// checkReleaseVocabulary 让守卫认得住那些版本名。
//
// ⚠️ 守卫读语法树，所以只能按**名字**认一个版本。⇒ 如果 pkg/jmsapi 改了
// 其中一个的名字，守卫就看不见它要找的东西——而且会**不再报告**，那是
// 危险的方向（没人看得见的规则就是没人守的规则）。
//
// ⇒ 所以名字在这里被核对：pkg/jmsapi 里的改名是守卫里的一次响亮失败。
func checkReleaseVocabulary(t *testing.T, file string) {
	t.Helper()
	declared := constNames(t, file)
	for _, name := range releaseNames {
		if !declared[name] {
			t.Errorf("the guard expects a release named %q, and pkg/jmsapi does not declare it: "+
				"the guard would stop seeing the releases it is there to keep out of the control flow",
				name)
		}
	}
}

// checkWatchListNamesRealFunctions 让监视名单保持诚实。
//
// 「呈现某能力凭据的那些调用」是一份**名字**清单，而名字会变陈：把函数
// 改名，清单就指着不存在的东西——于是守卫匹配不到任何调用点，什么都不查，
// 然后报绿。
//
// ⚠️ 那是一个守卫能有的**最坏**的失败方式：它不说「我坏了」，它说「一切
// 正常」。所以这份清单对着代码核对：清单里的每个名字都必须仍是 somebody
// 声明的函数。
//
// ⚠️ 它仍然是一份手写清单——只是它住在它所描述的能力**旁边**，改名与清单
// 在同一个地方，而这条断言把一条陈旧的清单变成一次响亮的失败，而不是一次
// 静悄悄的失败。
func checkWatchListNamesRealFunctions(t *testing.T, root string) {
	t.Helper()
	declared := map[string]bool{}
	for _, f := range goFilesOrFatal(t, root) {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", Relative(root, f), err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			declared[fn.Name.Name] = true
		}
	}
	for _, decl := range jmsapi.CapabilityDeclarations() {
		for _, name := range decl.SchemeCalls {
			if !declared[name] {
				t.Errorf("the %s capability's watch list names %q, and no function by that "+
					"name exists any more: the guard would match no call site, check nothing "+
					"and report green", decl.Capability, name)
			}
		}
	}
}

// checkCapabilityGates 是对**门禁**的守卫。
//
// 每个呈现某能力凭据的调用点都必须先问部署**有没有**这个能力——而且这个
// 问题必须问成守卫**读得懂**的形状，否则守卫没法替它背书。
//
// ⚠️ 认可的形状是：
//
//   - 凭据调用在某个 `if` 的**主体**里，而这个 `if` 问的就是能力问题，
//     并且它跑的那条分支正是「能力存在」的那条；
//   - 或者前面有一条**卫语句**：一个说「不存在」并离开函数的 `if`，凭据
//     调用在它后面。
//
// 两个都没有，一个没有该方案的部署（v4）就会收到一个它读不懂的凭据，
// 而回来的 401 会被归类成「connection-token 方案不可用」：于是每个会话都
// 走慢的 koko 终端路径，为一个并不存在的原因。
//
// 方案自己的 API 是豁免的：一个**以方案命名**的函数（DelegationRequest 及其
// 同类）就是方案本身，不是它的调用点。
func checkCapabilityGates(t *testing.T, root string) {
	t.Helper()
	for _, decl := range jmsapi.CapabilityDeclarations() {
		scheme := map[string]bool{}
		for _, name := range decl.SchemeCalls {
			scheme[name] = true
		}
		for _, f := range goFilesOrFatal(t, root) {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), f, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", Relative(root, f), err)
			}
			imports := packageNames(file)
			for _, fnDecl := range file.Decls {
				fn, ok := fnDecl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				visitFuncBody(fn.Name.Name, fn.Body, scheme, imports,
					func(scopeName string, body *ast.BlockStmt, call *ast.CallExpr) {
						if scheme[scopeName] {
							return // the scheme's own API
						}
						if !dominatedByGate(body, call, decl.Const, imports) {
							t.Errorf("%s: %s() presents the %s credential without asking "+
								"whether the deployment has it: on a deployment without the "+
								"scheme the credential comes back 401 and every session is "+
								"sent down the slow terminal path",
								Relative(root, f), scopeName, decl.Capability)
						}
					})
			}
		}
	}
}

// visitFuncBody 走一个像函数的主体，报出它做的调用。
//
// 一个**闭包**是它自己的作用域：里面的调用只属于它，不属于别的。
// 没有这一点，注册 handler 的那个函数里的闭包里的调用也会被算到那个函数
// 头上——而保护它的门禁住在闭包里，于是外层函数看起来没有门禁。
func visitFuncBody(name string, body *ast.BlockStmt, names map[string]bool,
	imports map[string]bool,
	fn func(scopeName string, body *ast.BlockStmt, call *ast.CallExpr)) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.FuncLit:
			visitFuncBody(name, v.Body, names, imports, fn)
			return false // the outer walk must not descend into it again
		case *ast.CallExpr:
			if called := calledName(v); called != "" && names[called] {
				fn(name, body, v)
			}
		}
		return true
	})
}

// dominatedByGate 报告一个调用点是否被能力问题罩住了。
//
// 认可两种形状，它们正是代码里真正在用的两种：
//
//   - **被条件罩住**：调用在某个 `if` 的主体里，而这个 `if` 问的是能力
//     问题，且它跑的那条分支正是「能力存在」的那条。于是调用只在答案为
//     「是」时发生。
//   - **卫语句**：一个说「不存在」并在那条失败的分支上**返回**的 `if`
//     出现在调用之前。
//
// ⚠️ 取反要紧，取反错了就是整整一类静悄悄的漏判。这条规则的第一个版本
// 接受**任何**更早提到那个问题、且带一个 return 的 `if`——而一个主体是
// **成功分支**的 `if` 也带 return（错误路径要返回）。于是那样的 `if`
// 把这个函数里**后面所有**的调用点都标成被罩住了，而之后新加的调用点从
// 来没被报出来。
//
// 实测：在 mintConnectionToken 里那段已有的门禁之后加一个没有门禁的
// DelegationRequest() ⇒ 守卫仍然是绿的。
//
// ⇒ 所以第二种形状要求那个问题被**反着**问（`!c.MayPresent(...)`、
// `state != CapabilityPresent`，或者 `!ok` 而 `ok` 是从那个问题绑来的），
// 那才是一条卫语句真正的样子。
func dominatedByGate(body *ast.BlockStmt, call *ast.CallExpr, constName string,
	imports map[string]bool) bool {
	gated := false
	ast.Inspect(body, func(n ast.Node) bool {
		ifs, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		if !gateInIf(ifs, constName, imports) {
			return true
		}
		bound := gateBoundNames(ifs.Init, constName, imports)
		if containsCall(ifs.Body, call) {
			// The call is inside the guarded block — but only if the
			// running branch is the one where the capability IS present.
			// A gate that compares against the wrong state (==
			// CapabilityAbsent) is not a gate: it presents the
			// credential exactly when the deployment lacks it.
			if gatePolarity(ifs.Cond, constName, imports, bound) {
				gated = true
				return false
			}
		}
		if ifs.Pos() < call.Pos() && guardClause(ifs, constName, imports) {
			gated = true
		}
		return true
	})
	return gated
}

// gateInIf 报告一个 `if` 是否在问能力。
//
// ⚠️ 问题问在 `if` 的 **INIT** 里，不在它的条件里：代码写的是
// `if ok, _ := c.DelegationAvailable(ctx); !ok {` ——门禁是初始化式，
// 条件是答案的用法。只看条件的守卫根本看不到门禁。
func gateInIf(ifs *ast.IfStmt, constName string, imports map[string]bool) bool {
	if ifs.Init != nil && nodeAsksCapability(ifs.Init, constName, imports) {
		return true
	}
	return exprAsksCapability(ifs.Cond, constName, imports)
}

// stateCmp 是「能力的主体」与「三个状态之一」的一次比较。
type stateCmp struct {
	op     token.Token
	marker string // "present" / "absent" / "unknown"
}

// stateComparisons 收集「能力的主体」与「三个状态之一」之间的比较。
//
// ⚠️ 搜的是**整个条件**，不只是它最外层。
//
// ⚠️ 为什么：一个写成 `dc != nil && state == CapabilityAbsent` 的门禁把
// 比较藏在一层之下，而只看最外层的守卫会读成这个条件的**真值**——于是
// 接受一个恰好在能力缺失时呈现凭据的门禁。
//
// ⇒ 那是一个真实的洞，是靠一次变异抓出来的（有人问这条守卫还有没有牙齿，
// 答案「不是到处都有」）。
func stateComparisons(expr ast.Expr, constName string, imports map[string]bool,
	bound map[string]bool) []stateCmp {
	var out []stateCmp
	ast.Inspect(expr, func(n ast.Node) bool {
		bin, ok := n.(*ast.BinaryExpr)
		if !ok {
			return true
		}
		if bin.Op != token.EQL && bin.Op != token.NEQ {
			return true
		}
		left, right := stateMarker(bin.X), stateMarker(bin.Y)
		switch {
		case left != "" && isCapabilitySubject(bin.Y, constName, imports, bound):
			out = append(out, stateCmp{op: bin.Op, marker: left})
		case right != "" && isCapabilitySubject(bin.X, constName, imports, bound):
			out = append(out, stateCmp{op: bin.Op, marker: right})
		}
		return true
	})
	return out
}

// gatePolarity 判定 `if` 跑的那条分支是不是「能力存在」的那条。
//
// ⚠️ 三值的事实必须拿一个**状态**比，而只有一种比较意味着「存在」：
// `== CapabilityPresent`。另外两种（`== CapabilityAbsent`、
// `== CapabilityUnknown`）意味着相反，而 `!= CapabilityPresent` 意味着
// 跑的那条分支是**没有**它的那条。
//
// ⇒ 比较是**精确**读的；一个**没有**状态比较的条件按它的真值算
// （「问题答了是」⇒ 能力可以用）。
//
// ⚠️ 这就是让门禁保持诚实的那道检查。没有它，一个拿**错状态**比较的门禁
// 会通过守卫——而且它恰好会在能力缺失的地方呈现凭据。
//
// ⚠️ 这道检查的**边界**是写出来的，不是藏起来的：一个**布尔**问题
// （`MayPresent(...)`）根本没法检查极性（守卫分不清「我可以呈现吗？」与
// 「它存在吗？」）——所以布尔门禁按真值接受。三值形式**是**被检查的，
// 而且它必须把跑的那条分支放在「存在」的世界里。
func gatePolarity(cond ast.Expr, constName string, imports map[string]bool,
	bound map[string]bool) bool {
	cmps := stateComparisons(cond, constName, imports, bound)
	if len(cmps) == 0 {
		// No state comparison ⇒ the question's truthiness decides.
		return true
	}
	for _, c := range cmps {
		if c.op != token.EQL || c.marker != "present" {
			return false
		}
	}
	return true
}

// guardClause 报告一个 `if` 是不是卫语句：它说「不存在」，并在那条
// 失败的分支上离开函数。
//
// ⚠️ 两半都要。没有那个取反，一个主体是**成功分支**（因而在自己的错误
// 路径上返回）的 `if` 也会算成卫语句——于是它会罩住这个函数里后面所有
// 的调用点，这正是这条规则的早期版本漏掉整整一类没有门禁的调用点的原因。
func guardClause(ifs *ast.IfStmt, constName string, imports map[string]bool) bool {
	if !bodyReturns(ifs.Body) {
		return false
	}
	bound := gateBoundNames(ifs.Init, constName, imports)
	return notPresentTest(ifs.Cond, constName, imports, bound)
}

// notPresentTest 报告一个表达式说的是不是「能力**不**存在」。
//
// 三种形状，也正是代码里在用的三种：
//
//   - `!<问题>` —— 一个被取反的布尔问题；
//   - `<问题> != CapabilityPresent` —— 三值事实的比较；
//   - `!<名字>` —— 一个从问题绑来的名字被取反。
func notPresentTest(expr ast.Expr, constName string, imports map[string]bool,
	bound map[string]bool) bool {
	// A negated BOOLEAN question, or a negated name the question was bound
	// to. ⚠️ The polarity of a boolean question cannot be checked (the
	// guard cannot tell "may I present this?" from "is it present?"), so
	// these are accepted on their truthiness.
	if un, ok := expr.(*ast.UnaryExpr); ok && un.Op == token.NOT {
		if capabilityQuestion(un.X, constName, imports) {
			return true
		}
		if negatesBoundName(un.X, bound) {
			return true
		}
	}
	// The three-valued form: the condition must be true in the NOT-present
	// world and false in the present one ⇒ `!= CapabilityPresent`.
	cmps := stateComparisons(expr, constName, imports, bound)
	if len(cmps) == 0 {
		return false
	}
	for _, c := range cmps {
		if c.op != token.NEQ || c.marker != "present" {
			return false
		}
	}
	return true
}

// negatesBoundName 报告一个表达式是否取反了那些名字之一。
//
// `!ok`、`ok == false` 与 `ok != true` 说的都是「不」。
func negatesBoundName(expr ast.Expr, names map[string]bool) bool {
	switch e := expr.(type) {
	case *ast.UnaryExpr:
		if e.Op != token.NOT {
			return false
		}
		if id, ok := e.X.(*ast.Ident); ok && names[id.Name] {
			return true
		}
		return negatesBoundName(e.X, names)
	case *ast.BinaryExpr:
		if e.Op != token.EQL && e.Op != token.NEQ {
			return false
		}
		return exprIsAnyName(e.X, names) || exprIsAnyName(e.Y, names)
	}
	return false
}

// exprIsAnyName 报告一个表达式是不是那些名字之一。
func exprIsAnyName(expr ast.Expr, names map[string]bool) bool {
	id, ok := expr.(*ast.Ident)
	return ok && names[id.Name]
}

// isCapabilitySubject 报告一个表达式是不是能力问题本身，
// 或者是一个从它绑来的名字。
func isCapabilitySubject(expr ast.Expr, constName string, imports map[string]bool,
	bound map[string]bool) bool {
	if capabilityQuestion(expr, constName, imports) {
		return true
	}
	if id, ok := expr.(*ast.Ident); ok && bound[id.Name] {
		return true
	}
	return false
}

// stateMarker 读出一个比较里说的状态（如果它说的是一个状态）。
//
// ⚠️ 状态是按**名字**认的，因为守卫读语法树，求不了常量。名字由
// CheckCapabilityVocabulary 拿去对着 pkg/jmsapi 核对，于是那里的改名是一次
// 响亮的失败，而不是一次悄悄变弱的守卫。
func stateMarker(expr ast.Expr) string {
	var name string
	switch e := expr.(type) {
	case *ast.Ident:
		name = e.Name
	case *ast.SelectorExpr:
		name = e.Sel.Name
	default:
		return ""
	}
	switch name {
	case presentStateName:
		return "present"
	case absentStateName:
		return "absent"
	case unknownStateName:
		return "unknown"
	}
	return ""
}

// gateBoundNames 列出一个能力问题被绑到了哪些名字上。
//
// `ok, _ := c.MayPresent(ctx, cap)` 绑 `ok`；然后条件说 `!ok`。
// `state := c.Profile(ctx).State(cap)` 绑 `state`；然后条件说
// `state != CapabilityPresent`。
func gateBoundNames(init ast.Stmt, constName string, imports map[string]bool) map[string]bool {
	out := map[string]bool{}
	assign, ok := init.(*ast.AssignStmt)
	if !ok {
		return out
	}
	found := false
	for _, rhs := range assign.Rhs {
		if capabilityQuestion(rhs, constName, imports) {
			found = true
		}
	}
	if !found {
		return out
	}
	for _, lhs := range assign.Lhs {
		if id, ok := lhs.(*ast.Ident); ok {
			out[id.Name] = true
		}
	}
	return out
}

// nodeAsksCapability 报告一个语句是否在问能力。
func nodeAsksCapability(stmt ast.Stmt, constName string, imports map[string]bool) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isCapabilityQuery(call, constName, imports) {
			found = true
			return false
		}
		return true
	})
	return found
}

// exprAsksCapability 报告一个表达式是否在问能力。
func exprAsksCapability(expr ast.Expr, constName string, imports map[string]bool) bool {
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok && isCapabilityQuery(call, constName, imports) {
			found = true
			return false
		}
		return true
	})
	return found
}

// capabilityQuestion 报告一个表达式是否在问能力。
func capabilityQuestion(expr ast.Expr, constName string, imports map[string]bool) bool {
	return exprAsksCapability(expr, constName, imports)
}

// isCapabilityQuery 报告一个调用是不是「部署**有**这个能力吗」这个问题。
//
// 规则是**形状**，不是名字：关于能力的问题是一个**方法调用**（它有接收者
// ——那个客户端），而它的参数带着这个能力的常量。⇒ 守卫认的是**问题**
// 本身，不是某个助手的名字，所以执行侧可以问「我可以呈现这个吗？」而
// 上报侧问「它有这个吗？」，**两者**都算门禁。
//
// ⚠️ 「必须有接收者」是把普通的包函数挡在外面的那一条：
// CostOf(cap) 也提到那个常量，而它是一个**答案**，不是一个问题。
func isCapabilityQuery(call *ast.CallExpr, constName string, imports map[string]bool) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false // a plain function call is not a question about the deployment
	}
	// ⚠️ A PACKAGE function is not a question either — and this is where
	// the hole was: `jmsapi.CostOf(jmsapi.CapDelegation)` names the
	// constant, so the old rule counted it as the question, and a call
	// site could hide an UNGATED credential call behind it:
	//
	//	if ok := jmsapi.CostOf(jmsapi.CapDelegation); ok != "" {
	//	    c.DelegationRequest(call)   // ← never gated, and the guard said
	//	}                               //   it was
	//
	// ⇒ The receiver of a package function is the PACKAGE, and a package
	// cannot be asked anything.
	if id, ok := sel.X.(*ast.Ident); ok && imports[id.Name] {
		return false
	}
	for _, arg := range call.Args {
		// The constant is written `jmsapi.CapDelegation` (a selector) or
		// `CapDelegation` (an ident, inside the package itself) — both name
		// the same constant.
		switch a := arg.(type) {
		case *ast.Ident:
			if a.Name == constName {
				return true
			}
		case *ast.SelectorExpr:
			if a.Sel.Name == constName {
				return true
			}
		}
	}
	return false
}

// packageNames 返回这个文件里各包被导入时用的名字。
//
// ⚠️ 守卫需要它们来分辨「包函数」与「方法调用」。
//
// ⚠️ 包的名字不总是导入路径的最后一段（`gopkg.in/yaml.v3` 的包名是
// `yaml`），所以有别名时用文件写的别名，否则用路径的最后一段。⇒ 一个包名
// 不跟随路径的包会溜过检查；本仓导入的那些都跟随。
func packageNames(file *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		} else {
			parts := strings.Split(path, "/")
			name = parts[len(parts)-1]
		}
		if name == "_" || name == "." {
			continue
		}
		out[name] = true
	}
	return out
}

// calledName 读出一个调用调的是哪个函数。
func calledName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// containsCall 报告一个主体里是否含有着**这一个**调用。
func containsCall(root ast.Node, target *ast.CallExpr) bool {
	found := false
	ast.Inspect(root, func(n ast.Node) bool {
		if n == ast.Node(target) {
			found = true
			return false
		}
		return true
	})
	return found
}

// bodyReturns 报告一个主体是否结束函数。
func bodyReturns(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if _, ok := n.(*ast.ReturnStmt); ok {
			found = true
			return false
		}
		return true
	})
	return found
}

// packageMentionsEnv 报告某个包的文件里是否带着某个设置的 env tag。
func packageMentionsEnv(t *testing.T, dir, setting string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		body := readFileOrFatal(t, filepath.Join(dir, e.Name()))
		if strings.Contains(body, `env:"`+setting+`"`) {
			return true
		}
	}
	return false
}

// readFileOrFatal 读一个文件，读不了就让测试失败。
func readFileOrFatal(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// constNames 列出一个文件里声明的常量名。
func constNames(t *testing.T, path string) map[string]bool {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	declared := map[string]bool{}
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, n := range vs.Names {
				declared[n.Name] = true
			}
		}
	}
	return declared
}

// protocolLayerFile 按 **import 路径**找出协议层的某个文件。
//
// ⚠️ 它按 import 路径找，不按目录名：协议层在哪个 module path 之下是
// 判据的一部分（服务仓里没有协议层，kit 里才有）。
func protocolLayerFile(t *testing.T, root, modulePath, name string) (string, bool) {
	t.Helper()
	// ⚠️ ImportPathOf **去掉 .go 后缀**（它给的是「读者会写的那个导入路径」，
	//    而导入路径不带文件名后缀）⇒ 拿带 .go 的名字去比，**永远不等**。
	//    ⚠️ 这不是笔误级别的事：它让下面三条检查**从不执行**，
	//    而守卫仍然报绿 —— 改名 pkg/jmsapi 的状态词都不会有人听见。
	want := modulePath + "/pkg/jmsapi/" + strings.TrimSuffix(name, ".go")
	for _, f := range goFilesOrFatal(t, root) {
		if ImportPathOf(modulePath, root, f) == want {
			return f, true
		}
	}
	return "", false
}

// hasProtocolLayer 报告这棵树里**有没有**协议层。
//
// ⚠️ 它是为了把两种「找不到」分开：
//   - 这棵树**真的没有**协议层（服务仓）⇒ 那三条检查不在这儿跑，正常；
//   - 这棵树**有**协议层（底座）却没找到那个文件 ⇒ **守卫出了故障**，
//     它该红，而不是在日志里说一句没人看的话。
func hasProtocolLayer(t *testing.T, root, modulePath string) bool {
	prefix := modulePath + "/pkg/jmsapi/"
	for _, f := range goFilesOrFatal(t, root) {
		if strings.HasPrefix(ImportPathOf(modulePath, root, f), prefix) {
			return true
		}
	}
	return false
}
