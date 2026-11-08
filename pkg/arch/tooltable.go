package arch

// The doc-table guard: the tool names an agent reads in the docs must be
// the tools the server actually registers — mechanically, not by memory.
//
// 0.12.0's jmsx_put_dir added one registration and SIX hand-edited doc
// spots; every future add/rename/delete will rot the same way until the
// comparison is a test. Docs opt in by framing the enumeration with
// <!-- jms-tools --> ... <!-- /jms-tools -->; prose outside the markers
// is never scanned.

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// toolNameRE matches the fleet's tool-name vocabulary: jmsx_* (execution
// plane) and jms_* (management plane). \b keeps jms.Risk_read (dotted)
// out while jms_job_run matches.
var toolNameRE = regexp.MustCompile(`\bjmsx?_[a-z0-9_]+\b`)

// CheckToolTableMatchesRegistry 让文档标记块里的工具名集合与注册表
// 机械一致：
//
//   - 注册表里的每个名字必须出现在某个标记块中（缺 = 文档没说它有）；
//   - 标记块里的每个名字必须在注册表里（多 = 文档说了个不存在的，
//     或该工具被删/改名后文档没跟上）；
//   - conditional 里的名字允许只出现在文档侧：「有凭据才注册」的例外
//     （执行面的 jmsx_inventory），以及跨面引用（执行面文档提到管理面的
//     jms_job_run）——注册表不承诺它们，文档提它们不算漂移。
func CheckToolTableMatchesRegistry(t *testing.T, root string, registry, conditional []string) {
	t.Helper()
	for _, v := range toolTableViolations(root, registry, conditional) {
		t.Errorf("%s", v)
	}
}

// toolTableViolations is the guard's testable core: it returns the
// violation lines instead of reporting them, so the self-test asserts on
// the lines without standing up a fake *testing.T (which Go does not let
// us substitute for the real one).
func toolTableViolations(root string, registry, conditional []string) []string {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return []string{"abs " + root + ": " + err.Error()}
	}
	inDocs := map[string]bool{}
	mds, err := mdFiles(rootAbs)
	if err != nil {
		return []string{"walk " + rootAbs + ": " + err.Error()}
	}
	for _, f := range mds {
		body, err := os.ReadFile(f)
		if err != nil {
			return []string{"read " + f + ": " + err.Error()}
		}
		for _, block := range markedBlocks(string(body)) {
			for _, m := range toolNameRE.FindAllString(block, -1) {
				inDocs[m] = true
			}
		}
	}
	var out []string
	if len(inDocs) == 0 {
		out = append(out, "no <!-- jms-tools --> block names a single tool: "+
			"the docs are not opted in, so this guard has nothing to check")
	}
	cond := map[string]bool{}
	for _, c := range conditional {
		cond[c] = true
	}
	reg := map[string]bool{}
	var missing, extra []string
	for _, name := range registry {
		reg[name] = true
		if !inDocs[name] {
			missing = append(missing, name)
		}
	}
	for name := range inDocs {
		if !reg[name] && !cond[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	for _, m := range missing {
		out = append(out, "registered tool "+m+" is not named in any "+
			"<!-- jms-tools --> block: the docs an agent reads do not "+
			"mention a tool it can call")
	}
	for _, e := range extra {
		out = append(out, "docs name "+e+", but nothing registers it: "+
			"stale table entry (tool renamed or deleted without updating the docs)")
	}
	return out
}

// markedBlocks returns the text between each <!-- jms-tools --> and its
// <!-- /jms-tools -->, in order.
func markedBlocks(body string) []string {
	var out []string
	for {
		i := strings.Index(body, "<!-- jms-tools -->")
		if i < 0 {
			return out
		}
		rest := body[i+len("<!-- jms-tools -->"):]
		j := strings.Index(rest, "<!-- /jms-tools -->")
		if j < 0 {
			out = append(out, rest)
			return out
		}
		out = append(out, rest[:j])
		body = rest[j+len("<!-- /jms-tools -->"):]
	}
}

// mdFiles lists the markdown files under root — the same walk discipline
// as the other guards (skip .git, legacy and generated trees).
func mdFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "legacy", "kitex_gen", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(info.Name(), ".md") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// ⚠️ 纪律（本注释即约定）：registry 参数必须是**测试里现搭的注册表**——
// reg.New + 真实的 Register 调用序列 + r.Specs() 取名。手抄的名字列表
// 与 policy 表无机械关联，抄错一个 Register 调用守卫不知道（两个服务
// 的接线都在 internal/arch 的测试里，照抄即可）。前缀词汇是 jms_/jmsx_
// 两个（TestToolNameRegexVocabulary 钉住）；换/加前缀要同步改正则与
// 该测试。
