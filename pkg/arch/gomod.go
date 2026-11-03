package arch

// 从原仓 internal/arch/gomod_test.go 搬来的守卫体。
//
// 守着这个仓自己的依赖接线。
//
// 沙箱挡掉了 Go 的 module cache 解包时需要的 rename(2)。那过去是用指向
// ~/go/pkg/mod 下已解包副本的 `replace` 绕过去的——那让 go.mod 与机器
// 绑定（绝对路径），让 `go list -m` 报的是路径而不是版本，也让 require 行
// 里的版本号变成一个标签而不是一个事实。
//
// replace 已经没了。依赖现在按普通方式解析：module cache 里有它，go.sum
// 钉住它的内容，构建全程不需要网络。于是有三件事必须保持同步，而工具链
// 一件也不查：
//
//   - go.mod 的 require 清单说要哪个版本；
//   - go.sum 钉住那个版本的内容，于是 cache 不会漂；
//   - 恢复脚本说哪些副本可以在 cache 被清空时放回去。
//
// 它们一漂，失败是安静而且费解的：go.sum 里缺一个版本，构建就会去够
// 网络，而沙箱拒绝它——报出来的错指向一条在这里根本跑不了的 `go get`。
import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// CheckDependencyPinning 让依赖的接线保持同步。
//
// ⚠️ restoreScript 是**可的**：kit 没有恢复脚本（kit 的依赖由两个服务
// 仓一起恢复），空串 ⇒ 那一条不跑，其余三条照跑。⚠️ 少了的覆盖要写在
// 汇报里，不许装作还在。
func CheckDependencyPinning(t *testing.T, root, restoreScript string) {
	t.Helper()
	root = absRoot(t, root)
	goModPath := filepath.Join(root, "go.mod")
	goSumPath := filepath.Join(root, "go.sum")

	require := parseRequire(t, goModPath)
	sum := parseGoSum(t, goSumPath)
	for path, version := range require {
		_, okH := sum[path+" "+version]
		_, okM := sum[path+" "+version+"/go.mod"]
		if !okH || !okM {
			t.Errorf("%s %s is not pinned by go.sum (content hash: %v, go.mod hash: %v): "+
				"the build would have to fetch it, and the sandbox refuses to write "+
				"into the module cache", path, version, okH, okM)
		}
	}

	// The restore script is optional: a repository without one has nothing
	// to keep in step.
	if restoreScript != "" {
		restorePath := restoreScript
		if !filepath.IsAbs(restorePath) {
			restorePath = filepath.Join(root, restoreScript)
		}
		restored := parseRestoreList(t, restorePath)
		for path, version := range require {
			key := path + "@" + version
			if _, ok := restored[key]; !ok {
				t.Errorf("%s is in go.mod but not in %s: if the module cache is "+
					"wiped, this one cannot be put back", key, restoreScript)
			}
		}
		for key := range restored {
			at := strings.LastIndex(key, "@")
			path, version := key[:at], key[at+1:]
			want, ok := require[path]
			if !ok {
				t.Errorf("%s is in %s but not in go.mod", key, restoreScript)
				continue
			}
			if want != version {
				t.Errorf("%s: %s restores v%s but go.mod wants v%s", key, restoreScript, version, want)
			}
		}
	}

	// A replace that points into this machine's module cache works here and
	// nowhere else.
	body, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read %s: %v", goModPath, err)
	}
	re := regexp.MustCompile(`^replace\s+(\S+)\s+=>\s+(\S+)`)
	for _, line := range strings.Split(string(body), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		target := m[2]
		if filepath.IsAbs(target) {
			t.Errorf("%s: replace points at the absolute path %q: "+
				"it works on this machine and nowhere else", m[1], target)
		}
	}

	// The end-to-end check: the build must not need the network, so every
	// dependency it compiles has to be unpacked in the module cache already.
	cache := os.Getenv("GOMODCACHE")
	if cache == "" {
		out, err := exec.Command("go", "env", "GOMODCACHE").Output()
		if err != nil {
			t.Skipf("cannot ask the toolchain for GOMODCACHE: %v", err)
		}
		cache = strings.TrimSpace(string(out))
	}
	for path, version := range require {
		dir := filepath.Join(cache, filepath.FromSlash(path)+"@"+version)
		if _, err := os.Stat(dir); err != nil {
			t.Errorf("%s %s is not unpacked in the module cache (%s): "+
				"the build would have to fetch it", path, version, dir)
		}
	}
}

// parseRequire 读出 go.mod 里的 require 指令。
func parseRequire(t *testing.T, goModPath string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read %s: %v", goModPath, err)
	}
	require := map[string]string{}
	inRequire := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "require (" {
			inRequire = true
			continue
		}
		if inRequire && trimmed == ")" {
			inRequire = false
			continue
		}
		if !inRequire {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 && !strings.HasPrefix(fields[0], "//") {
			require[fields[0]] = fields[1]
		}
	}
	if len(require) == 0 {
		t.Fatalf("no require directives found in %s", goModPath)
	}
	return require
}

// parseGoSum 读 go.sum 成「<module> <version>」→ hash。
func parseGoSum(t *testing.T, goSumPath string) map[string]string {
	t.Helper()
	body, err := os.ReadFile(goSumPath)
	if err != nil {
		t.Fatalf("read %s: %v", goSumPath, err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		out[fields[0]+" "+fields[1]] = fields[2]
	}
	return out
}

// parseRestoreList 读出恢复脚本里的 MODULES 数组。
func parseRestoreList(t *testing.T, restorePath string) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(restorePath)
	if err != nil {
		t.Fatalf("read %s: %v", restorePath, err)
	}
	out := map[string]bool{}
	inList := false
	for _, line := range strings.Split(string(body), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "MODULES=(") {
			inList = true
			continue
		}
		if inList && trimmed == ")" {
			break
		}
		if inList {
			if m := regexp.MustCompile(`"([^"]+)"`).FindStringSubmatch(trimmed); m != nil {
				out[m[1]] = true
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no MODULES list found in %s", restorePath)
	}
	return out
}
