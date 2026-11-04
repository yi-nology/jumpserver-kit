package arch

// 一棵源码树：根目录 + 它的模块路径 + 人话名字（错误消息用）。
//
// ⚠️ 为什么要「树」而不是「目录」：拆成三个仓之后，有几条守卫**跨仓**：
// 底座的包必须被两个服务都用（可达性）、共用词汇必须被产出（产出者在服务仓里）、
// 能力的措辞不许在别处重写（三棵树都要看）。⇒ 这些守卫一次要看不止一棵树，
// 而每棵树都要说清「根在哪、module path 是什么、它是谁」。
//
// ⚠️ module path 不是装饰：三个仓的 module path **互为字符串前缀**
// （.../jumpserver-mgmt 是 .../jumpserver-exec 的前缀，差一个 "-"），
// 所以「某个 import 属于哪棵树」必须带尾斜杠比（见 IsImportOf）——
// 本文件是唯一知道这三个路径的地方，别在别处再抄一份。
import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// 三个仓的 module path。
//
// ⚠️ 这是**唯一**一份。两个服务仓与 kit 互为前缀，抄第二份就会开始漂，
// 而漂的那份决定守卫认不认得出「这个 import 越界了」。
const (
	// ModuleKit 是共用底座（协议层、门禁、契约、留痕、脱敏、风险分类）。
	ModuleKit = "github.com/yi-nology/jumpserver-kit"
	// ModuleManagement 是管理面。
	ModuleManagement = "github.com/yi-nology/jumpserver-mgmt"
	// ModuleExecution 是执行面。
	ModuleExecution = "github.com/yi-nology/jumpserver-exec"
)

// Tree 是一棵源码树：根目录 + 它的模块路径 + 人话名字（错误消息用）。
type Tree struct {
	Root       string
	ModulePath string
	Name       string
}

// Files 返回这棵树里的 Go 文件。
func (tr Tree) Files() ([]string, error) {
	return GoFiles(tr.Root)
}

// ImportPath 返回某个文件在这棵树里的 import 路径（读者会写的那个）。
func (tr Tree) ImportPath(path string) string {
	return ImportPathOf(tr.ModulePath, tr.Root, path)
}

// PackagePath 返回某个文件所属**包**的 import 路径。
//
// ⚠️ 它切掉最后一段：「pkg/reg/registry.go」属于包「…/pkg/reg」。
// 在最后一段斜杠处切会把每个包都塌成它的父目录，整条规则就空转了。
func (tr Tree) PackagePath(path string) string {
	return packagePathOf(tr.ImportPath(path))
}

// TreeAt 按 go.mod 里的 module 行认出一个仓。
//
// ⚠️ 它读的是 go.mod，不是目录名：兄弟仓在哪由环境决定，而「它是谁」
// 由 module path 决定（…/jumpserver-mgmt 与 …/jumpserver-exec 只差一个
// "-" ⇒ 目录名认不出来，module path 才认得出来）。
func TreeAt(root string) (Tree, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return Tree{}, err
	}
	gomod := filepath.Join(abs, "go.mod")
	body, err := os.ReadFile(gomod)
	if err != nil {
		return Tree{}, fmt.Errorf("read %s: %w", gomod, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 2 && fields[0] == "module" {
			return Tree{Root: abs, ModulePath: fields[1]}, nil
		}
	}
	return Tree{}, fmt.Errorf("%s: no module line in go.mod", gomod)
}

// packagePathOf 把一个 import 路径切成它所属的**包**的 import 路径。
//
// ⚠️ 它只用于 FILE 路径（先算 import 路径，再切最后一段）。
// 一个 import 路径**已经**是包路径（…/pkg/redact）⇒ 不能再切一次。
func packagePathOf(importPath string) string {
	if i := strings.LastIndex(importPath, "/"); i >= 0 {
		return importPath[:i]
	}
	return importPath
}
