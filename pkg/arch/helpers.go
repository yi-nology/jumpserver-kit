package arch

// 搬过来的守卫们共用的机械。
//
// ⚠️ 这些是「怎么读文件」的部分；「读出什么算违反」留在每个守卫身上
// （判据与文案都在守卫里，机械在底座——这是本仓早就有的分法）。
import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// absRoot 把仓根变成绝对路径。
//
// ⚠️ 它是必要的：守卫读到的文件路径必须能和仓根比，否则「相对仓根的路径」
// 算不出来（相对基路径与绝对目标路径不能混着比）。
func absRoot(t *testing.T, root string) string {
	t.Helper()
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("resolve the repository root: %v", err)
	}
	return abs
}

// goFilesOrFatal 列出仓里的 Go 文件。
func goFilesOrFatal(t *testing.T, root string) []string {
	t.Helper()
	files, err := GoFiles(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

// idlFilesOrFatal 列出仓里的 thrift 文件。
func idlFilesOrFatal(t *testing.T, root string) []string {
	t.Helper()
	files, err := IdlFiles(root)
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return files
}

// importsOrFatal 读一个文件的 import 路径。
func importsOrFatal(t *testing.T, path string) []string {
	t.Helper()
	imps, err := ImportsOf(path)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return imps
}

// relToInternal 把路径写成相对**internal/**的样子（"../../pkg/reg/registry.go"）。
//
// ⚠️ 原来的守卫住在 internal/arch/，它们的失败消息里的路径是相对 internal/
// 的（读者在守卫那个目录下打开文件）。搬进底座之后守卫不再住在那里，
// 但消息的形状留着——路径是给人打开的，形状变了就得重新找。
func relToInternal(root, path string) string {
	base := filepath.Join(root, "internal")
	if r, err := filepath.Rel(base, path); err == nil {
		return filepath.ToSlash(r)
	}
	return path
}

// namespaceGo 读一个 thrift 文件的 `namespace go <pkg>` 声明。
// 空结果表示这个文件根本没有 Go 命名空间。
func namespaceGo(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "namespace" && f[1] == "go" {
			return f[2]
		}
	}
	return ""
}

// jsonTagName 读出一个 struct tag 里的 json 名（`json:"name,omitempty"`）。
//
// ⚠️ tag 用 reflect.StructTag 解析，不是手工切文本：手工切会把
// `risk,omitempty` 当成名，之后查 `risk` 永远扑空。
func jsonTagName(tag string) string {
	raw, err := strconv.Unquote(tag)
	if err != nil {
		return ""
	}
	name, _, _ := strings.Cut(reflect.StructTag(raw).Get("json"), ",")
	if name == "-" {
		return ""
	}
	return name
}
