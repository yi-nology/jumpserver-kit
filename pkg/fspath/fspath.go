// Package fspath 是路径形态的小工具，供共用底座与配置层共用。
//
// 它只有一件事：配置值里的 `~` 是人写路径的方式，而配置机器原样交出
// 字符串，展开它是这里的事。曾经 audit 的目录解析与 exec 的密钥路径
// 各有一份逐字相同的 expandHome——两份逐字相同的机械就是下一处漂。
package fspath

import (
	"os"
	"path/filepath"
	"strings"
)

// ExpandHome 把路径开头的 `~` 展开成用户家目录；展开不了就原样返回。
//
// ⚠️ 只认开头的 `~`（`~/...` 与裸 `~`）；`~user/...` 不支持——那种
// 展开需要查口令库，猜出来的家目录比不展开更糟。
func ExpandHome(p string) string {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return home
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~"))
}
