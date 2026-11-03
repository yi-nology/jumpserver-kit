// Package textx 是本仓「给答复与留痕看的文本」的截断机械。
//
// 截断的实现只留这一份：拼后缀、切 rune 边界这三行里出过两次 UTF-8 事故
// （切进多字节字符留下非法 UTF-8，JSON 编码器把尾巴变成 U+FFFD，存进
// 留痕/答复的就不是调用方的那个字符串了），抄一份就多一处能再犯的地方。
//
// 后缀是调用方的语义标记，不是这份实现的事：留痕里 `…(clipped)` 是列
// 上限裁的、`…(truncated)` 是值截的，答复里 `...` 是展示截的 —— 读的人
// 靠它分辨「原文就这么短」与「被裁过」，所以它留在调用方手上。
package textx

import (
	"github.com/oekit/pkg/stringx"
)

// Trunc 把 s 截到 n 字节（切在 rune 边界），截了就在尾巴上拼 suffix；
// 没截就原样返回。suffix 可以是空串（截断不留标记的场合，比如客户端名
// —— 名字要像个名字，尾巴上挂个省略号就不像了）。
func Trunc(s string, n int, suffix string) string {
	out, cut := stringx.TruncBytes(s, n)
	if !cut {
		return s
	}
	return out + suffix
}
