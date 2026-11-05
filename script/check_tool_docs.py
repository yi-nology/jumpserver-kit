#!/usr/bin/env python3
"""工具表 ↔ 注册表 机械一致性守卫。

加一个工具的实录：代码 1 处注册，文档要同步改 6 处（AGENTS 工具数口径×4、
README 工具表与目录树、skills 工具表与示例）——全靠手工，漏一处就是漂，
漂了的文档会教错下一个 agent。这道守卫把「文档里声明的工具集合」钉在
「注册表的实际集合」上：名字缺失/多余都红。

用法（在工具仓根目录，如 jumpserver-exec）：

    python3 ../jumpserver-kit/script/check_tool_docs.py \
        --policy internal/service/policy/policy.go \
        --count 16 \
        --docs AGENTS.md README.md skills/

机制：

  - 注册表口径：--policy 指到的 Go 文件里的键集合（policy 是工具目录的
    风险侧权威，policy_test 钉的就是它；也可指向 swagger 生成物等）。
    键抽取的正则与 Go map 字面量形状绑定（"tool_name": {），改形状要同步。
  - 文档侧：显式标记块框住要核对的段落，守卫只核块内集合，散文不动：

        <!-- tools:exec -->
        ...（表格、示例、目录树，凡块内出现的 tool name 都算声明）...
        <!-- /tools:exec -->

    块内的数字口径（如「16 个工具」）也核：--count 与块内 N 不一致即红。

退出码 0 = 一致；1 = 有漂移（打印每个缺失/多余与文件位置）。
"""
import argparse
import os
import re
import sys


def registry_names(policy_path, prefix):
    """从 Go 文件抽注册表键集合（形状绑定：`"name": {`）。"""
    body = open(policy_path, encoding="utf-8").read()
    names = set(re.findall(r'"(%s[a-z0-9_]+)"\s*:\s*\{' % re.escape(prefix), body))
    return names


def doc_blocks(docs_roots):
    """收集所有标记块：返回 [(file, block_body)]。

    块标记的形状：<!-- tools:<plane> --> ... <!-- /tools:<plane> -->。
    """
    blocks = []
    for root in docs_roots:
        if os.path.isfile(root):
            files = [root]
        else:
            files = []
            for base, _, names in os.walk(root):
                files += [os.path.join(base, n) for n in names
                          if n.endswith((".md", ".txt"))]
        for f in files:
            text = open(f, encoding="utf-8", errors="replace").read()
            for m in re.finditer(
                    r"<!--\s*tools:[a-z-]+\s*-->(.*?)<!--\s*/tools:[a-z-]+\s*-->",
                    text, re.S):
                blocks.append((f, m.group(1)))
    return blocks


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy", required=True,
                    help="注册表来源 Go 文件（相对工具仓根）")
    ap.add_argument("--prefix", default="jms",
                    help="工具名前缀（默认 jms）")
    ap.add_argument("--count", type=int, default=None,
                    help="工具数口径；给定时核块内的「N 个工具」数字")
    ap.add_argument("docs", nargs="+", help="要核对的文档文件或目录")
    args = ap.parse_args()

    names = registry_names(args.policy, args.prefix)
    if not names:
        sys.exit(f"❌ 注册表抽取为空（{args.policy}）——形状绑定漂了，先修脚本。")

    problems = []
    blocks = doc_blocks(args.docs)
    if not blocks:
        problems.append("没有任何 <!-- tools:* --> 标记块——文档还没接线，"
                        "在 AGENTS/README/skills 的工具表段落加上标记块。")
    for f, body in blocks:
        seen = set(re.findall(r"\b(%s[a-z0-9_]+)\b" % re.escape(args.prefix), body))
        missing = sorted(names - seen)
        extra = sorted(seen - names)
        for n in missing:
            problems.append(f"{f}: 工具 {n} 在注册表里，标记块没提")
        for n in extra:
            problems.append(f"{f}: 工具 {n} 在标记块里，注册表没有")
        if args.count is not None:
            for m in re.finditer(r"(\d+)\s*个工具", body):
                if int(m.group(1)) != args.count:
                    problems.append(
                        f"{f}: 口径「{m.group(1)} 个工具」≠ 注册表 {args.count}")

    if problems:
        print(f"❌ 工具表漂移（{len(problems)} 处）：")
        for p in problems:
            print("  - " + p)
        sys.exit(1)
    print(f"✓ 工具表一致：{len(names)} 个工具 × {len(blocks)} 个标记块"
          + (f"，口径 {args.count}" if args.count is not None else ""))


if __name__ == "__main__":
    main()
