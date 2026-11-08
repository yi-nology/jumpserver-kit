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

⚠️ registry 参数的纪律（调用方必读）：--policy 指的必须是**调用方自己**的
注册表权威源（两个服务各自在自己 CI 里传 internal/service/policy/policy.go）。
本脚本不内嵌任何一张注册表、也不自动发现——kit 与服务之间没有机械关联，
「指向谁」全靠调用方显式这一手；指向了旧的/别人的表，守卫不知道，漂移就
从这一手开始。所以换注册表来源时要连 CI 的 --policy 一起改，不许抄别家的
命令行。工具名的扫描面同样由 --prefix 一手圈定（默认 jms ⇒ jms_ / jmsx_
系）：上游工具名（bashguard、egress）与别的任何前缀**不在**扫描面里——
守卫不越权（--self-test 钉着这条边界）。

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


def doc_tool_names(block_body, prefix):
    """标记块内出现的工具名集合（形状绑定：`\\b前缀[a-z0-9_]+\\b`）。

    前缀就是扫描面的全部：前缀之外的名字（上游工具名、别的系的词）不是
    这道守卫的职权，扫进来等于越权——self_test 钉着这条边界。
    """
    return set(re.findall(r"\b(%s[a-z0-9_]+)\b" % re.escape(prefix), block_body))


def self_test():
    """守卫自测（--self-test）：前缀集合的边界（issue #15）。

    构造一个 other_ 前缀的假工具名，断言注册表侧与文档侧**都不**把它扫出
    ——钉住「守卫只认自家词表」：一旦扫描面越权（比如放宽成正则吞掉别的
    前缀），别人的词汇会被当成漂移报红，或者反过来把本家的漏掉，这里先红。
    """
    problems = []
    # 注册表侧：形状完全相同的 other_ 键不许进集合，jms_ / jmsx_ 都要进。
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".go")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write('var policy = map[string]Policy{\n'
                '\t"jms_one":   {},\n'
                '\t"jmsx_two":  {},\n'
                '\t"other_three": {},\n'
                '}\n')
    try:
        got = registry_names(path, "jms")
    finally:
        os.unlink(path)
    for want in ("jms_one", "jmsx_two"):
        if want not in got:
            problems.append(f"注册表侧漏扫 {want}（got={sorted(got)}）")
    if "other_three" in got:
        problems.append("注册表侧越权扫出 other_three（got=%s）" % sorted(got))
    # 文档侧：同一段标记块，other_ 假名不许进 seen。
    body = "jms_one 与 jmsx_two 在表里；other_three 是别家的词"
    seen = doc_tool_names(body, "jms")
    if {"jms_one", "jmsx_two"} - seen:
        problems.append(f"文档侧漏扫 {sorted({'jms_one', 'jmsx_two'} - seen)}（seen={sorted(seen)}）")
    if "other_three" in seen:
        problems.append("文档侧越权扫出 other_three（seen=%s）" % sorted(seen))
    if problems:
        print("❌ 守卫自测不过（前缀边界漂了，先修扫描面）：")
        for p in problems:
            print("  - " + p)
        return 1
    print("✓ 守卫自测通过：jms_ / jmsx_ 扫得出，other_ 前缀不越权")
    return 0


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
    ap.add_argument("--policy", required=False, default=None,
                    help="注册表来源 Go 文件（相对工具仓根）")
    ap.add_argument("--prefix", default="jms",
                    help="工具名前缀（默认 jms）")
    ap.add_argument("--count", type=int, default=None,
                    help="工具数口径；给定时核块内的「N 个工具」数字")
    ap.add_argument("--self-test", action="store_true",
                    help="跑守卫自己的前缀边界自测，不核对任何文档")
    ap.add_argument("docs", nargs="*", help="要核对的文档文件或目录")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if not args.policy:
        ap.error("--policy 不能为空（注册表来源要调用方显式给，守卫不猜）")
    if not args.docs:
        ap.error("要核对的文档文件或目录不能为空（或用 --self-test 跑自测）")

    names = registry_names(args.policy, args.prefix)
    if not names:
        sys.exit(f"❌ 注册表抽取为空（{args.policy}）——形状绑定漂了，先修脚本。")

    problems = []
    blocks = doc_blocks(args.docs)
    if not blocks:
        problems.append("没有任何 <!-- tools:* --> 标记块——文档还没接线，"
                        "在 AGENTS/README/skills 的工具表段落加上标记块。")
    for f, body in blocks:
        seen = doc_tool_names(body, args.prefix)
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
