#!/usr/bin/env python3
"""变异测试：把 pkg/audit 的每一处修复退回一次，看对应的测试**会不会变红**。

为什么它在仓里：一份「全都验过了」的证据，如果只躺在 /tmp 里，机器一重启
就没了，下一轮谁也复现不了 ⇒ 而「守卫必须自证会红」正是本仓的规矩。

⚠️ **它住在底座仓（jumpserver-mcp-kit）里，因为它跨仓**：被变异的源码在底座
（pkg/audit、pkg/redact、pkg/reg、pkg/textx）与两个服务仓（两个面的
handler）里，而**要证明会红的守卫有一部分在服务仓里**（答复守卫、留痕守卫）
⇒ 一轮变异要同时动三个仓。

用法（在底座仓根目录）：

    python3 script/mutate-audit.py            # 跑全部变异
    python3 script/mutate-audit.py -v         # 顺带打印每个变异做了什么

工作集（哪些仓参与这一轮）：

    JMS_SIBLING_ROOTS=/path/to/jumpserver-mcp:/path/to/jumpserver-mcp-exec

没有这个环境变量时用同级目录约定（见 script/workset.py）。

每个变异都是**一处**改动：把修复退回旧行为，然后跑那个本该拦住它的测试。
测试**变红** = 那个守卫是真的；测试**仍绿** = 那个守卫是假的（脚本会列出来
并以非零码退出）。

⚠️ 变异用 overlay 注入，**不碰仓库里的任何文件**：每个变异是一份改过的
副本，go test 用 -overlay 把它盖到真实路径上。
"""
import difflib
import json
import os
import re
import subprocess
import sys

# 同仓的另一个脚本：工作集的定义。
# ⚠️ 与守卫是同一套约定，别另造一份 —— 一份拷贝会漂，而漂了的那份决定
# 报告对着的是哪一份代码。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workset

# ⚠️ realpath, NOT abspath: the overlay's keys have to be the paths GO
# resolves, and on macOS /tmp is a symlink to /private/tmp. When the two
# disagree the overlay is SILENTLY IGNORED and every mutant runs against
# unmutated code — which looks exactly like "all the guards are fake".
# The fourth review found it that way: 0/32, with no hint of why.
# ⚠️ **仓不止一个**：底座（jumpserver-mcp-kit）与两个服务仓并排。
# 这一轮变异要改底座的源码（pkg/audit、pkg/redact、pkg/reg、pkg/textx），
# 也要改服务仓的源码（两个面的 handler）⇒ 「文件在哪」「测试在哪」都得
# 在**工作集**里找，而不是在某一个仓根底下找。
ROOT = workset.own_root(__file__)
ROOTS = workset.roots(__file__)
# 给子进程（go test）的多仓工作集：守卫可能需要回头指着自己那个仓。
SIBLING_ENV = workset.sibling_env(ROOTS)
OUT = "/tmp/jms-mutants"


def _at(relpath):
    """工作集里的「仓内相对路径」→ 绝对路径。"""
    return workset.locate(relpath, ROOTS)


def _in(repo_name, relpath):
    """**点名**的那个仓里的「仓内相对路径」→ 绝对路径。

    ⚠️ 两个服务仓重构之后**都有** `biz/handler/` ⇒ locate 会拒绝猜
    （撞名时它宁可报错也不猜 —— 猜错了就是「在错的代码上跑」）⇒ 凡是
    服务仓的路径都要指名道姓地说在哪个仓里。
    """
    return workset.locate_in(repo_name, relpath, ROOTS)


A = os.path.dirname(_at("pkg/audit/audit.go"))
R = os.path.dirname(_at("pkg/redact/redact.go"))
H = os.path.dirname(_in("jumpserver-mcp-exec", "biz/handler/audit.go"))
S = os.path.dirname(_in("jumpserver-mcp", "biz/handler/onboarding.go"))

audit = open(f"{A}/audit.go").read()
file = open(f"{A}/file.go").read()
read = open(f"{A}/read.go").read()
redact = open(f"{R}/redact.go").read()
handler = open(f"{H}/audit.go").read()
health = open(f"{A}/health.go").read()
alive_win = open(f"{A}/alive_windows.go").read()
# ⚠️ 截断的唯一实现（pkg/textx）：clip/truncate/Truncate 三份截断归一后，
# 「按字节切」「不留标记」这类机械变异打的是这里，不再打 audit 的薄壳。
T = _at("pkg/textx/textx.go")
textx_src = open(T).read()
RG = _at("pkg/reg/registry.go")
reg = open(RG).read()
onboarding = open(f"{S}/onboarding.go").read()
# ⚠️ 答复面（管理面）的脱敏：**另一条路径**，自己的形状，自己的规则。
# 两条路径共用同一份**词表**（pkg/redact），但形状各走各的 ⇒ 答复面的
# 每一处规则都要有自己的变异，否则「答复面没人守」这件事没人知道。
answer = open(f"{S}/redact.go").read()

# anchor_in returns a line of a source file that contains `marker` —
# the anchor of a mutation, taken from the SOURCE rather than written
# out by hand.
#
# ⚠️ Why: a hand-written anchor has to carry the source's own escaping
# (a Go raw string keeps the backslashes verbatim, and a Python literal
# doubles them) ⇒ the two layers disagree by a backslash and the
# mutation silently matches NOTHING ⇒ the sweep reports it as "the
# mutation did not take" and the real problem (the guard is not
# exercised) never surfaces.
#
# ⚠️ Taking the anchor from the source removes that whole class of
# mistake: the anchor is whatever the source says it is.
def anchor_in(text, marker, occurrence=0):
    hits = [l for l in text.split("\n") if marker in l]
    if not hits:
        raise SystemExit(f"⚠️  锚点不存在（源码里找不到 {marker!r}）")
    if occurrence >= len(hits):
        raise SystemExit(f"⚠️  锚点只有 {len(hits)} 处，取不到第 {occurrence} 处")
    return hits[occurrence]


# SOURCES is the snapshot every mutation was built FROM — the source as
# it was when this script started.
#
# ⚠️ The checks below compare a mutation against THIS, not against the
# file on disk right now: a mutation is "one edit against the source it
# was read from" ⇒ comparing it against a source that changed under us
# counts somebody else's edit as ours ⇒ and the "one mutation, one
# place" rule then fires on half the set for no reason.
SOURCES = {
    f"{A}/audit.go": audit,
    f"{A}/file.go": file,
    f"{A}/read.go": read,
    f"{A}/health.go": health,
    f"{A}/alive_windows.go": alive_win,
    f"{R}/redact.go": redact,
    f"{H}/audit.go": handler,
    f"{S}/onboarding.go": onboarding,
    f"{S}/redact.go": answer,
    T: textx_src,
    RG: reg,
}


def source_of(path):
    """The snapshot of `path` the mutations were built from."""
    if path in SOURCES:
        return SOURCES[path]
    return open(path).read()


# (名字, {文件: 改后的内容}, 该由哪条测试拦住)
M = {}

# STALE collects the mutations whose ANCHOR was not unique (or not found
# at all).
#
# ⚠️ It is a LIST, not an immediate exit: the old `sub1` walked into the
# first bad anchor ⇒ the mutations after it were never even declared ⇒
# one run reported ONE problem ⇒ fixing it meant another run ⇒ and a run
# is a quarter of an hour.
# ⇒ Here the problem is only RECORDED, and the script reports all of
# them at once (at the end).
STALE = []

# ALLOWED_SITES holds the mutations that MUST change more than one place,
# and why.
#
# ⚠️ "One mutation, one place" is what keeps the sweep honest: a
# mutation that changes two places exercises two guards at once, and the
# report then says one thing while two things happened.
# ⇒ The exceptions are written DOWN, with their reason, so that a second
# place is a DECISION and never an accident.
ALLOWED_SITES = {
    "注册表不洗": "去掉 scrub 调用就必须去掉它的 import，否则编译不过 ⇒ "
                  "两处是**必须**的，不是手滑",
}


def sub1(text, old, new):
    """替换**一处**，并且在目标不是唯一的时候拒绝动手。

    ⚠️ 变异命中两处 ⇒ 那是两个变异共用一个名字 ⇒ 这一轮只报了一次检查，
    而实际被检查的守卫不是它声称的那个。旧的 `str.replace` 静默地全换。
    ⇒ 这里数一遍，出现次数不是 1 就**记进 STALE**。

    ⚠️ 为什么不当场退出：当场退出只能报出**第一个**坏锚点 ⇒ 后面那些
    变异连声明都没有 ⇒ 修一个跑一轮（一轮十几分钟）。
    ⇒ 这里只记账 ⇒ 脚本结束时**一次报全部** ⇒ 并且退出码是 1。
    """
    n = text.count(old)
    if n != 1:
        STALE.append((old[:100], n))
        return text
    return text.replace(old, new)


def swap(text, anchor, old, new, count=1):
    """把**锚点那一行**里的 `old` 换成 `new`，其余一行不动。

    ⚠️ 锚点来自源码（anchor_in）⇒ 那一行就是源码说的样子 ⇒ 「源码 ↔
    变异」之间不可能差一层转义 ⇒ 变异不会静默地什么都改不到。
    ⚠️ `old` 在**那一行里**也必须只出现 `count` 次 ⇒ 否则这一条变异改
    了不止一处（而「一次变异只改一处」是这套脚本自己的规矩）。
    """
    n = anchor.count(old)
    if n != count:
        STALE.append((old[:100], n))
        return text
    return sub1(text, anchor, anchor.replace(old, new))


def swap_re(text, anchor, pattern, new):
    """把锚点那一行里**正则**匹配到的一段换成 `new`。

    ⚠️ 用正则而不是手写的那一段，是因为源码会变：签名改了、参数改了，
    手写的那一段就再也匹配不上 ⇒ 变异静默地什么都改不到 ⇒ 而扫描只会
    说「守卫是假的」，真正的问题（守卫根本没被跑到）永远浮不出来。
    """
    hits = re.findall(pattern, anchor)
    if len(hits) != 1:
        STALE.append((pattern, len(hits)))
        return text
    return sub1(text, anchor, re.sub(pattern, new.replace("\\", "\\\\"), anchor))


def two_lines(text, marker):
    """The line at `marker` and the line after it, as they appear.

    ⚠️ Needed for the edits that span two lines (a rule and its
    verdict): the lines come from the SOURCE ⇒ the escaping cannot
    drift, and the two lines are guaranteed to be ADJACENT.
    """
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if marker in line:
            if i + 1 >= len(lines):
                break
            return lines[i] + "\n" + lines[i + 1]
    STALE.append((marker, 0))
    return ""


def drop_block(text, marker, closer="}"):
    """删掉从 `marker` 那行开始、到它自己那个 `closer` 行为止的整块。

    ⚠️ 块的范围**由源码决定**（找到那一行的块尾为止），不数行号 ⇒ 源码
    改了行数，这条变异照样指对地方。
    """
    lines = text.split("\n")
    start = None
    for i, line in enumerate(lines):
        if marker in line:
            start = i
            break
    if start is None:
        STALE.append((marker, 0))
        return text
    end = None
    for i in range(start, len(lines)):
        if lines[i].strip() == closer:
            end = i
            break
    if end is None:
        STALE.append((closer, 0))
        return text
    return "\n".join(lines[:start] + lines[end + 1:])


def mut(name, files, test, pkg="./pkg/audit/"):
    M[name] = (files, test, pkg)


# ---- 读回侧：文件名、轮转、排序、队列、limit -------------------------------
mut("glob_只看当前代", {f"{A}/read.go": read.replace(
    'const trailGlob = "audit-*.jsonl*"', 'const trailGlob = "audit-*.jsonl"')},
    "TestTheRotatedTrailIsStillReadable")

# ---- 写入侧：截断（唯一实现在 pkg/textx，audit 的 clip/truncate 是带语义后缀的薄壳）----
# ⚠️ 截断归一（pkg/textx）后，机械类变异（按字节切 / 不留标记）只剩**一份**
# 实现可打 ⇒ 原先 clip/truncate 两份各一条的四条变异合成两条。行为类变异
# （整个不裁）打各自的语义薄壳，仍是两条。
# ⚠️ 合并是必须的：同一个 fingerprint 登记两次 ⇒ 第二条会被判「同一处编辑」
# ⇒ 被算成「没新增检查」⇒ 头条数字当场报红。
# ⚠️ Each mutation touches ONE place.
mut("截断按字节切", {T: sub1(textx_src,
    'out, cut := stringx.TruncBytes(s, n)',
    'out, cut := stringx.TruncBytes(s[:n], n)')},
    "TestTheArgumentsAreCutOnACharacterBoundary")

mut("截断不留标记", {T: sub1(textx_src,
    'return out + suffix',
    'return out')},
    "TestTheArgumentsAreCutOnACharacterBoundary")

mut("args 列整个不裁", {f"{A}/audit.go": sub1(audit,
    'func truncate(s string, n int) string {\n\treturn textx.Trunc(s, n, "…(truncated)")\n}',
    'func truncate(s string, n int) string {\n\treturn s\n}')},
    "TestTheArgumentsAreCutOnACharacterBoundary")

mut("列上限整个不裁", {f"{A}/audit.go": sub1(audit,
    'func clip(s string, n int) string {\n\treturn textx.Trunc(s, n, "…(clipped)")\n}',
    'func clip(s string, n int) string {\n\treturn s\n}')},
    "TestEveryFreeTextColumnHasACeiling")

mut("轮转前先删归档代", {f"{A}/file.go": file.replace(
    '\tif err := os.Rename(t.path, t.path+".1"); err != nil {',
    '\t_ = os.Remove(t.path + ".1")\n\tif err := os.Rename(t.path, t.path+".1"); err != nil {')},
    "TestAFailedRotationKeepsTheArchivedGeneration")

mut("轮转失败继续写", {f"{A}/file.go": file.replace(
    """		logx.Error("the audit trail file could not be rotated; the file trail stops here",
			"path", t.path, "err", err)
		return false""",
    """		logx.Error("the audit trail file could not be rotated", "path", t.path, "err", err)
		if f, err2 := openAppend(t.path); err2 == nil {
			t.f = f
		}
		return true""")},
    "TestTheCapHoldsEvenWhenTheRotationFails")

mut("轮转整个不触发", {f"{A}/file.go": file.replace(
    "	if t.size+int64(len(line)) > t.max {", "	if false && t.size+int64(len(line)) > t.max {")},
    "TestTheCapHoldsEvenWhenTheRotationFails")

mut("轮转改成读不出的名字", {f"{A}/file.go": file.replace(
    'os.Rename(t.path, t.path+".1")', 'os.Rename(t.path, t.path+".rotated")')},
    "TestTheRotatedTrailIsStillReadable")

mut("不认文件名", {f"{A}/read.go": read.replace(
    """		if !trailFileName.MatchString(filepath.Base(path)) {
			continue
		}""", "")},
    "TestAFileThatIsNotTheTrailIsNotReadAsOne")

# ⚠️ The old form was not valid Go (a multi-value assignment cannot use
# the comma form in a single-value context), so it never compiled and
# never ran: the mutation existed on paper only.
mut("不认不是我们的行", {f"{A}/read.go": read.replace(
    "				at, ok := trailMoment(e)\n				if ok && matches(e, at, opts) {",
    "				at, _ := parseTs(e.Ts)\n				if matches(e, at, opts) {")},
    "TestALineThatIsNotACallIsNotAFact")

mut("limit 没有上限", {f"{A}/read.go": read.replace(
    """	if limit > MaxReadLimit {
		limit = MaxReadLimit
	}""", "")},
    "TestTheLimitHasACeiling")

# ⚠️ 一次变异只改**一处** ⇒ 原来的 `str.replace` 命中**两处**（队列里那
# 一次排序与最后那一次）是两处编辑 ⇒ 它同时动了两条守卫 ⇒ 数字比实际
# 弱 ⇒ 锚点取「最后那一次排序」那一处（队列里的那一次由「队列按到达顺序
# 淘汰」守着）。
mut("排序按字符串", {f"{A}/read.go": sub1(read,
    "func (n *newest) sorted() []Entry {\n\tsort.SliceStable(n.items, func(i, j int) bool {\n\t\treturn n.items[i].at.After(n.items[j].at)",
    "func (n *newest) sorted() []Entry {\n\tsort.SliceStable(n.items, func(i, j int) bool {\n\t\treturn n.items[i].entry.Ts > n.items[j].entry.Ts")},
    "TestTheNewestLineComesFirst")

mut("队列按到达顺序淘汰", {f"{A}/read.go": read.replace(
    """		sort.SliceStable(n.items, func(i, j int) bool {
			return n.items[i].at.After(n.items[j].at)
		})
		n.items = n.items[:n.limit]""",
    """		keep := copy(n.items, n.items[len(n.items)-n.limit:])
		n.items = n.items[:keep]""")},
    "TestTheAnswerIsTheNewestLines")

mut("队列不裁剪", {f"{A}/read.go": read.replace(
    "	if len(n.items) >= 2*n.limit {", "	if false && len(n.items) >= 2*n.limit {")},
    "TestTheQueueStaysBounded")

mut("Since 不筛", {f"{A}/read.go": read.replace(
    "	if !opts.Since.IsZero() && at.Before(opts.Since) {",
    "	if false && !opts.Since.IsZero() && at.Before(opts.Since) {")},
    "TestTheSinceFilterKeepsOnlyWhatIsAfterIt")

# ⚠️ The old form did not compile either (the counts went unused), and the
# path it guards is now REACHABLE: the reader takes a seam, so a test can
# hand it a file that breaks halfway.
# ⚠️ The counting has to happen on BOTH paths, and each one needs its own
# mutation: the mutation that moved the counting into the error branch
# left the successful path uncounted, and the test that watched the error
# path never saw it.
mut("成功时不计数", {f"{A}/read.go": read.replace(
    "		res.Total += matched\n		res.Skipped += skipped\n		if err != nil {",
    "		_ = matched\n		_ = skipped\n		if err != nil {")},
    "TestTheCountIsOfEverythingThatMatched")

# ⚠️ The error path is the one that matters: the lines that WERE read are
# already in the answer, so a read that breaks halfway has to leave its
# count behind. The mutation makes the reader forget what it read.
mut("出错时不计数", {f"{A}/read.go": read.replace(
    "		if rerr != nil {\n			return matched, skipped, rerr\n		}",
    "		if rerr != nil {\n			return 0, 0, rerr\n		}")},
    "TestAFileThatBreaksHalfwayStillHasItsLinesCounted")

# ---- 写入侧：脱敏、随机后缀、落盘与日志两侧 -------------------------
# （列上限的三条变异已随截断归一合并进上面「写入侧：截断」一节 ——
#   按字节切 / 不留标记各剩一份实现可打，整个不裁打 clip 薄壳。）

mut("error 列不裁", {f"{A}/audit.go": audit.replace(
    "return clip(scrub(strings.TrimPrefix(text, \"ERROR: \")), maxColumn)",
    "return scrub(strings.TrimPrefix(text, \"ERROR: \"))")},
    "TestEveryFreeTextColumnHasACeiling")

# ⚠️ 一次变异只改**一处** ⇒ 原来的 `str.replace` 命中**两处**
# （reasonText 与 refusedText）⇒ 门禁理由那一处由「门禁理由不裁」守着
# ⇒ 这一条只改 refusedText 那一处。
mut("拒绝理由不裁", {f"{A}/audit.go": sub1(audit,
    "func refusedText(reason string) string {\n\treturn clip(scrub(reason), maxColumn)",
    "func refusedText(reason string) string {\n\treturn scrub(reason)")},
    "TestEveryFreeTextColumnHasACeiling")

# ⚠️ The gate's own stage reason is a column too, and the sweep never
# touched it — the headline was "EVERY column" and one column was never
# mutated at all.
mut("门禁理由不裁", {f"{A}/audit.go": audit.replace(
    "func reasonText(reason string) string {\n\treturn clip(scrub(reason), maxColumn)",
    "func reasonText(reason string) string {\n\treturn scrub(reason)")},
    "TestEveryFreeTextColumnHasACeiling")

# ⚠️ And the LOG side carries the same ceiling as the file side. A second
# copy of the shaping is a second waterline, and this one survived the
# whole suite.
mut("日志侧自己一份上限", {f"{A}/audit.go": audit.replace(
    '"refused", refusedText(gate.Outcome.RefusalReason())',
    '"refused", clip(scrub(gate.Outcome.RefusalReason()), maxColumn*2)')},
    "TestEveryFreeTextColumnHasACeiling")

# ⚠️ Dropping the PAYLOAD half (not the whole scrubber) is the mutation
# that matters: a base64 private key has no PEM header to recognise, so
# only the payload rule catches it. The whole suite stayed green with it
# removed, and the key went into the trail file in the clear.
# ⚠️ The payload reduction now happens in TWO places (the text scrubber
# and redact.Args), so removing one of them is not observable — the
# mutation has to remove the one that matters.
# ⚠️ 载荷缩减没了 ⇒ base64 私钥原样落盘。
# ⚠️ 载荷缩减没了 ⇒ base64 私钥原样落盘。
mut("脱敏丢掉载荷缩减", {f"{R}/redact.go": sub1(redact,
    "	text = maskProseCredentials(Payloads(text))", "	text = maskProseCredentials(text)")},
    "TestTheTrailDoesNotWriteDownAPayload", "./pkg/audit/")

# ⚠️ 兜底整个不生效 ⇒ 含 `&` 或含引号的凭据明文落盘。
mut("脱敏不生效", {f"{R}/redact.go": sub1(redact,
    "	text = maskProseCredentials(Payloads(text))\n	text = maskCredentialKeys(Text(text))",
    "	text = Payloads(text)")},
    "TestACredentialIsMaskedWholeWhateverItsShape", "./pkg/audit/")

mut("载荷脱敏不幂等", {f"{R}/redact.go": redact.replace(
    """					if alreadyScrubbed(str) {
						continue
					}
""", "")},
    "TestScrubbingAPayloadTwiceKeepsTheSize", "./pkg/redact/")

# ⚠️ The mutant targets the CONSTANT, not the branch that uses it: the
# branch is unreachable (crypto/rand.Read never returns an error), so
# changing it is not observable — and the only property that CAN be
# checked is the constant's shape. A "guard" on an unreachable path is
# not a guard; the shape is.
mut("随机后缀兜底改回 4 位", {f"{A}/file.go": file.replace(
    'const randomSuffixFallback = "00000000"', 'const randomSuffixFallback = "0000"')},
    "TestTheRandomSuffixFitsTheShapeTheReaderRecognises")

mut("打开文件改成截断", {f"{A}/file.go": file.replace(
    "return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)",
    "return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)")},
    "TestTheSizeOfAnExistingFileIsRead")

mut("fileSize 恒返回 0", {f"{A}/file.go": file.replace(
    """	info, err := f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()""", "	return 0")},
    "TestTheSizeOfAnExistingFileIsRead")

mut("OverCap 的边界改成 >=", {f"{A}/file.go": file.replace(
    "if info.Size() > MaxTrailBytes {", "if info.Size() >= MaxTrailBytes {")},
    "TestAFileExactlyAtTheCapIsNotOverIt")

mut("OverCap 不认文件名", {f"{A}/file.go": file.replace(
    """		if !trailFileName.MatchString(filepath.Base(p)) {
			continue
		}""", "")},
    "TestANeighbouringFileOverTheCapIsNotReported")

mut("上限没接到文件上", {f"{A}/file.go": file.replace(
    "max: MaxTrailBytes", "max: 0")},
    "TestTheTrailFileCarriesTheCap")

# ---- 答复面：跳过的行数、上限的措辞 ----------------------------------------
mut("note 不说跳过了几行", {f"{H}/audit.go": handler.replace(
    "len(rows), res.Total, effectiveLimit(args.Limit), skippedNote(res.Skipped),",
    "len(rows), res.Total, effectiveLimit(args.Limit), \"\",")},
    "TestTheAnswerSaysWhenItCouldNotReadEverything", "./biz/handler/")

mut("note 的上限写天花板", {f"{H}/audit.go": handler.replace(
    "effectiveLimit(args.Limit)", "audit.MaxReadLimit")},
    "TestTheAnswerDoesNotClaimItMissedAnything", "./biz/handler/")

mut("答复不报 skipped", {f"{H}/audit.go": handler.replace(
    "Skipped: jms.OptInt32(int32(res.Skipped)),", "")},
    "TestTheAnswerSaysWhenItCouldNotReadEverything", "./biz/handler/")


# ⚠️ 两侧要逐字节相同：落盘侧自己洗 ⇒ 日志侧不洗时两边就分岔了。
# 这条变异守的就是这个 —— 它盯的不是「有没有脱敏」，是「两个出口说的是
# 同一串字吗」。
mut("日志侧不洗", {f"{A}/audit.go": audit.replace(
    "\t\tgate.Call.Args = scrubArgs(gate.Call.Args)", "\t\t_ = scrubArgs")},
    "TestTheLogLineAndTheFileLineCarryTheSameText")

# ---- 第七轮审阅的探针：标记假阳性（泄漏）与保留期溢出 ---------------------
# ⚠️ 守卫必须只认 logredact 真正的标记（闭引号被吃掉了），否则一段文本里
# 只要有 `"x=****`，**整段**就不脱敏 ⇒ 别处的密码就活着进了留痕。
# ⚠️ The dangerous direction is the guard being too WIDE — mistaking an
# ordinary `"x=****"` value for a mark and skipping the whole text. The
# opposite direction (the guard never fires) only means "always scrub",
# which is the SAFE side — so a mutation that widens the guard is the one
# that can leak, and that is the one the guard has to catch.
#
# ⚠️ The condition is replaced rather than the block removed: removing it
# would leave a bare `continue` in the function body and the package would
# not compile — and a compile failure is NOT the guard firing.
# ⚠️ 保留期的乘法会溢出 ⇒ 变成负数 ⇒ 「比窗口旧」对**每个**文件都成立
# ⇒ 整份留痕被删。
mut("保留期溢出", {f"{A}/file.go": file.replace(
    "	if days > MaxRetentionDays {\n\t\tdays = MaxRetentionDays\n\t}", "")},
    "TestTheRetentionWindowNeverOverflows")

# ---- 第十轮审阅：凭据键兜底、名字过滤的守卫 --------------------------------
# ⚠️ 兜底规则没了 ⇒ 含 `&` 或含引号的凭据会**明文**进留痕。
# ⚠️ 注册表不洗 ⇒ 回调拿到明文 ⇒ 这条公共 API 承诺就没有任何东西守着。
mut("注册表不洗", {f"{RG}": reg.replace(
    "\trec.Call.Args = redact.Scrub(rec.Call.Args)\n", "").replace(
    "\t\"github.com/yi-nology/jumpserver-mcp-kit/pkg/redact\"\n", "")},
    "TestTheRegistryScrubsTheArgumentsBeforeTheCallback", "./pkg/reg/")

# ⚠️ note 报的保留天数不夹逼 ⇒ 承诺的比机器留的还多。
mut("note 不夹逼保留期", {f"{H}/audit.go": handler.replace(
    "	if days > audit.MaxRetentionDays {\n\t\tdays = audit.MaxRetentionDays\n\t}", "")},
    "TestTheAnswerPromisesNoMoreThanThePrunerKeeps", "./biz/handler/")

# ⚠️ 词表是这一版的全部内容 ⇒ 两条方向的守卫都要有：
# 「退成子串匹配」⇒ 良性字段（session/key_id/keywords）被抹 ⇒ 数据损坏；
# 「删掉几个词」⇒ authorization/bearer/cookie 这类**上游不认**的词漏网 ⇒ 明文落盘。
# ⚠️ 布尔标志（has_password: true）不是凭据 ⇒ 被抹就成了字符串。
# ⚠️ 布尔标志（has_password: true）不是凭据 ⇒ 被抹就成了字符串。
# ⚠️ 布尔标志（has_password: true）不是凭据 ⇒ 被抹就成了字符串。
# ⚠️ 布尔标志不再被**摘出** ⇒ 上游的形态规则就会把它洗掉（它对凭据键一律
# 动手）⇒ `has_password: true` 变成 `has_password: ****`（事实变成了字符串）。
# ⚠️ 锚点要**唯一**：这一行（`isCredentialKey(sub[2])`）在散文兜底里也有一份，
# 而散文兜底是**另一条**守卫 ⇒ 一次改两处 ⇒ 这一轮只报了一次检查。
mut("布尔标志不被摘出", {f"{R}/redact.go": sub1(redact,
    "\t\tif sub == nil || !isCredentialKey(sub[2]) {\n\t\t\treturn m\n\t\t}\n\t\tflags = append(flags, bareCredential{key: sub[2], value: sub[3]})",
    "\t\tif true {\n\t\t\treturn m\n\t\t}\n\t\tflags = append(flags, bareCredential{key: sub[2], value: sub[3]})")},
    "TestABooleanFlagIsNotMasked", "./pkg/redact/")

# ⚠️ 转义 JSON 里的凭据（命令行里带 JSON 的形态）。
# ⚠️ 两条正则**都**去掉 (?i) ⇒ 大写键（普通形态与转义形态都算）
# 明文落盘。⚠️ 只去掉转义那一条**测不到**：普通那支（有 (?i)）会兜住
# 同一个输入 ⇒ 变异无效却看起来「守卫是假的」。
mut("大写键不再遮蔽", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "`(?i)` + esc(1)"),
    "`(?i)` + esc(1)", "`` + esc(1)")},
    "TestACapitalisedCredentialInAnEscapedJSONStringIsMasked", "./pkg/redact/")

mut("普通键也不再遮蔽大写", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, '`(?i)"([a-z0-9_.-]+)"?'),
    '`(?i)"([a-z0-9_.-]+)"?', '`"([a-z0-9_.-]+)"?')},
    "TestACapitalisedCredentialKeyIsMasked", "./pkg/redact/")

mut("词表退成子串匹配", {f"{R}/redact.go": sub1(redact,
    "\t\tif strings.HasSuffix(lower, w) {", "\t\tif strings.Contains(lower, w) {")},
    "TestTheCredentialWordList", "./pkg/redact/")

mut("词表漏掉 authorization", {f"{R}/redact.go": redact.replace(
    "\"authorization\", ", "")},
    "TestTheCredentialWordList", "./pkg/redact/")

# ⚠️ 一次变异只改**一处** ⇒ 原来的 `str.replace` 命中**三处**（兜底的三
# 条规则：普通/转义/双层转义）⇒ 这一条只关**普通**那一条 ⇒ 转义那两条
# 由「大写键不再遮蔽」「转义兜底的值跨字段」「双层转义形态少写反斜杠」
# 守着。
mut("凭据键兜底不生效", {f"{R}/redact.go": sub1(redact,
    "\t\tsub := credentialKeyRE.FindStringSubmatch(m)\n\t\tif sub == nil || !isCredentialKey(sub[1]) {\n\t\t\treturn m\n\t\t}",
    "\t\tsub := credentialKeyRE.FindStringSubmatch(m)\n\t\tif true {\n\t\t\treturn m\n\t\t}")},
    "TestTheCredentialWordList", "./pkg/redact/")

# ---- 这一轮：散文形态、无引号值、转义形态的反斜杠、词边界 --------------------
# ⚠️ 散文形态（命令行的 `export PASSWORD=…`）里，**引号内带 & 的凭据**上游
# 一条规则都不匹配 ⇒ 整条明文落盘（不是尾巴，是全部）。
mut("散文兜底不生效", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "if !isCredentialKey(key) || value == \"\""),
    "if !isCredentialKey(key) || value == \"\" || isBooleanLiteral(value) {", "if true {")},
    "TestAProseCredentialIsMaskedWhole", "./pkg/redact/")

# ⚠️ 散文兜底**过掩**：词表里加进一个**本仓真实命中过**的词（session）⇒
# 「export SESSION=abc」这种定位线索被抹掉。
# ⚠️ 方向：不是拆掉 `isCredentialKey`（散文正则的**键组**本身就带一份词表 ⇒
# 它先找到键、`isCredentialKey` 只是**否决权** ⇒ 拆掉否决权根本不改行为 ⇒
# 这样的变异是**无效的**，扫描会把它报成「守卫是假的」而其实代码没变）。
mut("散文兜底过掩", {f"{R}/redact.go": sub1(redact,
    '"token", "secret", "passphrase", "credential",',
    '"token", "secret", "passphrase", "credential", "session",')},
    "TestTheProseFormDoesNotOverMask", "./pkg/redact/")

# ⚠️ 散文兜底**吃掉 & 之后的正文** ⇒ URL 的其余参数、命令的后半条都没了 ⇒
# 留痕丢掉「到底跑了什么」。
mut("散文兜底吃掉正文", {f"{R}/redact.go": drop_block(redact,
    "if i := strings.Index(value, \"&\")")},
    "TestTheTextBehindAnAmpersandStays", "./pkg/redact/")

# ⚠️ 散文兜底**不提前** ⇒ 上游先动 ⇒ 它把转义引号里的凭据吃成一个碎片 ⇒
# 整条凭据明文留在留痕里（这是执行面最常见的形态：命令是 JSON 字符串）。
mut("散文兜底不提前", {f"{R}/redact.go": sub1(redact,
    "\ttext = maskProseCredentials(Payloads(text))\n\ttext = maskCredentialKeys(Text(text))",
    "\ttext = maskCredentialKeys(Text(Payloads(text)))\n\ttext = maskProseCredentials(text)")},
    "TestACredentialInEscapedQuotesIsMaskedWhole", "./pkg/redact/")

# ⚠️ `&` 之后的尾巴**不再重扫** ⇒ 尾巴里的第二个凭据（`?token=abc&password=x`）
# 明文进留痕（它落在这一轮匹配吃掉的值里，外层不会再看它）。
mut("散文尾巴不再重扫", {f"{R}/redact.go": swap_re(redact,
    anchor_in(redact, "maskProseCredentialsIn(value[i:]"),
    r"maskProseCredentialsIn\([^)]*\)", "value[i:]")},
    "TestTheTailBehindAnAmpersandIsScrubbedToo", "./pkg/redact/")

# ⚠️ 转义形态的替换多写了一个反斜杠 ⇒ `\\"` 在 JSON 字符串里是「转义的反斜杠」
# 后面跟一个**收尾的引号** ⇒ 文档当场不再是 JSON。
mut("转义形态多写反斜杠", {f"{R}/redact.go": sub1(redact,
    r'return `\"` + sub[1] + `\":\"****\"`',
    r'return `\\"` + sub[1] + `\\":\\"****\\"`')},
    "TestScrubbingKeepsTheDocumentReadable", "./pkg/redact/")

# ⚠️ 无引号的值（数字/布尔）不摘出 ⇒ 上游的形态规则把 `}` 一起吃掉 ⇒ 文档坏掉。
mut("无引号数字不被摘出", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "(?:true|false|null)"),
    r'|[+-]?[0-9][0-9.eE+-]*\b', "")},
    "TestScrubbingKeepsTheDocumentReadable", "./pkg/redact/")

# ⚠️ 带符号的数字不认 ⇒ `{"password":-1}` 的闭括号被吃掉 ⇒ 文档坏掉。
mut("带符号数字不被摘出", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "(?:true|false|null)"),
    r'|[+-]?[0-9][0-9.eE+-]*\b', r'|[0-9][0-9.eE+-]*\b')},
    "TestScrubbingKeepsTheDocumentReadable", "./pkg/redact/")

# ⚠️ 词边界退成「永远匹配空」⇒ "trueX" 被当成布尔摘出 ⇒ 又原样放回去 ⇒ 凭据明文。
mut("边界退成永远匹配空", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "(?:true|false|null)"),
    r'((?:true|false|null)\b|[+-]?[0-9][0-9.eE+-]*\b)',
    r'(true|false|null|[+-]?[0-9][0-9.eE+-]*)([^0-9A-Za-z_.,}\]\[]*|$)')},
    "TestAValueStartingWithTrueIsNotABoolean", "./pkg/redact/")

# ⚠️ 词边界若**吃掉**后面的分隔符 ⇒ 同一对象里的第二个无引号凭据没有前缀可用
# ⇒ 它不被摘出 ⇒ 上游的形态规则把它的 `}` 吃掉 ⇒ 文档坏掉。
mut("边界吃掉分隔符", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "(?:true|false|null)"),
    r'((?:true|false|null)\b|[+-]?[0-9][0-9.eE+-]*\b)',
    r'((?:true|false|null)([^0-9A-Za-z_]|$)|[+-]?[0-9][0-9.eE+-]*([^0-9A-Za-z_]|$))')},
    "TestScrubbingKeepsTheDocumentReadable", "./pkg/redact/")

# ⚠️ 键名规则退成「前缀必须以分隔符结尾」⇒ 上游认得、本仓不认的键
# （mytoken/dbpassword）兜底补不回结构 ⇒ 第二遍再吃一个字符 ⇒
# **两个出口不再逐字节相同**。
mut("键名规则退回分隔符前缀", {f"{R}/redact.go": sub1(redact,
    "\t\tif strings.HasSuffix(lower, w) {\n\t\t\treturn true\n\t\t}",
    "\t\tif !strings.HasSuffix(lower, w) {\n\t\t\tcontinue\n\t\t}\n\t\trest := lower[:len(lower)-len(w)]\n\t\tif rest != \"\" {\n\t\t\tif last := rest[len(rest)-1]; last == '-' || last == '_' {\n\t\t\t\treturn true\n\t\t\t}\n\t\t\tcontinue\n\t\t}\n\t\treturn true")},
    "TestScrubbingKeepsTheDocumentReadable", "./pkg/redact/")

# ⚠️ 非标量的凭据值（数组/对象）不整字段摘出 ⇒ 上游只遮住一个碎片 ⇒ 里头的
# 凭据（「value」这种不带凭据词的名字）明文留在留痕里。
mut("非标量凭据不摘出", {f"{R}/redact.go": sub1(redact,
    "\ttext, more := takeOutNonScalarCredentials(text, len(flags))",
    "\tvar more []bareCredential")},
    "TestANonScalarCredentialIsMaskedWhole", "./pkg/redact/")

# ⚠️ 词表长出一个**本仓自己参数**的名字 ⇒ 留痕不再记这个参数 ⇒
# 「查的是哪一条会话」这种定位线索没了（本仓真实命中过 session/key_id）。
# ⚠️ 与上面那条「散文兜底过掩」是**不同的编辑**（加的是 group，不是 session）
# ⇒ 指纹不同 ⇒ 两条都能查（同一处编辑只能查一次）。
mut("词表长出自家参数名", {f"{R}/redact.go": sub1(redact,
    '"token", "secret", "passphrase", "credential",',
    '"token", "secret", "passphrase", "credential", "group",')},
    "TestTheRepositorysOwnParametersAreNotMistakenForCredentials", "./internal/arch/")

# ⚠️ 兜底只用在 args 列 ⇒ error 列的同一个凭据明文落盘 ⇒ 一行两水位线。
mut("兜底只用在 args 列", {f"{A}/audit.go": audit.replace(
    "	return redact.Scrub(text)", "	return redact.Text(redact.Payloads(text))")},
    "TestTheSameCredentialLooksTheSameInEveryColumn", "./pkg/audit/")

# ⚠️ 名字过滤没了 ⇒ 清理会删掉**不是我们的**文件（操作员自己的笔记、.bak）。
mut("名字过滤失效", {f"{A}/file.go": file.replace(
    "		if !trailFileName.MatchString(base) {\n\t\t\tcontinue\n\t\t}", "")},
    "TestTheOldTrailFilesArePruned", "./pkg/audit/")

# ---- 「只洗一次」这个不变量本身 --------------------------------------------
# ⚠️ 注册表也洗一次 ⇒ 留痕再洗一次 ⇒ 第二次把掩码后的分隔符也吃掉 ⇒
# args 列少一个字符。
# ⚠️ "The arguments are scrubbed TWICE" is the bug this whole chain is
# about, and the mutation is the simplest form of it: scrub once more and
# the separator after the mask is gone.
# ⚠️ 「洗两次」这条变异按构造**不可测**了：组合脱敏（形态规则 + 凭据键兜底）
# **是幂等的** ⇒ 洗两次与洗一次结果相同 ⇒ 变异证明不了任何东西。
# ⇒ 幂等这件事本身由「凭据键兜底不生效」与「脱敏不生效」两条守着。

# ---- 活着的进程，它的文件永远不删 -------------------------------------------
# ⚠️ 进程持有这个文件：删掉名字，它随后就写进了一个没有目录项的文件 ⇒
# 留痕静默消失。mtime 分不清「死了」与「很久没被调用」⇒ 靠名字里的 pid。
# ⚠️ The direction that matters: "I cannot tell" must NOT be treated as
# "it is dead" — the caller has to fall back to the age rules.
# ⚠️ The direction that matters: "I cannot tell" must fall back to the AGE
# rules, not to "it is dead" and not to "keep it". Skipping it when the
# answer is unknown is the bug.
# ⚠️ The direction that matters: "I cannot tell" must fall back to the AGE
# rules, not to "keep it".
# ⚠️ The direction that matters: "I cannot tell" must fall back to the AGE
# rules, not to "keep it".
# ⚠️ 「pid 活」不再与「在保留期内」**一起**要求 ⇒ 一个 pid 被复用的死
# 文件会被永久钉住 ⇒ 目录可以越过保留期承诺地长。
mut("超期也钉住", {f"{A}/file.go": file.replace(
    "keepByAge(retentionDays, age) {", "true {")},
    "TestAReusedPidDoesNotPinADeadFile", "./pkg/audit/")

# ⚠️ 「判不出来」不能当成「死了」：Windows 上答「活着」会把两条 mtime 规则
# 全部短路 ⇒ 目录永远不清。这条与上面那条**各扰动一个决定** ⇒ 互不遮蔽。
# ⚠️ 这条按构造**不可测**：「判不出来」（AliveUnknown）与「活着」
# （AliveYes）的行为**没有差别** —— 两者都在保留期内保留、超期删除 ⇒
# 扰动其中一半，文件照样按同一条规则走 ⇒ 测试不会红。
# ⇒ 而「Windows 上判不出来 ⇒ 落回年龄规则」这条**没有独立行为**
# （它就是年龄规则），所以它也不需要单独的变异。
# ⇒ 「保留期」那一半由「超期也钉住」守着。

# ---- 保留期带来的假沉默：note 必须说明留痕只保留多久 -----------------------
# ⚠️ 没有这一句，「0 行匹配」就与「那天什么都没发生」长得一模一样。
mut("note 不说保留期", {f"{H}/audit.go": handler.replace(
    "				retentionNote(settings.RetentionDays))),", '				"")),')},
    "TestTheAnswerSaysHowFarBackTheTrailGoes", "./biz/handler/")

# ---- 第八轮审阅：结构内脱敏、Windows 的 unknown、pid 命名空间 -------------
# ⚠️ 脱敏退回**文本**形态 ⇒ 值内部的 `=****` 会让整段跳过 ⇒ 密码活着进留痕。
# ⚠️ The mutation has to break the STRUCTURED scrubbing itself. Falling
# back to the text scrubber would NOT be observable: a single text pass
# masks the credential fine (the leak only ever appeared on the SECOND
# pass), so that mutation proves nothing.
# ⚠️ The arguments are scrubbed by the TRAIL, once. The mutation has to
# break THAT, not a helper that is no longer on the path.
# ⚠️ 「判不出来」不能当成「死了」：Windows 上答「活着」会把两条 mtime 规则
# 全部短路 ⇒ 目录永远不清。
# ---- 第六轮审阅：脱敏幂等、不可写目录、PWD、留痕关闭的提示 -----------------
# ⚠️ 第二次脱敏不得再改字符串：脱敏器吃掉闭引号后，第二遍会把分隔符
# 也吃掉 ⇒ 两次脱敏比一次脱敏毁掉更多。
# ⚠️ 目录存在 ≠ 能写。写不进去的目录 ⇒ 整个进程生命周期里没有文件留痕，
# 而旧检查说「ok」。
mut("不可写的目录也说 ok", {f"{A}/health.go": health.replace(
    "	if err := writableProbe(dir); err != nil {", "	if false {")},
    "TestAnUnwritableTrailDirectoryIsNotHealthy")

# ⚠️ 留痕关闭时必须说明 —— 否则每个数字都在说「那就是全部」。
mut("留痕关闭不说", {f"{H}/audit.go": handler.replace(
    "trailOffNote(dir),", '"",')},
    "TestTheAnswerSaysWhenTheTrailIsOff", "./biz/handler/")

# ---- 目录不留空壳：惰性创建 + 保留策略 -------------------------------------
# ⚠️ 一个启动后没被调用过的进程，不该在留痕目录里留下一个空文件。
mut("不留空壳", {f"{A}/file.go": file.replace(
    "	return &trailFile{path: path, max: MaxTrailBytes}",
    "	f, err := openAppend(path)\n\tif err != nil {\n\t\treturn nil\n\t}\n\treturn &trailFile{f: f, path: path, max: MaxTrailBytes}")},
    "TestAProcessThatWritesNothingLeavesNoFile")

# ⚠️ 清理的每一条规则都各有一次「删错了就是毁证据」的可能。
mut("清理不删空文件", {f"{A}/file.go": file.replace(
    "		case info.Size() == 0:", "		case false:")},
    "TestTheOldTrailFilesArePruned")

mut("清理不看保留期", {f"{A}/file.go": file.replace(
    "		case retentionDays > 0:", "		case false:")},
    "TestTheOldTrailFilesArePruned")

# ---- 第五轮审阅：落盘侧别再洗一遍、截断的值算未知、僵死的半行要计数 -------
# ⚠️ 落盘侧自己再洗一遍 ⇒ 两个出口写了**不同的字符串**，而文件那份是坏的
# （少一个逗号）：logredact 不是幂等的。
# ⚠️ 这条变异按构造**不可测**了：scrub 幂等之后，落盘侧再洗一遍得到的是
# 同一个字符串 ⇒ 两侧仍然逐字节相同 ⇒ 「两侧一致」那条断言不会红。
# ⇒ 它不再测任何东西，删掉；「幂等」本身由「脱敏不幂等」那条守着。

# ⚠️ 收尾引号是这条正则的一部分：值被切在中间 ⇒ 读不出来 ⇒ 算「未知」
# ⇒ 保守计入。少了收尾引号，半截值会被当成「与你要的无关」。
mut("截断的值当成整值", {f"{A}/read.go": read.replace(
    'regexp.MustCompile(`"([^"\\\\]*)"\\s*:\\s*"([^"\\\\]*)"`)',
    'regexp.MustCompile(`"([^"\\\\]*)"\\s*:\\s*"([^"\\\\]*)`)')},
    "TestACutOffValueCountsAsUnknown")

# ⚠️ 正在写的最后一行只在文件**还活着**时豁免：进程被杀留下的半截尾行，
# 安静超过五分钟就要计数。
mut("僵死的半行也豁免", {f"{A}/read.go": read.replace(
    "return rerr == io.EOF && !touched.IsZero() && time.Since(touched) < halfWrittenGrace",
    "return rerr == io.EOF")},
    "TestAStaleHalfWrittenLineIsCounted")

# ---- 这一轮：空目录、坏行、短写、doctor -------------------------------------
# ⚠️ 两侧对同一个空值必须说同一句话。写侧说「没有目录 = 留痕关闭」，
# 读侧曾经说「没有目录 = 去当前工作目录找」—— 而一个形状像留痕的
# 文件名，就是一张通行证。
mut("空目录照样去读工作目录", {f"{A}/read.go": read.replace(
    """	dir := strings.TrimSpace(fspath.ExpandHome(opts.Dir))
	if dir == "" {
		return Result{}, nil
	}""", """	dir := strings.TrimSpace(fspath.ExpandHome(opts.Dir))""")},
    "TestAnEmptyTrailDirectoryReadsNothing")

# ⚠️ 读不了的行必须被**说出来**。太长的那种数了，解析不了的那种曾经
# 一声不响 —— 答复于是又变回「那是全部」。
mut("坏行不计数", {f"{A}/read.go": read.replace(
    """				if !halfWritten(rerr, touched) && unreadableIsRelevant(text, opts) {
					skipped++
				}""", """				if false {
					skipped++
				}""")},
    "TestALineThatDoesNotParseIsCounted")

# ⚠️ 但正在写的那一行不算：它没写完，不是坏了。下一次读它就完整了。
mut("半写的最后一行也计数", {f"{A}/read.go": read.replace(
    """				if !halfWritten(rerr, touched) && unreadableIsRelevant(text, opts) {
					skipped++
				}""", """				if unreadableIsRelevant(text, opts) {
					skipped++
				}""")},
    "TestAHalfWrittenLineIsSkipped")

# ⚠️ 读不了的行只能算「可能与你要的有关的」：别的工具的坏行混进来，
# agent 会以为「有一条我关心的拒绝记录读不出来」。
mut("坏行不判相关性", {f"{A}/read.go": read.replace(
    """				if !halfWritten(rerr, touched) && unreadableIsRelevant(text, opts) {""",
    """				if !halfWritten(rerr, touched) && true {""")},
    "TestABrokenLineAboutAnotherToolIsNotCounted")

mut("长行不判相关性", {f"{A}/read.go": read.replace(
    """			if unreadableIsRelevant(string(line), opts) {""",
    """			if true {""")},
    "TestABrokenLineAboutSomethingElseIsNotCounted")

# ⚠️ 半行后面没有换行 ⇒ 下一行会粘上去 ⇒ 两行都读不回来，而且没人
# 知道。写侧要给它补一个换行，把它封成自己的一行。
mut("短写不补换行", {f"{A}/file.go": file.replace(
    """		if n > 0 {
			if _, e := t.f.Write([]byte{'\\n'}); e == nil {
				t.size++
			}
		}""", "")},
    "TestAPartialWriteDoesNotGlueTheNextLine")

# ⚠️ 两个服务的留痕目录各自配置 ⇒ 各自要报自己的那一份。
mut("doctor 不报留痕", {f"{S}/onboarding.go": onboarding.replace(
    "	if trail != nil {", "	if false && trail != nil {")},
    "TestTheDoctorReportsTheTrail", "./biz/handler/")

# ⚠️ 「不知道」与「没有」是两种沉默，不该长得一样。
mut("doctor 不知道也说", {f"{S}/onboarding.go": onboarding.replace(
    "	if trail != nil {",
    "	if trail == nil { trail = &audit.Settings{Mode: \"file\"} }\n	if trail != nil {")},
    "TestTheDoctorSaysNothingAboutTheTrailWhenItCannotKnow", "./biz/handler/")

# The canary is a mutation that MUST turn the test red. It runs FIRST, and
# if it stays green the sweep stops right there: a green canary means the
# overlay did not take effect, so every other mutant would have run
# against UNMUTATED code — and the sweep would report "the guards are
# fake" when the truth is "the sweep did nothing".
#
# ⚠️ This is not hypothetical: the fourth review ran the script from /tmp
# on macOS and got 0/32, because /tmp is a symlink to /private/tmp and the
# overlay's keys no longer matched the paths Go resolves.
# ⚠️ The canary has to be a mutation that CANNOT stay green. The first
# attempt was "the ceiling becomes 1" — and the test adapted to it (it
# computes its expectation FROM the constant), so the canary stayed green
# and the sweep would have stopped for the wrong reason.
#
# This one removes the "was it cut?" branch: the column is no longer cut
# but still carries the marker, so the column is over the ceiling and the
# test turns red.
CANARY = ("【canary】上限整个不裁", {f"{A}/audit.go": sub1(audit,
    'func clip(s string, n int) string {\n\treturn textx.Trunc(s, n, "…(clipped)")\n}',
    'func clip(s string, n int) string {\n\treturn s\n}')},
    "TestEveryFreeTextColumnHasACeiling", "./pkg/audit/")


# ---- 这一轮：底座的散文形态 + 答复面（管理面）的脱敏 ----------------------
# ⚠️ 这一节的锚点**全部**取自源码（anchor_in / swap / swap_re / drop_block）
# ⇒ 「源码 ↔ 变异」之间不可能差一层转义 ⇒ 变异不会静默地什么都改不到 ⇒
# 扫描报「变异没生效」而真正的问题（守卫根本没被跑到）永远浮不出来这件事，
# 从这里没有余地。
#
# ⚠️ 散文形态那几条（过掩 / 吃掉正文 / 不提前 / 尾巴不再重扫）在前面的几轮
# 里已经各有一条 ⇒ 同一处编辑不能登记两次（指纹一样 ⇒ 第二条会被算成
# 「没新增检查」）⇒ 这一节补的是**另一处**编辑，或**另一条路径**（答复面）。

# ⚠️ 散文规则**不跑第二遍** ⇒ 形态规则停在第一个 `&` 之后的那截尾巴没人
# 收 ⇒ 凭据的尾巴明文进留痕。
mut("散文规则不跑第二遍", {f"{R}/redact.go": sub1(redact,
    anchor_in(redact, "text = maskProseCredentials(text)"),
    "")},
    "TestTheFreeTextRuleRunsTwice", "./pkg/redact/")

# ⚠️ 参数名**不再靠问号认** ⇒ "PASSWORD=AAA&bbb=1" 的尾巴被当成另一个
# 参数留着 ⇒ 凭据的尾巴明文进留痕。
mut("参数名不再靠问号认", {f"{R}/redact.go": sub1(redact,
    anchor_in(redact, "return InQueryString(before)"),
    "\treturn true")},
    "TestAnAmpersandInsideACredentialIsNotASeparator", "./pkg/redact/")

# ⚠️ 问号判定**不看是不是同一个查询串** ⇒ 前一句里的一个问号替这条 `&`
# 开了口子 ⇒ 凭据的尾巴明文进留痕。
# ⚠️ 整块换掉（判定 + 它算出来的那一段）⇒ 留着那段就会变成**没用到的
# 变量** ⇒ 编译不过 ⇒ 而编译失败不是守卫立功。
mut("问号判定不看是不是同一个查询串", {f"{R}/redact.go": sub1(redact,
    two_lines(redact, "tail := before[i+1:]"),
    "\treturn strings.Contains(before, \"?\")")},
    "TestOnlyTheSameQueryStringLicensesASeparator", "./pkg/redact/")

# ⚠️ null 的判定**大小写敏感** ⇒ "NULL" 被当成凭据 ⇒ 「没有密码」这个
# 事实变成了一串掩码。
mut("null 判定大小写敏感", {f"{R}/redact.go": sub1(redact,
    anchor_in(redact, "EqualFold(v, \"null\")"),
    "\treturn v == \"null\"")},
    "TestAFactIsAFactWhateverItsSpelling", "./pkg/redact/")

# ⚠️ 转义兜底的值形态**跨字段** ⇒ 一次匹配吞掉两个字段 ⇒ 第二个字段里的
# 凭据跟着逃了（真留痕里见过：`{\"username\":\"admin\",\"password\":\"…\"}`）。
mut("转义兜底的值跨字段", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "unquotedValueShape + `)", 1),
    r'\\[^"]', r'\\.')},
    "TestACredentialInsideAnEscapedJSONStringIsMasked", "./pkg/redact/")

# ⚠️ 转义的替换**少写一个反斜杠** ⇒ 文档当场不再是文档（下一个读它的
# 人读出来的是另一个东西）⇒ 而两个出口也不再逐字节相同。
# ⚠️ 少的那一个就是**形状**：转义的深度就是文档的形状 ⇒ 少一个反斜杠，
# 嵌套文档里的引号就不再是转义的了。
# ⚠️ 上面那条「转义形态多写反斜杠」是多写一个 ⇒ 两条是**同一个形状的两
# 个方向** ⇒ 指纹不同 ⇒ 两条都能查。
mut("转义形态少写反斜杠", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, r'return `\"` + sub[1]'),
    r'return `\"` + sub[1]', 'return `"` + sub[1]')},
    "TestTheDoubleEscapedDocumentKeepsItsEscaping", "./pkg/redact/")

# ⚠️ 无引号的值形态**吃引号** ⇒ 形态规则把下一个字段的引号一起吃掉 ⇒
# 那个字段整个消失 ⇒ 留痕丢掉一条事实。
mut("无引号值吃引号", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "const unquotedValueShape"),
    r'[^\s",}\]\[{}]*', r'[^\s,}\]\[{}]*')},
    "TestAnUnquotedValueDoesNotEatTheNextField", "./pkg/redact/")


# LOCAL_WORD_LIST is the answer path's OWN word list — the one the shared
# base was supposed to replace.
#
# ⚠️ It is written down HERE (and appended by the mutation) because it IS
# the old shape: the answer path used to carry a list of its own, the two
# lists drifted, and fourteen words the trail knows were unknown here ⇒
# `passphrase=hunter2` reached the agent in the clear while the JSON form
# of the SAME word was masked.
#
# ⚠️ The whole mutation is an APPEND: the answer path's own init() hands
# the free-text rule a locally-worded pattern ⇒ one place, no in-place
# edit, and the appended text does not count as a place either.
LOCAL_WORD_LIST = """

// localCredentialWords is the answer path's OWN word list.
//
// ⚠️ It is the drift the shared base exists to prevent: the trail's list
// knows fourteen more words than this one ("passphrase", "credential",
// "cookie", "kubeconfig", "id_token", "refresh_token", …) ⇒ those words
// reach the agent in the clear.
var localCredentialWords = []string{
	"private_key", "private-key",
	"password", "passwd",
	"token", "secret",
	"api_key", "api-key",
	"access_key", "access-key",
	"client_secret", "client-secret",
	"auth_token", "auth-token",
	"session_key", "session-key",
}

// localCredentialWordPattern is the alternation of those words.
func localCredentialWordPattern() string {
	return strings.Join(localCredentialWords, "|")
}

// localCredentialKey says whether a field name says the value is a
// credential — by THIS path's own list.
func localCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	for _, w := range localCredentialWords {
		if strings.HasSuffix(lower, w) {
			return true
		}
	}
	return false
}

// ⚠️ 变异：答复面不再共用留痕面的词表 ⇒ 自由文本那条规则用的是**本地**
// 的一份 ⇒ 留痕面认识的十四个词它不认识 ⇒ `passphrase=hunter2` 原样进
// agent 的上下文窗口，而同一个词的 JSON 形态被抹了。
func init() {
	secretValueRe = regexp.MustCompile(
		`(?i)([a-z0-9_.-]*(?:` + localCredentialWordPattern() + `))(\\s*[:=]\\s*)` +
			`("(?:[^"\\\\]|\\\\[^"])*"|'[^']*'|[^\\s"'&]+)(&[^&\\r\\n]*)?`)
	_ = localCredentialKey
}
"""

# ⚠️ 留痕的散文规则**不认空白分隔** ⇒ "--password secret" 这种命令行
# 形状在留痕里不被遮蔽 ⇒ 而答复路径遮它 ⇒ 同一个词、同一个形状，两条
# 路径一个遮一个不遮 ⇒ 正是这个仓整套演练要防的那种漂移。
# ⚠️ 分隔符**有**空白那一支 ⇒ 去掉它，"=" 与 ":" 两种仍然遮 ⇒ 这一条
# 只管那第三种写法。
mut("留痕的散文规则不认空白分隔", {f"{R}/redact.go": swap(redact,
    anchor_in(redact, "credentialWordPattern + `))"),
    r"(?:\s*[:=]\s*|[ \t]+)", r"(?:\s*[:=]\s*)")},
    "TestTheTrailMasksTheCommandLineShapes", "./pkg/redact/")


# ---- 答复面（管理面）：它有自己的一整套规则 ------------------------------
# ⚠️ 答复面不是留痕面：它把**值**抹掉、把**键名与 scheme 留下**（读它的
# 是 agent，它得看得见「跑了什么」）⇒ 形状与留痕面不同是**故意的**。
# ⚠️ 但**词表只有一份**（pkg/redact）⇒ 一个词在两条路径上要么都认、要么
# 都不认 ⇒ 下面第一条守的就是这件事。

# ⚠️ 答复面**不共用词表** ⇒ 十四���词（passphrase/credential/cookie/
# kubeconfig/id_token/refresh_token…）它不认识 ⇒ `passphrase=hunter2` 到
# 了 agent 的明文里，而同一个词的 JSON 形态被抹了 ⇒ 一个词在两条路径上
# 一个抹一个不抹。
mut("答复不共用词表", {f"{S}/redact.go": answer + LOCAL_WORD_LIST},
    "TestRedactSecretsUsesTheSharedWordList", "./biz/handler/")

# ⚠️ 答复面**不认 JSON 形态** ⇒ `{"password":"x"}` 原样进 agent 的上下文
# 窗口（实测 12/12 全漏）。
mut("答复不认 JSON 形态", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "return redactJSONCredentials(s)"),
    "\treturn s")},
    "TestRedactSecretsMasksTheJSONForm", "./biz/handler/")

# ⚠️ 答复面**不抹非标量** ⇒ 只抹掉一个碎片 ⇒ 里头的凭据（名字里没有
# 凭据词的那个）明文留着，文档还坏了。
mut("答复不抹非标量", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "s = maskNonScalarCredentials(s)"),
    "")},
    "TestRedactSecretsMasksNonScalarValues", "./biz/handler/")

# ⚠️ 答复面**把事实也抹了** ⇒ 「这个账号**有**密码」与「这个账号**没有**
# 密码」变成了同一句话。
mut("答复把事实也抹了", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "if isFactLiteral(sub[2]) {"),
    "\t\tif false {")},
    "TestRedactSecretsKeepsTheFacts", "./biz/handler/")

# ⚠️ 答复面**抹掉认证 scheme** ⇒ 记录里不再说得清「怎么认证的」。
mut("答复抹掉认证 scheme", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "return sub[1] + scheme"),
    "\t\treturn sub[1] + answerMarker")},
    "TestRedactSecretsKeepsTheAuthScheme", "./biz/handler/")

# ⚠️ 答复面**不抹 URL 内嵌的凭据** ⇒ 它没有键名 ⇒ 任何按键名的规则都
# 抓不到它 ⇒ 明文进 agent 的上下文窗口。
mut("答复不抹 URL 内嵌凭据", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "urlCredentialRe.ReplaceAllString(s,"),
    "")},
    "TestRedactSecretsMasksTheURLCredential", "./biz/handler/")

# ⚠️ 答复面**只抹认证头的第一个词** ⇒ Digest 的 response 哈希活着。
mut("答复只抹认证头第一个词", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "authParamsRe.ReplaceAllString(s,"),
    "")},
    "TestRedactSecretsMasksTheAuthCredentialOnly", "./biz/handler/")

# ⚠️ 答复面**不抹查询串参数** ⇒ "?token=abc" 里的 token 原样进上下文。
mut("答复不抹查询串参数", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "queryParamRe.ReplaceAllStringFunc(s,"),
    "\ts = queryParamRe.ReplaceAllStringFunc(\"\", func(m string) string {")},
    "TestRedactSecretsMasksQueryParameters", "./biz/handler/")

# ⚠️ 答复的散文规则**不认空白分隔** ⇒ 「the password was v」这种「键 +
# 空格 + 值」的形状在留痕路径被抹、在答复路径不被抹 ⇒ 两条路径对同一个
# 形状强弱相反（同一个词、同一件事，两条路径给出不同的答案）。
mut("答复的散文规则不认空白分隔", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, "redact.CredentialWordPattern() + `))((?:"),
    "))((?:\\s*[:=]\\s*|[ \\t]+))",
    "))(\\s*[:=]\\s*)")},
    "TestRedactSecretsMasksTheProseShapeWithASpace", "./biz/handler/")

# ⚠️ 答复的散文规则**退回任意键** ⇒ 匹配从「凭据」那里开始变成从「前面
# 那个词」开始 ⇒ "login failed: password: x" 的凭据从来没有自己的匹配 ⇒
# 它到了 agent 的明文里。
mut("答复的散文规则退回任意键", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, "redact.CredentialWordPattern()", 0),
    r'([a-z0-9_.-]*(?:` + redact.CredentialWordPattern() + `))', r'([a-z0-9_.-]+)')},
    "TestRedactSecretsFindsTheCredentialWhereverItIs", "./biz/handler/")

# ⚠️ 答复的**命令行参数不独立** ⇒ 前缀组没了 ⇒ 组号整个挪了一位 ⇒ 回调
# 里的 sub[1..3] 不再是「前缀/名字/分隔符」⇒ **值被原样写回** ⇒ 凭据活着。
# ⚠️ 守卫挂在「命令行参数只被抹一次」那条上：幂等那条的输入里没有一个
# 带「--」又带「=」的 ⇒ 它看不见这一处。
mut("答复的命令行参数不独立", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, "redact.CredentialWordPattern()", 1),
    r'(?i)(^|[^a-z0-9_.-])(--?', r'(?i)(--?')},
    "TestRedactSecretsMasksACommandLineArgumentOnce", "./biz/handler/")

# ⚠️ 答复的 URL 凭据**只吃第一个 @** ⇒ 密码里自己的 @ 之后那一截留在
# 明文里（"https://user:[REDACTED]@ss@host"）。
mut("答复的 URL 凭据只吃第一个 at", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, "amqp)://"),
    r'([^\s]+)@', r'([^\s@]+)@')},
    "TestRedactSecretsMasksTheURLAndQueryShapes", "./biz/handler/")

# ⚠️ 答复的查询串参数**不认引号** ⇒ "?token=\"a b\"" 的引号站在掩码旁边
# ⇒ 值**一半**在明文里。
mut("答复的查询串参数不认引号", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, "([?&])"),
    r"""("[^"]*"|'[^']*'|[^\s&"']*)""", r"""([^\s&"']*)""")},
    "TestRedactSecretsMasksTheURLAndQueryShapes", "./biz/handler/")

# ⚠️ 答复**不认转义的散文形态** ⇒ 值的形态停在反斜杠 ⇒ 凭据站在它后面
# 明文里（`{"cmd":"export PASSWORD=\"SECRET\""}`）。
mut("答复不认转义的散文形态", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, r"(?i)([a-z0-9_.-]+)(\s*[:=]\s*)"),
    r'(\\"(?:[^"\\]|\\[^"])*\\")', r'("[^"]*")')},
    "TestRedactSecretsMasksTheEscapedProseForm", "./biz/handler/")


# ---- 答复面的另外四处：这一轮修的东西，答复面也得有自己的守卫 ----------
# ⚠️ 答复面与留痕面是**两条路径**：留痕面有的规则，答复面没有 ⇒ 凭据从
# 答复里走进 agent 的上下文窗口（留痕里看不见，因为留痕不是它）。

# ⚠️ 答复的 `&` **不再靠问号认** ⇒ "PASSWORD=AAA&bbb=1" 的尾巴被当成
# 另一个参数留着 ⇒ 凭据的尾巴明文进上下文窗口。
mut("答复的 & 不再靠问号认", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "return redact.InQueryString(before)"),
    "\treturn true")},
    "TestRedactSecretsHandlesTheAmpersand", "./biz/handler/")

# ⚠️ 答复**不认双层转义的 JSON** ⇒ SDK 序列化的参数是转义**两次**的 ⇒
# 一层那条规则看不见它 ⇒ 凭据原样进上下文窗口。
mut("答复不认双层转义的 JSON", {f"{S}/redact.go": drop_block(answer,
    "answerDoubleEscapedKeyRe.ReplaceAllStringFunc(s,", closer="})")},
    "TestRedactSecretsMasksTheDoubleEscapedJSON", "./biz/handler/")

# ⚠️ 答复的 JSON **无引号值吃引号** ⇒ 形态规则把下一个字段的引号一起
# 吃掉 ⇒ 那个字段整个消失 ⇒ 答复丢掉一条事实。
mut("答复的 JSON 无引号值吃引号", {f"{S}/redact.go": swap(answer,
    anchor_in(answer, r'[^\s",}\]\[{}]*'),
    r'[^\s",}\]\[{}]*', r'[^\s,}\]\[{}]*')},
    "TestRedactSecretsDoesNotEatTheNextField", "./biz/handler/")

# ⚠️ 答复的认证头**不认没有凭据的 scheme** ⇒ "authorization: bearer" 是
# 一条**事实**（怎么认证的），不是凭据 ⇒ 抹了它，记录里就凭空多出一个
# 掩码，而读的人会以为那里本来有秘密。
mut("答复不认没有凭据的 scheme", {f"{S}/redact.go": sub1(answer,
    anchor_in(answer, "if isAuthScheme(sub[3]) {"),
    "\t\tif false {")},
    "TestRedactSecretsKeepsASchemeWithoutACredential", "./biz/handler/")


def fingerprint(path, content):
    """WHERE a mutation changed something — its fingerprint.

    Two mutations with the SAME fingerprint are the same edit under two
    names, and the sweep would count one of them twice: the headline
    number would be bigger than the number of things actually checked.

    ⚠️ The position has to be CHARACTER level. A line-level fingerprint
    called two edits on the same line "the same edit" — and one of them
    was in a different function entirely (the clip and the truncate).

    ⚠️ The path is part of the fingerprint: the same edit in two
    DIFFERENT files is two checks, not one.

    ⚠️ ⚠️ And it has to be LINEAR. The first version used
    difflib.SequenceMatcher(autojunk=False) — with the "popular
    elements" heuristic switched OFF, that is quadratic on a source file
    (Go code is full of repeated spaces and braces) ⇒ the fingerprint
    check alone ate a whole sweep, and it got worse as the files grew.
    ⇒ The common prefix and the common suffix say the same thing in
    one pass.
    """
    old = open(path).read()
    if old == content:
        return (path, "identical")
    i = 0
    n = min(len(old), len(content))
    while i < n and old[i] == content[i]:
        i += 1
    j = 0
    while j < n - i and old[len(old) - 1 - j] == content[len(content) - 1 - j]:
        j += 1
    return (path, i, len(old) - j, len(content) - j,
            hash(old[i:len(old) - j]), hash(content[i:len(content) - j]))


def _narrow(original, mutated):
    """The DIFFERING region of two texts, as LINES.

    ⚠️ The narrowing is done on LINES, not on bytes: a byte-level cut
    lands in the MIDDLE of a line ⇒ the first and the last line of the
    region are half lines ⇒ they differ in both texts ⇒ the diff reports
    a change that is not there ⇒ every mutation looks like it touched
    two places.
    ⚠️ The prefix and the suffix are cut at line boundaries ⇒ the region
    is a whole number of lines ⇒ the diff compares whole lines.
    """
    old = original.split("\n")
    new = mutated.split("\n")
    p = 0
    while p < len(old) and p < len(new) and old[p] == new[p]:
        p += 1
    s = 0
    while (s < len(old) - p and s < len(new) - p
           and old[len(old) - 1 - s] == new[len(new) - 1 - s]):
        s += 1
    return old[p:len(old) - s], new[p:len(new) - s]


def edit_sites(original, mutated):
    """How many SEPARATE places a mutation changed.

    ⚠️ The count is of CONTIGUOUS line ranges, not of diff opcodes: one
    line turned into three lines is ONE change, and an opcode-based
    count would call it two (a delete plus an insert) ⇒ every mutation
    that rewrites a line would look like a mutation that touches two
    places ⇒ and the "one mutation, one place" rule would fire on half
    the set.
    ⚠️ The ranges are counted in the ORIGINAL's line numbers: an
    insertion belongs to the block it was inserted next to ⇒ the range
    of an insert is the line it sits AFTER ⇒ a block that was rewritten
    into a longer block (the tail of which happens to match a line of
    the original) still counts as ONE place.
    """
    if original == mutated:
        return 0
    old_lines, new_lines = _narrow(original, mutated)
    matcher = difflib.SequenceMatcher(None, old_lines, new_lines, autojunk=False)
    ranges = []
    for tag, i1, i2, _j1, _j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "insert":
            # The insertion sits BEFORE the original's line i1 ⇒ it
            # belongs to whatever was changed just before it.
            at = max(i1 - 1, 0)
            ranges.append((at, at))
        else:
            ranges.append((i1, i2))
    ranges.sort()
    sites = 0
    end = None
    for a, b in ranges:
        if end is None:
            sites, end = 1, b
        elif a <= end:
            end = max(end, b)
        else:
            sites, end = sites + 1, b
    return sites


def appended_bytes(original, mutated):
    """How many bytes the mutation APPENDED at the END of the file.

    ⚠️ The judgement is made on BYTES, not on lines: a line that got
    LONGER is not an append — those bytes belong to that line, they did
    not arrive at the end of the file. ⇒ the common PREFIX says where
    the original stopped, and only what is behind it counts.
    ⚠️ The appended text must start at a LINE boundary ⇒ otherwise the
    last line merely grew.
    """
    if len(mutated) <= len(original):
        return 0
    i = 0
    while i < len(original) and original[i] == mutated[i]:
        i += 1
    if i < len(original):
        # The original was changed IN PLACE ⇒ nothing was appended.
        return 0
    tail = mutated[i:]
    if not tail.endswith("\n"):
        # The last line grew ⇒ that is not an append.
        return 0
    return len(tail)


def effective_sites(original, mutated):
    """The number of places a mutation changed, APPEND excluded.

    ⚠️ An appended block (a helper function, a word list) is not a
    "place the mutation edited" ⇒ it must not be counted as one ⇒ the
    count is taken over the text WITHOUT the appended tail.
    """
    appended = appended_bytes(original, mutated)
    if appended:
        mutated = mutated[:len(mutated) - appended]
    return edit_sites(original, mutated)


# ⚠️ **同一条测试可能住在不止一个仓里**：守卫住在各仓自己的 internal/arch/，
# 而同一个相对包路径在几个仓里都存在 ⇒ 「谁声明了这个测试函数」是唯一
# 不靠猜的判据（按包路径猜 = 在错的代码上跑，而那看起来跟「守卫是假的」
# 一模一样）。
_TEST_INDEX = None


def test_index():
    global _TEST_INDEX
    if _TEST_INDEX is None:
        _TEST_INDEX = workset.index_tests(ROOTS)
    return _TEST_INDEX


def test_homes(test, pkg):
    """这条测试住在哪些仓的哪些包里。"""
    homes = test_index().get(test)
    if homes:
        return homes
    # 找不到声明处 ⇒ 退回条目里写着的包路径（在工作集里找那个目录）。
    rel = pkg.strip("./").rstrip("/")
    return [(r, rel) for r in ROOTS if os.path.isdir(os.path.join(r, rel))]


def run_one(name, files, test, pkg, verbose):
    """Run one mutation. Returns "red", "green" or "build-failed"."""
    replace = {}
    for path, content in files.items():
        tmp = os.path.join(OUT, f"{name}_{os.path.basename(path)}")
        open(tmp, "w").write(content)
        replace[path] = tmp
    overlay = os.path.join(OUT, f"overlay_{name}.json")
    json.dump({"Replace": replace}, open(overlay, "w"))

    homes = test_homes(test, pkg)
    if not homes:
        print(f"⚠️  {name}: 工作集里找不到 {test} 的声明处 —— 这个变异不算数")
        return "green"

    green = False
    build_failed = False
    for repo, pkgdir in homes:
        p = subprocess.run(
            ["go", "test", "-v", "-overlay=" + overlay, "./" + pkgdir,
             "-run", "^" + test + "$"],
            cwd=repo, capture_output=True, text=True,
            # ⚠️ PWD must be realpath too: Go's os.Getwd() believes $PWD
            # over the real path, so the go command resolves the package
            # through the SYMLINK path while the overlay key is the
            # realpath — and the overlay is then silently ignored, i.e.
            # every mutant runs against UNMUTATED code.
            #
            # ⚠️ JMS_SIBLING_ROOTS 一起传下去：守卫要知道另外两个仓在哪。
            env={**os.environ, "GOFLAGS": "-mod=readonly", "GOPROXY": "off",
                 "PWD": repo, "JMS_SIBLING_ROOTS": SIBLING_ENV})
        out = p.stdout + p.stderr
        # ⚠️ The test has to have RUN. A -run pattern that matches nothing
        # exits 0 — and "nothing ran, so it is green" is exactly how a
        # mutation sweep lies to you.
        ran = ("--- PASS: " + test) in out or ("--- FAIL: " + test) in out
        if not ran:
            if "build failed" in out or "[setup failed]" in out or "cannot use" in out:
                # The mutation broke the build. That is the COMPILER catching
                # it, not the guard — so it is counted apart, and it does not
                # go into the headline number.
                build_failed = True
                continue
            print(f"⚠️  {name}: 测试**没跑**（{repo} 的 {pkgdir} 里没有 {test}）")
            continue
        if p.returncode != 0:
            if verbose:
                print(f"✅ {name}: {test} 变红（{os.path.basename(repo)}）")
            return "red"
        green = True
    if verbose and green:
        print(f"❌ {name}: {test} 仍绿 —— 守卫是假的")
    if build_failed:
        if verbose:
            print(f"🧱 {name}: 编译失败（编译器逮住了改动，测试没跑到 —— 不算守卫立功）")
        return "build-failed"
    return "green"


def report_stale():
    """⚠️ 一次报全部 —— 不是第一个就退出。

    ⚠️ 报不出来才是最难查的那种错：一条锚点坏了，别的锚点也坏了，而
    一次一个 ⇒ 一轮十几分钟 ⇒ 改一个跑一轮 ⇒ 一轮下来才发现下一个。
    ⇒ 这里把全部坏锚点一次列出来，退出码是 1。
    """
    if not STALE:
        return False
    print(f"⚠️  变异目标有问题（{len(STALE)} 处）：锚点不唯一或没匹配上")
    for old, n in STALE:
        print(f"   - {n} 处: {old!r}")
    return True


def main():
    verbose = "-v" in sys.argv
    os.makedirs(OUT, exist_ok=True)

    # ⚠️ 锚点坏了 ⇒ 那几条变异**什么都没改** ⇒ 这一轮的数字不作数 ⇒
    # 不跑那十几分钟的扫描，直接把全部坏锚点报出来。
    if report_stale():
        return 1

    # The canary first, and alone.
    name, files, test, pkg = CANARY
    for path, content in files.items():
        if content == source_of(path):
            print(f"⚠️  canary: 变异没生效（模式没匹配上）")
            return 1
    print("先跑 canary：")
    if run_one(name, files, test, pkg, True) != "red":
        print("❗ canary 没有变红 ⇒ overlay 没生效，后面每一条变异都会跑在**未变异的代码**上。")
        print("   （这一轮的数字不作数。）")
        return 1
    print()

    survivors = []
    build_failed = []
    # The same edit under two names is one edit, and the headline would
    # count it twice.
    prints = {}
    for mname, (mfiles, mtest, mpkg) in M.items():
        for mpath, mcontent in mfiles.items():
            fp = fingerprint(mpath, mcontent)
            if fp in prints:
                print(f"⚠️  {mname}: 与「{prints[fp]}」是同一处编辑 —— 这一条没有新增检查")
                survivors.append(mname)
            else:
                prints[fp] = mname

    # ⚠️ 三道机器检查里的第二道：一次变异只能改一处。
    # ⚠️ 一条变异改两处 ⇒ 它同时动了两条守卫 ⇒ 报告说「一条」而实际上
    # 「两条」⇒ 数字比实际弱 ⇒ 而弱的那一处没人知道 ⇒ 它得被写下来。
    site_checked = 0
    site_violations = []
    appended_mutations = []
    for name, (files, test, pkg) in M.items():
        for path, content in files.items():
            original = source_of(path)
            if appended_bytes(original, content):
                appended_mutations.append(name)
            sites = effective_sites(original, content)
            site_checked += 1
            if sites > 1 and name not in ALLOWED_SITES:
                site_violations.append((name, sites, path))

    for name, (files, test, pkg) in M.items():
        if name in survivors:
            continue
        broken = False
        for path, content in files.items():
            if content == source_of(path):
                print(f"⚠️  {name}: 变异没生效（模式没匹配上）")
                broken = True
                break
        if broken:
            survivors.append(name)
            continue
        outcome = run_one(name, files, test, pkg, verbose)
        if outcome == "build-failed":
            build_failed.append(name)
        elif outcome == "green":
            survivors.append(name)
    total = len(M)
    print()
    print(f"{total - len(survivors) - len(build_failed)}/{total} 个变异被**测试**杀掉")
    # ⚠️ The compile failures are counted apart and printed ALWAYS: they
    # prove the compiler caught the change, not that the guard did, and
    # folding them into the headline made a sweep look stronger than it
    # was.
    if build_failed:
        print(f"另有 {len(build_failed)}/{total} 个变异编译失败（编译器逮住，测试没跑到 —— 不算守卫立功）:")
        for n in build_failed:
            print("   -", n)
    # ⚠️ 三道检查都要**说出来** ⇒ 静默的检查等于没有检查。
    print()
    print(f"🔍 锚点唯一性：{len(M)} 条变异的锚点全部唯一（无重复、无未匹配）")
    print(f"🔍 一次变异只改一处：核对了 {site_checked} 处改动，"
          f"{len(site_violations)} 处越界"
          f"（ALLOWED_SITES 登记了 {len(ALLOWED_SITES)} 条**必须**改多处的）")
    for name, sites, path in site_violations:
        print(f"   ⚠️  {name}: 一条变异改了 {sites} 处（{path}）")
    print(f"🔍 追加的文本不算一处：{len(appended_mutations)} 条变异带追加"
          f"（追加的部分不计入改动处数）")
    # ⚠️ 源码在扫描期间被改过 ⇒ 这一轮的数字对着的是**开始时的快照** ⇒
    # 那些改动**不在**任何一个变异体里 ⇒ 数字要重跑才算数。
    drifted = [p for p, snap in SOURCES.items()
               if os.path.exists(p) and open(p).read() != snap]
    if drifted:
        print(f"⚠️  扫描期间源码被改过（{len(drifted)} 个文件）⇒ 这一轮的数字对着"
              f"的是开始时的快照 ⇒ 改动落地后请重跑:")
        for p in drifted:
            print("   -", workset.rel_to_repo(p, ROOTS))
    if site_violations:
        # 一条变异改了两处 ⇒ 它算「没被守住」⇒ 不能算进头条数字。
        for name, _sites, _path in site_violations:
            if name not in survivors:
                survivors.append(name)
    if report_stale():
        return 1
    if survivors:
        print("存活（假守卫）:", survivors)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
