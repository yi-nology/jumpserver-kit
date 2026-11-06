#!/usr/bin/env python3
"""变异测试：把「委派凭据必须有门禁」这条规则的每一处实现退回一次，
看 internal/arch 的守卫**会不会变红**。

为什么它在仓里：一份「全都验过了」的证据，如果只躺在 /tmp 里，机器一重启
就没了，下一轮谁也复现不了 ⇒ 而「守卫必须自证会红」正是本仓的规矩。

用法（在底座仓根目录）：

    python3 script/mutate-version-guard.py            # 跑全部变异
    python3 script/mutate-version-guard.py -v         # 顺带打印每个变异做了什么

工作集（哪些仓参与这一轮）：

    JMS_SIBLING_ROOTS=/path/to/jumpserver-mgmt:/path/to/jumpserver-exec

没有这个环境变量时用同级目录约定（见 script/workset.py）。

每个变异都是**一处**改动：把一条规则退回旧行为（或者把守卫的一处识别摘掉），
然后跑那条本该拦住它的守卫。
变红 = 那个守卫是真的；仍绿 = 那个守卫是假的（脚本会列出来并以非零码退出）。

⚠️ **为什么这个脚本不�� overlay**（而 script/mutate-audit.py 用 overlay）：
这条守卫**在运行时扫源码树** —— 它用 go/parser 读全仓的 .go 文件，自己判断
「这个委派调用有没有被门禁支配」。⇒ **overlay 只影响编译器，看不见运行时的
读盘** ⇒ 用 overlay 注入的源码树变异，守卫读到的还是**未变异的代码** ⇒
每一条变异都会「仍绿」⇒ 报告会说「守卫全是假的」，而真相是「扫描什么都没扫」。

⚠️ ⇒ 所以这里用**整仓副本**：把工作树复制到 /tmp，在副本里改，在副本里跑。
**真仓一个字节都不会被碰到** ⇒ 不存在「跑一半崩了，仓里留着变异」这种事。
（⚠️ 而 overlay 那条路也不是白走的：守卫**自己**的源码（internal/arch/
version_test.go）是被**编译**的，所以改守卫自己的那一条，overlay 是有效的 ——
本脚本两种都用，各自用在能用的一边。）
"""
import os
import shutil
import subprocess
import sys

# ⚠️ realpath, NOT abspath: on macOS /tmp is a symlink to /private/tmp, and
# a path that disagrees with the one the tooling resolves is a path that
# silently does nothing.
OUT = os.path.realpath("/tmp/jms-mutants-version")

# ⚠️ **仓不止一个**：这条规则跨三个仓 ——
#   - 词汇与能力在**底座**（jumpserver-kit）；
#   - 委派调用点在**管理面**（biz/handler/delegation.go）；
#   - 反门禁在**执行面**（internal/repository/koko/token.go、cmd/*/doctor.go）；
#   - 守卫住在**服务仓**的 internal/arch/。
# ⇒ 「文件在哪」「守卫在哪」都得在**工作集**里找，而不是在某一个仓根下找。
# 工作集的约定与守卫是同一套（见 script/workset.py）：环境变量
# JMS_SIBLING_ROOTS，否则用同级目录约定。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workset

ROOT = workset.own_root(__file__)
ROOTS = workset.roots(__file__)
# 副本里的工作集：三个仓并排放在 OUT/ws/ 下，**保留原来的目录名** ⇒
# go.work 里的相对路径（../jumpserver-kit）与守卫的同级目录约定
# 在副本里照样成立。
WS = os.path.join(OUT, "ws")
COPY_ROOTS = [os.path.join(WS, os.path.basename(r)) for r in ROOTS]
COPY_SIBLING_ENV = ":".join(COPY_ROOTS)


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


def _first(relpaths):
    """工作集里第一个存在的「仓内相对路径」→ 绝对路径。"""
    for rel in relpaths:
        for r in ROOTS:
            p = os.path.join(r, rel)
            if os.path.exists(p):
                return p
    raise SystemExit(
        "⚠️  工作集里找不到 %s（工作集：%s）" % (", ".join(relpaths), ", ".join(ROOTS)))


def _doctor_file():
    """执行面的 doctor 在哪个仓的哪个 cmd 目录下。

    ⚠️ 按**目录内容**找，不写死二进制名：二进制改过名（jms-exec-mcp →
    jumpserver-exec），写死的名字迟早会过期，而过期的那天脚本会报
    「找不到文件」—— 一个与真实原因毫无关系的错误信息。

    ⚠️ 而且只在**执行面那个仓**里找：两个服务仓重构之后**都有**
    `cmd/doctor/doctor.go` ⇒ 按「工作集里第一个」找会找到管理面那个
    ⇒ 变异打在错的代码上 ⇒ 而那看起来跟「守卫是假的」一模一样。
    """
    root = workset.repo_root_named("jumpserver-exec", ROOTS)
    cmd = os.path.join(root, "cmd")
    if not os.path.isdir(cmd):
        raise SystemExit("⚠️  执行面那个仓里没有 cmd/")
    for name in sorted(os.listdir(cmd)):
        p = os.path.join(cmd, name, "doctor.go")
        if os.path.exists(p):
            return p
    raise SystemExit("⚠️  执行面那个仓里找不到 cmd/*/doctor.go")


def _guard_file():
    """守卫的**体**住在哪个仓。

    ⚠️ 拆成三个仓之后，守卫的体搬进了**底座**（pkg/arch/version.go），
    三个仓的 internal/arch/ 只是**判据**（薄壳）⇒ 按「谁声明了
    checkCapabilityGates」来找，不靠猜（猜错了就是在错的代码上跑，
    而那看起来跟「守卫是假的」一样）。
    """
    needle = "func checkCapabilityGates("
    hits = []
    for r in ROOTS:
        p = os.path.join(r, "pkg", "arch", "version.go")
        if os.path.exists(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                if needle in f.read():
                    hits.append(p)
    if not hits:
        raise SystemExit(
            "⚠️  工作集里找不到底座的 pkg/arch/version.go（守卫的体还没迁过来？）")
    if len(hits) > 1:
        raise SystemExit("⚠️  守卫的体在多个仓里都有：%s ⇒ 不猜" % ", ".join(hits))
    return hits[0]


H = os.path.dirname(_in("jumpserver-mgmt", "biz/handler/delegation.go"))
K = os.path.dirname(_in("jumpserver-exec", "internal/repository/koko/token.go"))
A = os.path.dirname(_guard_file())
D = os.path.dirname(_doctor_file())

handler = open(f"{H}/delegation.go").read()
token = open(f"{K}/token.go").read()
mint = open(f"{K}/mint.go").read()
guard = open(f"{A}/version.go").read()
doctor = open(f"{D}/doctor.go").read()

# SOURCES is the snapshot every mutation was built FROM — the source as it
# was when this script started.
SOURCES = {
    f"{H}/delegation.go": handler,
    f"{K}/token.go": token,
    f"{A}/version.go": guard,
    f"{D}/doctor.go": doctor,
}

# KIT_REPO is the copy of the repository that holds the guard's BODY.
KIT_REPO = os.path.join(WS, os.path.basename(workset.repo_of(f"{A}/version.go", ROOTS)))


def source_of(path):
    """The snapshot of `path` the mutations were built from."""
    if path in SOURCES:
        return SOURCES[path]
    return open(path).read()


def in_copy(path):
    """The same file, inside the copy.

    ⚠️ 副本里三个仓**保持原来的目录名**并排放在 OUT/ws/ 下 ⇒ 相对路径
    （go.work 里的 ../jumpserver-kit、守卫的同级目录约定）在副本里
    照样成立 ⇒ 副本是一个**自洽的工作集**，不是一个孤零零的仓。
    """
    owner = workset.repo_of(path, ROOTS)
    if owner is None:
        raise SystemExit(f"⚠️  {path} 不属于工作集里的任何一个仓")
    return os.path.join(WS, os.path.basename(owner), os.path.relpath(path, owner))


# STALE collects the mutations whose ANCHOR was not unique (or not found).
#
# ⚠️ It is a LIST, not an immediate exit: walking into the first bad anchor
# would mean the mutations after it were never even declared ⇒ one run
# reports ONE problem ⇒ fixing it meant another run.
STALE = []

# ALLOWED_SITES holds the mutations that MUST change more than one place,
# and why.
#
# ⚠️ "One mutation, one place" is what keeps the sweep honest: a mutation
# that changes two places exercises two guards at once, and the report then
# says one thing while two things happened.
ALLOWED_SITES = {
    "藏在 && 里的反门禁 + 摘掉极性检查": "这两处**必须**一起改：极性检查是唯一挡"
                                       "「反门禁」的东西 ⇒ 只改反门禁会被抓到，"
                                       "只改极性检查则没人能证明它有牙齿 ⇒ "
                                       "合在一起才是「摘掉它会怎样」这个问题",
}

# M holds the mutations that MUST be caught: each one breaks the rule, and
# the guard has to go red.
#
# (名字, {文件: 改后的内容}, 该由哪条测试拦住, 变异方式)
M = {}

# BLIND_SPOTS holds the edits that are deliberately NOT caught. They are not
# failures — they are the **documented boundary** of this guard.
#
# ⚠️ Why they are in the script at all: a guard's boundary that lives only
# in someone's head is a boundary that moves. ⇒ These are asserted to stay
# GREEN, and when one of them turns RED the script says so — that means the
# boundary got TIGHTER, which is good news and a reason to delete the entry.
BLIND_SPOTS = {}

# IN_TREE means "the mutation is in a file the guard SCANS at runtime" ⇒ it
# has to be on disk in the copy. OVERLAY means "the mutation is in the
# guard's own compiled source" ⇒ the overlay does work for it.
IN_TREE = "tree"
OVERLAY = "overlay"


def sub1(text, old, new, name):
    """替换**一处**，并且在目标不是唯一的时候拒绝动手。

    ⚠️ 变异命中两处 ⇒ 那是两个变异共用一个名字 ⇒ 这一轮只报了一次检查，
    而实际被检查的守卫不是它声称的那个。
    """
    n = text.count(old)
    if n != 1:
        STALE.append((old, n, name))
        return text
    return text.replace(old, new, 1)


def mut(name, files, test, pkg, how=IN_TREE, repo=None):
    M[name] = (files, test, pkg, how, repo)


def blind(name, files, why, how=IN_TREE, repo=None):
    BLIND_SPOTS[name] = (files, why, how, repo)


GUARD_TEST = "TestTheCapabilityVocabulary"
GUARD_PKG = "./internal/arch/"

# The management plane's gate. It appears TWICE (the call tool and the probe
# tool), so an anchor that is only the gate line is not unique ⇒ the
# mutation would hit both, or hit neither.
#
# ⚠️ The two gates are told apart by the error message that precedes them:
# the call tool says "… Run jms_delegation_status for how to set it up",
# the probe tool does not. ⇒ The anchor is taken from the source, so it
# cannot drift away from it.
GATE_HEAD = ('\t\t\treturn render.Failf("delegation is not ready: %v. '
             'Run jms_delegation_status for how to set it up", err)\n\t\t}\n')
GATE_LINE = ("\t\tif state := c.Profile(ctx).State(jmsapi.CapDelegation); "
             "state != jmsapi.CapabilityPresent {")


def gate_block():
    """The management plane's gate (the CALL tool's one), with the unique
    context that tells the two gates apart."""
    i = handler.find(GATE_HEAD)
    if i < 0:
        raise SystemExit("⚠️  锚点不存在（源码里找不到门禁前的那句错误返回）")
    j = handler.find(GATE_LINE, i)
    if j < 0:
        raise SystemExit("⚠️  锚点不存在（源码里找不到门禁那一行）")
    return handler[i:j + len(GATE_LINE)]


GATE = gate_block()

# M1 「漏门禁」：一个**没有门禁**的委派调用，放在门禁**之前**。
#
# ⚠️ 放在门禁之前才是漏门禁：放在之后的话，它本来就被那条 guard clause
# 支配着（守卫 clause 的形状是「前面有一条会离开函数的 if」），守卫不报它
# 是对的 —— 这也是为什么「变异放在哪」比「变异改了什么」更要紧。
mut("漏门禁：委派调用插在门禁之前", {
    f"{H}/delegation.go": sub1(handler, GATE,
        '\t\t_, _, _ = c.DelegationRequest(client.DelegationCall{Method: "GET", Path: "/x/"})\n' + GATE,
        "漏门禁"),
}, GUARD_TEST, GUARD_PKG)

# M2 「包限定伪装」：`jmsapi.CostOf(cap)` 看着像个门禁（它提到了能力常量），
# 其实是个**答案**。里面藏一个没门禁的委派调用。
#
# ⚠️ 这一条是修掉的**真漏洞**：旧规则只要求「call.Fun 是 selector 且参数
# 带能力常量」⇒ 包限定函数被误认成提问 ⇒ 守卫以为这里有门禁。
mut("包限定伪装：CostOf 当门禁，里面藏没门禁的委派调用", {
    f"{H}/delegation.go": sub1(handler, GATE,
        '\t\tif ok := jmsapi.CostOf(jmsapi.CapDelegation); ok != "" {\n'
        '\t\t\t_, _, _ = c.DelegationRequest(client.DelegationCall{Method: "GET", Path: "/x/"})\n'
        '\t\t}\n' + GATE,
        "包限定伪装"),
}, GUARD_TEST, GUARD_PKG)

# M3 「错状态门禁」：门禁比的是**错的那个状态** ⇒ 它在「能力确实没有」的时候
# 才拦 ⇒ 能力未知的时候反而把凭据递出去了。
mut("错状态门禁：!= Present 改成 == Absent", {
    f"{H}/delegation.go": sub1(handler, GATE,
        GATE.replace(GATE_LINE,
                     "\t\tif state := c.Profile(ctx).State(jmsapi.CapDelegation); "
                     "state == jmsapi.CapabilityAbsent {"),
        "错状态门禁"),
}, GUARD_TEST, GUARD_PKG)

# M4 「藏在 && 里的反门禁」：执行面的门禁是「条件成立就跑」，所以把比较
# 藏在 && 的下一层 ⇒ 顶层看不出来。
#
# ⚠️ 这一条是**守卫生成的那轮**才发现的洞：极性检查只看条件的顶层比较 ⇒
# `dc != nil && state == CapabilityAbsent` 里的比较被漏掉 ⇒ 反门禁被放过。
mut("藏在 && 里的反门禁：执行面门禁改成错状态比较", {
    f"{K}/mint.go": sub1(mint,
        "\tif dc := cfg.Delegation; dc != nil && cfg.API.MayPresent(ctx, jmsapi.CapDelegation) {",
        "\tif dc := cfg.Delegation; dc != nil && cfg.API.Profile(ctx).State(jmsapi.CapDelegation) == jmsapi.CapabilityAbsent {",
        "藏在 && 里的反门禁"),
}, GUARD_TEST, GUARD_PKG)

# M5 「守卫不认三态门禁」：把守卫识别 `!= CapabilityPresent` 的那一条改掉 ⇒
# 真代码里的门禁它就看不到了 ⇒ 守卫会把**有门禁**的代码报成没门禁。
#
# ⚠️ 这一条改的是守卫**自己**的源码 ⇒ 它是被编译的 ⇒ overlay 对它有效。
mut("守卫不认三态门禁：notPresentTest 的 NEQ 改成 EQL", {
    f"{A}/version.go": sub1(guard,
        '\t\tif c.op != token.NEQ || c.marker != "present" {',
        '\t\tif c.op != token.EQL || c.marker != "present" {',
        "守卫不认三态门禁"),
}, GUARD_TEST, GUARD_PKG, OVERLAY, "jumpserver-mgmt")

# M6 「版本号溜进工具层」：在工具层加一个按**发行版**分支的助手。
#
# ⚠️ 这一条守的是「控制流里不许出现版本号」：版本是操作员填的（输入），
# 代码该问的是「这个部署有没有这个能力」。⇒ 工具层一旦开始按版本分支，
# 差异就有**两份**，而漂的那一份决定会话以谁的身份跑。
mut("版本号溜进工具层：handler 里加一个按发行版分支的助手", {
    f"{H}/delegation.go": sub1(handler, GATE, GATE + '''

// MUTATION: a release check in the tool layer.
func versionIsV4(v jmsapi.Version) bool { return v == jmsapi.VersionV4 }''',
        "版本号溜进工具层"),
}, "TestTheVersionDoesNotLeaveTheProtocolLayer", GUARD_PKG)

# M7 「措辞在别处重写」：doctor 自己写一句「这个部署没有委派方案」，
# 不用清单里的那一句。
#
# ⚠️ 这一条守的是「措辞只有一份」：两句都在的时候，看的人读到的是**哪一句**
# 取决于他先看到哪一处 ⇒ 而两个 doctor 正是这样漂开的。
mut("措辞在别处重写：doctor 自己写那句「没有委派方案」", {
    f"{D}/doctor.go": sub1(doctor,
        "jmsapi.Explain(jmsapi.CapDelegation, state)",
        '"this deployment has no Chat AI delegation scheme"',
        "措辞在别处重写"),
}, "TestTheCapabilityWordingIsNotRewrittenElsewhere", GUARD_PKG, IN_TREE, "jumpserver-kit")

# ---- 守卫的边界（必须仍然绿） ---------------------------------------------

# B1：反门禁 + 摘掉极性检查 ⇒ 没人抓。
#
# ⚠️ 这不是缺陷，是**这条守卫到哪儿为止**：极性检查是唯一挡「条件成立就跑」
# 形状的反门禁的东西 ⇒ 摘掉它，守卫就看不见这一类。
# ⇒ 它登记在这儿，是为了让「这条边界在哪儿」有一处可以查的地方。
blind("边界：反门禁 + 摘掉极性检查 ⇒ 没人抓", {
    f"{K}/mint.go": sub1(mint,
        "\tif dc := cfg.Delegation; dc != nil && cfg.API.MayPresent(ctx, jmsapi.CapDelegation) {",
        "\tif dc := cfg.Delegation; dc != nil && cfg.API.Profile(ctx).State(jmsapi.CapDelegation) == jmsapi.CapabilityAbsent {",
        "边界 B1"),
    f"{A}/version.go": sub1(guard,
        "\tcmps := stateComparisons(cond, constName, imports, bound)\n\tif len(cmps) == 0 {",
        "\tcmps := stateComparisons(cond, constName, imports, bound)\n\tif len(cmps) >= 0 {",
        "边界 B1"),
}, "极性检查是唯一挡「条件成立就跑」形状的反门禁的东西")

# CANARY: the guard stops recognising the QUESTION ⇒ no call site is gated
# any more ⇒ every credential call site must be reported ⇒ the test MUST go
# red.
#
# ⚠️ It has to COMPILE: a mutation that breaks the build is caught by the
# compiler, not by the guard, and the sweep counts those apart — so a
# canary that does not compile proves nothing about the overlay.
CANARY = ("【canary】守卫认不出能力提问", {
    f"{A}/version.go": sub1(guard,
        "\t\t\tif a.Sel.Name == constName {",
        "\t\t\tif a.Sel.Name == constName+\"__canary\" {",
        "canary"),
}, GUARD_TEST, GUARD_PKG, OVERLAY, "jumpserver-exec")


def make_copy():
    """Copy every repository of the working set into OUT/ws — the real ones
    are never touched.

    ⚠️ 目录名**保持原样**：go.work 里的相对路径与守卫的同级目录约定都
    指着这些名字 ⇒ 副本必须长得跟真的一模一样，否则守卫在副本里找错地方。
    """
    if os.path.exists(WS):
        shutil.rmtree(WS)
    os.makedirs(WS)
    for src, dst in zip(ROOTS, COPY_ROOTS):
        shutil.copytree(src, dst,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))

    # ⚠️ go.work 不入库：CI 的三个 checkout 之间没有工作区关系，服务副本
    #   会经 go.mod require 从**代理解析 kit**——对 kit 副本源码的 overlay
    #   变异根本到不了编译里（2026-11-06 实测：「词表」变异本地红、CI 绿；
    #   本地每个服务仓有一份不入库的 go.work 才被 copytree 一起带进副本）。
    #   副本必须自己接成工作区：WS/go.work 兜底（副本自带 go.work 时以离
    #   构建目录更近的那份为准，两者等价）。
    with open(os.path.join(WS, "go.work"), "w") as f:
        f.write("go 1.26.0\n\nuse (\n")
        for r in COPY_ROOTS:
            f.write("\t./" + os.path.basename(r) + "\n")
        f.write(")\n")


def reset_tree():
    """Put the copy's mutated files back to the pristine snapshot."""
    for path, snap in SOURCES.items():
        with open(in_copy(path), "w") as f:
            f.write(snap)


def apply_tree(files):
    """Write the mutated content into the copy."""
    for path, content in files.items():
        with open(in_copy(path), "w") as f:
            f.write(content)


def effective_sites(original, content):
    """How many places one mutation touched.

    ⚠️ The count is by CHANGED LINE, and an INSERTION shifts every line
    after it ⇒ a naive zip counts the whole file. ⇒ A pure append (the
    original is a prefix of the result) is ONE site, and an insertion is
    counted by the lines that actually differ.
    """
    a = original.split("\n")
    b = content.split("\n")
    if b[:len(a)] == a:
        return 1
    import difflib
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    changed = 0
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag != "equal":
            changed += max(1, (i2 - i1) if tag != "insert" else 1)
    return max(1, changed)


def is_guard_source(path):
    """这个文件是不是**守卫自己的源码**（底座的 pkg/arch/）。

    ⚠️ 守卫的体是被**编译**的 ⇒ 改它要用 overlay（-overlay），而服务仓的
    调用点是**运行时读源码树**的 ⇒ 改它要落盘。两种改法混在一条变异里时，
    靠这个判据分开。
    """
    return os.sep + "pkg" + os.sep + "arch" + os.sep in path


def repo_for(files):
    """这条变异要在**哪个仓**里跑测试。

    ⚠️ 判据是「守卫在那儿**扫树**」的那个仓 —— 守卫是运行时读源码树的，
    所以它得在**被改的那棵树**里跑。

    ⚠️ 跨仓的变异（改守卫的源码 + 改服务仓的调用点）：测试跑在**调用点**
    那个仓里，而守卫源码的改动走 overlay（它是编译进去的）⇒ 一次变异
    可以同时用两种改法。
    """
    tree_owners = []
    for path in files:
        owner = workset.repo_of(path, ROOTS)
        if owner is None:
            raise SystemExit(f"⚠️  {path} 不属于工作集里的任何一个仓")
        if not is_guard_source(path) and owner not in tree_owners:
            tree_owners.append(owner)
    if len(tree_owners) == 1:
        # ⚠️ **副本**里的那个仓，不是真仓！变异写在副本里 ⇒ 测试必须跑在副本上，
        #    跑在真仓上看到的永远是**未变异**的代码 ⇒ 每条变异都会「仍绿」。
        return os.path.join(WS, os.path.basename(tree_owners[0]))
    if not tree_owners:
        # 只改了守卫自己的源码 ⇒ 在底座里跑（它扫的是兄弟仓的树）。
        return KIT_REPO
    raise SystemExit("⚠️  变异跨了多个仓且说不清在哪儿跑测试：%s" % tree_owners)


def repo_by_name(name):
    """按仓名找到工作集里的那个仓（及其副本）。

    ⚠️ 为什么需要显式指定：守卫的**体**在底座，但它的**调用点**在服务仓 ⇒
    「让守卫认不出能力提问」这种变异，只能在**有调用点的那个仓**里跑测试，
    才看得出守卫是不是瞎了。⇒ 不能靠「改动在哪儿」推出来。
    """
    for r in ROOTS:
        if os.path.basename(r) == name:
            return os.path.join(WS, os.path.basename(r))
    raise SystemExit(f"⚠️  工作集里没有 {name} 这个仓")


def run_one(name, files, test, pkg, how, verbose, expect="red", repo=None):
    """Run one mutation. Returns "red", "green" or "build-failed".

    ⚠️ `expect` decides how the outcome is PHRASED, not whether it is
    judged: a mutation is expected to go red, a registered boundary is
    expected to stay green. ⇒ Printing "the guard is fake" for a boundary
    that stayed green would say the opposite of the truth.
    """
    # ⚠️ 两种改法可以混在一条变异里：守卫自己的源码（底座的 pkg/arch/）是
    #    **被编译**的 ⇒ 走 overlay；服务仓的调用点是**运行时读源码树**的
    #    ⇒ 落盘。跨仓的变异正是这种（改守卫 + 改调用点）。
    overlay_files = {p: c for p, c in files.items() if is_guard_source(p)}
    tree_files = {p: c for p, c in files.items() if not is_guard_source(p)}
    replace = {}
    for path, content in overlay_files.items():
        tmp = os.path.join(OUT, f"{name}_{os.path.basename(path)}")
        open(tmp, "w").write(content)
        replace[in_copy(path)] = tmp
    overlay = os.path.join(OUT, f"overlay_{name}.json")
    import json
    json.dump({"Replace": replace}, open(overlay, "w"))
    reset_tree()
    apply_tree(tree_files)
    cmd = ["go", "test", "-v"]
    if replace:
        cmd.append("-overlay=" + overlay)
    cmd += [pkg, "-run", "^" + test + "$"]
    # ⚠️ 测试在**被改的那棵树**的仓里跑（守卫运行时读源码树）。
    repo_dir = repo_by_name(repo) if repo else repo_for(files)
    try:
        p = subprocess.run(
            cmd,
            cwd=repo_dir, capture_output=True, text=True,
            # ⚠️ JMS_SIBLING_ROOTS 指着**副本**里的三个仓：守卫读的是源码树，
            # 不是编译产物 ⇒ 它得知道另外两个仓在哪。
            env={**os.environ, "GOFLAGS": "-mod=readonly", "GOPROXY": "off",
                 "PWD": repo_dir, "JMS_SIBLING_ROOTS": COPY_SIBLING_ENV})
    finally:
        # ⚠️ 副本复位：下一次变异必须从**未变异**的代码开始 ⇒ 否则上一条
        # 变异会渗进下一条 ⇒ 报告的数字比实际弱。
        reset_tree()
    out = p.stdout + p.stderr
    # ⚠️ The test has to have RUN. A -run pattern that matches nothing
    # exits 0 — and "nothing ran, so it is green" is exactly how a
    # mutation sweep lies to you.
    ran = ("--- PASS: " + test) in out or ("--- FAIL: " + test) in out
    if not ran:
        if "build failed" in out or "[setup failed]" in out or "cannot use" in out:
            if verbose:
                print(f"🧱 {name}: 编译失败（编译器逮住了改动，测试没跑到 —— 不算守卫立功）")
            return "build-failed"
        print(f"⚠️  {name}: 测试**没跑**（包 {pkg} 里没有 {test}）—— 这个变异不算数")
        return "green"
    red = p.returncode != 0
    if verbose:
        if expect == "red":
            print(("✅" if red else "❌") + f" {name}: {test} "
                  + ("变红" if red else "仍绿 —— 守卫是假的"))
        else:
            print(("✔️" if not red else "⬆️") + f" {name}: {test} "
                  + ("仍绿（边界没变）" if not red else "变红了 ⇒ 边界收紧了（或坏了）"))
    return "red" if red else "green"


def report_stale():
    """⚠️ 一次报全部 —— 不是第一个就退出。"""
    if not STALE:
        return False
    print(f"⚠️  变异目标有问题（{len(STALE)} 处）：锚点不唯一或没匹配上")
    for old, n, name in STALE:
        print(f"   - {name}: {n} 处: {old!r}")
    return True


def main():
    verbose = "-v" in sys.argv
    os.makedirs(OUT, exist_ok=True)
    make_copy()

    # ⚠️ 锚点坏了 ⇒ 那几条变异**什么都没改** ⇒ 这一轮的数字不作数 ⇒
    # 不跑扫描，直接把全部坏锚点报出来。
    if report_stale():
        return 1

    # The canary first, and alone.
    name, files, test, pkg, how, canary_repo = CANARY
    for path, content in files.items():
        if content == source_of(path):
            print(f"⚠️  canary: 变异没生效（模式没匹配上）")
            return 1
    print("先跑 canary：")
    if run_one(name, files, test, pkg, how, True, repo=canary_repo) != "red":
        print("❗ canary 没有变红 ⇒ overlay 没生效，后面每条变异都会跑在**未变异的代码**上。")
        print("   （这一轮的数字不作数。）")
        return 1
    print()

    survivors = []
    build_failed = []
    prints = {}
    for mname, (files, mtest, mpkg, mhow, mrepo) in M.items():
        for mpath, mcontent in files.items():
            fp = (mpath, mcontent)
            if fp in prints:
                print(f"⚠️  {mname}: 与「{prints[fp]}」是同一处编辑 —— 这一条没有新增检查")
                survivors.append(mname)
            else:
                prints[fp] = mname

    # ⚠️ 一次变异只能改一处。
    site_checked = 0
    site_violations = []
    for name, (files, test, pkg, how, repo) in M.items():
        for path, content in files.items():
            original = source_of(path)
            sites = effective_sites(original, content)
            site_checked += 1
            if sites > 1 and name not in ALLOWED_SITES:
                site_violations.append((name, sites, path))

    for name, (files, test, pkg, how, repo) in M.items():
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
        outcome = run_one(name, files, test, pkg, how, verbose, repo=repo)
        if outcome == "build-failed":
            build_failed.append(name)
        elif outcome == "green":
            survivors.append(name)

    total = len(M)
    print()
    print(f"{total - len(survivors) - len(build_failed)}/{total} 个变异被**测试**杀掉")
    if build_failed:
        print(f"另有 {len(build_failed)}/{total} 个变异编译失败（编译器逮住，测试没跑到 —— 不算守卫立功）:")
        for n in build_failed:
            print("   -", n)

    # ---- 边界：这些必须仍然绿 ---------------------------------------------
    print()
    print("🔬 守卫的边界（登记在案，必须仍然绿）:")
    tight = []
    for name, (files, why, how, repo) in BLIND_SPOTS.items():
        broken = False
        for path, content in files.items():
            if content == source_of(path):
                print(f"⚠️  {name}: 变异没生效（模式没匹配上）")
                broken = True
                break
        if broken:
            tight.append(name)
            continue
        outcome = run_one(name, files, GUARD_TEST, GUARD_PKG, how, verbose, expect="green")
        if outcome == "red":
            print(f"   ⬆️  {name}: 变红了 ⇒ 这条边界**收紧**了（或坏了）—— 请复核")
            tight.append(name)
        else:
            print(f"   ✔️  {name}: 仍绿（边界没变）—— {why}")

    print()
    print(f"🔍 锚点唯一性：{len(M)} 条变异的锚点全部唯一（无重复、无未匹配）")
    print(f"🔍 一次变异只改一处：核对了 {site_checked} 处改动，{len(site_violations)} 处越界"
          f"（ALLOWED_SITES 登记了 {len(ALLOWED_SITES)} 条**必须**改多处的）")
    for name, sites, path in site_violations:
        print(f"   ⚠️  {name}: 一条变异改了 {sites} 处（{path}）")
    # ⚠️ **真仓必须一个字节都没变**：这个脚本在副本里改 ⇒ 这一条是「没碰真仓」
    # 的证据，不是「源码在扫描期间被改过」的检查。
    touched = [p for p, snap in SOURCES.items() if open(p).read() != snap]
    if touched:
        print(f"❗ 真仓被改动了（{len(touched)} 个文件）—— 这个脚本**不该**碰真仓:")
        for p in touched:
            print("   -", os.path.relpath(p, ROOT))
        return 1
    print(f"🔍 真仓未被触碰：{len(SOURCES)} 个源文件逐字节未变（变异全在 {WS} 里）")
    if site_violations:
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
