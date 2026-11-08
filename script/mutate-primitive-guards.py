#!/usr/bin/env python3
"""变异测试：本轮 kit 原语层的新守卫，每条退回一次，看对应的测试**会不会变红**。

覆盖的守卫（这一轮新增/加强的）：

  - pkg/render/list_test.go —— ListSpec 流水线的顺序与计数
    （filter → map → sort → truncate → count；total=匹配数；Max<=0 无上限；
    NormLimit 的夹取策略）；
  - model/jms/enum_values_test.go + pkg/render/enum_pin_test.go ——
    枚举两表对账（生成常量 ↔ WireEnums）与 schema 钉词；
  - pkg/risk/rehearsal_test.go —— 演练判定与措辞的唯一源；
  - pkg/errs/errs_test.go —— 门禁拒绝的**精确**类型匹配。
  - pkg/reg/catalogue_table_test.go + pkg/httpapi/serve_test.go +
    pkg/testsupport/check_openapi_test.go —— 入口层收编的新原语：
    目录表格的确认列优先级与 hint 兜底、Start 回真端口、
    serve http 缺地址的拒绝（含示例端口来自 ServeOptions.ExampleAddr—— 共用文案
    硬编码某一个面的端口会把另一个面的操作员指去错误的面）、firstDiffLine 指到
    第一个分歧。

用法（在底座仓根目录）：

    python3 script/mutate-primitive-guards.py          # 跑全部变异
    python3 script/mutate-primitive-guards.py -v       # 顺带打印每条变异做了什么

每个变异都是**一处**改动：把行为退回旧行为，然后跑那个本该拦住它的测试。
测试**变红** = 那个守卫是真的；测试**仍绿** = 那个守卫是假的（脚本会列出来
并以非零码退出）。

⚠️ 变异用 overlay 注入，**不碰仓库里的任何文件**：每个变异是一份改过的
副本，go test 用 -overlay 把它盖到真实路径上。
⚠️ **-overlay 必须写在子命令之后**（go test -overlay=f.json ...）：写成
go -overlay f.json test ... 会被 go 工具回 "flag provided but not defined"
—— 退出码非零，但与「变异被抓」完全无法区分 ⇒ 每条都会被误判。
⚠️ 脚本先跑 canary（一条必红的变异）：canary 不红 ⇒ overlay 没生效 ⇒ 中止。
   在 /tmp 这类**符号链接**路径下 overlay 就是不生效（overlay 的键必须是
   go 解析出的路径，macOS 的 /tmp → /private/tmp）⇒ 每条变异都会在**未变
   异**的代码上跑 ⇒ 扫描报「守卫全是假的」而真相是「扫描什么都没做」。
   ⇒ 这里所有落地路径都过 realpath，canary 是最后一道自证。
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workset

# realpath, NOT abspath: overlay 的键必须是 go 解析出的路径（macOS 的
# /tmp 是符号链接，不一致时 overlay 被**静默忽略**）。
ROOT = os.path.realpath(workset.own_root(__file__))
OUT = os.path.realpath("/tmp/jms-mutants-primitive")


def at(relpath):
    return os.path.realpath(os.path.join(ROOT, relpath))


LIST = at("pkg/render/list.go")
ENUM = at("model/jms/enum_json.go")
RISK = at("pkg/risk/risk.go")
ERRS = at("pkg/errs/errs.go")
CATALOGUE = at("pkg/reg/catalogue_table.go")
SERVE = at("pkg/httpapi/serve.go")
CHECK = at("pkg/testsupport/check_openapi.go")

list_src = open(LIST).read()
enum_src = open(ENUM).read()
risk_src = open(RISK).read()
errs_src = open(ERRS).read()
catalogue_src = open(CATALOGUE).read()
serve_src = open(SERVE).read()
check_src = open(CHECK).read()

STALE = []


def anchor_in(text, marker, occurrence=0):
    """锚点行取自**源码**（含 marker 的那一行），不手写。

    ⚠️ 手写的锚点要背着源码自己的转义（Go 原始串里的反斜杠、Python
    字面量的双写）⇒ 两层差一个反斜杠 ⇒ 变异静默地什么都不改。
    """
    hits = [l for l in text.split("\n") if marker in l]
    if not hits:
        STALE.append((marker, 0))
        return ""
    if occurrence >= len(hits):
        STALE.append((marker, len(hits)))
        return ""
    return hits[occurrence]


def sub1(text, old, new):
    """替换**一处**；出现次数不是 1 就记进 STALE，不动手。"""
    n = text.count(old)
    if n != 1:
        STALE.append((old[:80], n))
        return text
    return text.replace(old, new)


def swap(text, anchor, old, new):
    """把锚点那一行里的 old 换成 new，其余一行不动。"""
    if not anchor:
        return text
    if anchor.count(old) != 1:
        STALE.append((old[:80], anchor.count(old)))
        return text
    return sub1(text, anchor, anchor.replace(old, new))


# (名字, {文件: 改后的内容}, 该由哪条测试拦住, 跑哪个包)
M = []


def mut(name, files, test, pkg):
    M.append((name, files, test, pkg))


# ---- ListSpec 流水线：顺序与计数 ------------------------------------------

SORT_THEN_TRUNCATE = "\n".join([
    "\tif s.Less != nil {",
    "\t\t// Stable, so rows the sort cannot tell apart keep the order the",
    "\t\t// endpoint gave them in.",
    "\t\tsort.SliceStable(items, func(i, j int) bool { return s.Less(items[i], items[j]) })",
    "\t}",
    "\t// The cap goes LAST, after the sort: limit=20 means \"the top 20 by the",
    "\t// sort key\", not \"20 rows, then sorted\".",
    "\t//",
    "\t// A list with NO maximum (Max <= 0) keeps everything that matched: some",
    "\t// answers are complete by nature (a short policy table, the node tree,",
    "\t// the platform list), and capping those would drop rows the caller needs",
    "\t// while reporting truncated for a list that is meant to be whole.",
    "\tlimit := total",
    "\tif s.Max > 0 {",
    "\t\tlimit = NormLimit(s.Limit, s.Def, s.Max)",
    "\t}",
    "\ttruncated := total > limit",
    "\tif truncated {",
    "\t\titems = items[:limit]",
    "\t}",
])

TRUNCATE_THEN_SORT = "\n".join([
    "\tlimit := total",
    "\tif s.Max > 0 {",
    "\t\tlimit = NormLimit(s.Limit, s.Def, s.Max)",
    "\t}",
    "\ttruncated := total > limit",
    "\tif truncated {",
    "\t\titems = items[:limit]",
    "\t}",
    "\tif s.Less != nil {",
    "\t\tsort.SliceStable(items, func(i, j int) bool { return s.Less(items[i], items[j]) })",
    "\t}",
])

mut("list_先截断后排序",
    {LIST: sub1(list_src, SORT_THEN_TRUNCATE, TRUNCATE_THEN_SORT)},
    "TestListSortsBeforeItTruncates", "./pkg/render/")

mut("list_total退回未过滤数",
    {LIST: swap(list_src, anchor_in(list_src, "total := len(items)"),
                "len(items)", "len(s.Rows)")},
    "TestListCountsTheWholeMatchingSet", "./pkg/render/")

mut("list_无上限也截断",
    {LIST: swap(list_src, anchor_in(list_src, "limit := total"),
                "limit := total", "limit := 0")},
    "TestListWithNoMaxKeepsEverything", "./pkg/render/")

mut("NormLimit不夹",
    {LIST: sub1(list_src,
        "\tpolicy := pagination.Policy{\n"
        "\t\tDefaultPageSize: def,\n"
        "\t\tMaxPageSize:     max,\n"
        "\t\tOverMax:         pagination.OverMaxFallback,\n"
        "\t}\n"
        "\treturn policy.NormalizeLimit(v)",
        "\t_, _ = def, max\n\t_ = pagination.Policy{}\n\treturn v")},
    "TestNormLimitClampsToThePolicy", "./pkg/render/")

# ---- 枚举：两表对账与 schema 钉词 -----------------------------------------

# ⚠️ WireEnums 的 wire 名不是字面量：它们由 wireNames 从生成常量的
# String() 得到 ⇒ 变异要打在 DeliveryValues 表 / wireNames 函数上，
# 而不是找 '"maybe_sent"' 这种引号字面量（那里根本没有）。
mut("WireEnums表多一个值",
    {ENUM: swap(enum_src, anchor_in(enum_src, "var DeliveryValues"),
                "Delivery_maybe_sent}", "Delivery_maybe_sent, Delivery_maybe_sent}")},
    "TestTheWireTableMatchesTheGeneratedConstants", "./model/jms/")

mut("WireEnums钉词拼错",
    {ENUM: swap(enum_src, anchor_in(enum_src, "names[i] = v.String()"),
                "v.String()", "v.String() + \"-oops\"")},
    "TestTheEnumPinsNameTheDocumentedWords", "./pkg/render/")

# ---- 演练：判定与措辞的唯一源 ---------------------------------------------

mut("Rehearsal措辞重写",
    {RISK: sub1(risk_src,
                'blocked = "classified " + c.String() + "; re-call with confirm=true to execute"',
                'blocked = "class " + c.String() + "; re-call with confirm=true to execute"')},
    "TestRehearsal", "./pkg/risk/")

# ---- 门禁拒绝：精确类型匹配 -----------------------------------------------

mut("GateDenial松匹配",
    {ERRS: sub1(errs_src,
        "\tdeny, ok := err.(*invoke.DenyError)\n\treturn deny, ok",
        "\tdeny, _ := err.(*invoke.DenyError)\n\treturn deny, true")},
    "TestGateDenialMatchesTheExactType", "./pkg/errs/")


# ---- 入口层收编：目录表格与 serve 生命周期 -------------------------------

mut("CatalogueTable不问Hint",
    {CATALOGUE: swap(catalogue_src, anchor_in(catalogue_src, "} else if hint != nil {"),
                "hint != nil", "false")},
    "TestCatalogueTableShowsNameRiskAndWhatItAsksFor", "./pkg/reg/")

mut("Start不回真端口",
    {SERVE: swap(serve_src, anchor_in(serve_src, "return srv, ln.Addr().String(), nil"),
                "ln.Addr().String()", "opts.Addr")},
    "TestStartHandsBackTheRealAddressAndServes", "./pkg/httpapi/")



mut("firstDiffLine钉1",
    {CHECK: swap(check_src, anchor_in(check_src, "return i + 1, av, bv"),
                "i + 1", "1")},
    "TestFirstDiffLinePointsAtTheFirstDisagreement", "./pkg/testsupport/")


def run_one(name, files, test, pkg, verbose=False):
    """跑一条变异：落地 overlay 副本 → go test 该测试 → 判红。"""
    os.makedirs(OUT, exist_ok=True)
    replace = {}
    for path, content in files.items():
        if content == source_of(path):
            return ("stale", f"变异没落地（内容与源码相同）: {os.path.basename(path)}")
        mpath = os.path.realpath(os.path.join(OUT, name + "-" + os.path.basename(path)))
        with open(mpath, "w") as f:
            f.write(content)
        replace[path] = mpath
    opath = os.path.realpath(os.path.join(OUT, name + ".json"))
    with open(opath, "w") as f:
        json.dump({"Replace": replace}, f)
    # ⚠️ -overlay 写在**子命令**之后（go test -overlay=...）。
    cmd = ["go", "test", f"-overlay={opath}", pkg,
           "-run", f"^{test}$", "-count=1"]
    if verbose:
        print("   $", " ".join(cmd))
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "GOPROXY": "off"})
    out = r.stdout + r.stderr
    if "no tests to run" in out or "testing: warning: no tests to run" in out:
        return ("broken", f"测试名不存在: {test}")
    if "--- FAIL" in out:
        return ("red", "")
    if r.returncode != 0:
        return ("broken", "变异没编译/包坏了:\n" + out[-2000:])
    return ("green", "")


SOURCES = {LIST: list_src, ENUM: enum_src, RISK: risk_src, ERRS: errs_src,
           CATALOGUE: catalogue_src, SERVE: serve_src, CHECK: check_src}


def source_of(path):
    return SOURCES.get(path, open(path).read())


def main():
    verbose = "-v" in sys.argv
    if STALE:
        print("⚠️  锚点有问题的变异（不参与判定）:")
        for what, n in STALE:
            print(f"   {what!r} 命中 {n} 处")
    usable = [m for m in M if not any(
        source_of(p) == c for p, c in m[1].items())]
    # canary：第一条（list_total退回未过滤数）必红 —— 不红就说明 overlay
    # 没生效（或守卫全假），此时报告没有意义，直接中止。
    canary = next(m for m in usable if m[0] == "list_total退回未过滤数")
    state, detail = run_one(*canary, verbose=verbose)
    if state != "red":
        print("🛑 canary 没有变红（%s）⇒ overlay 可能没生效，中止。" % state)
        print(detail)
        print("   常见原因：落地路径含符号链接（/tmp → /private/tmp），"
              "overlay 的键与 go 解析的路径不一致 ⇒ 变异被静默忽略。")
        return 2
    print("✅ canary 变红，overlay 生效。\n")
    fake, broken, ok = [], [], 0
    for name, files, test, pkg in usable:
        if name == canary[0]:
            state, detail = ("red", "")
        else:
            state, detail = run_one(name, files, test, pkg, verbose=verbose)
        mark = {"red": "✅", "green": "❌", "broken": "⚠️", "stale": "⚠️"}[state]
        line = f"{mark} {name} → {test}"
        if state == "red":
            ok += 1
            print(line + "（变红，守卫是真的）")
        elif state == "green":
            fake.append((name, test))
            print(line + "（仍绿，守卫是假的）")
        else:
            broken.append((name, detail))
            print(line + f"（{detail}）")
    print(f"\n合计：{ok} 条变红，{len(fake)} 条仍绿，{len(broken)} 条无效。")
    if fake:
        print("❌ 假守卫：")
        for name, test in fake:
            print(f"   {name}（{test} 没有抓住它）")
    if broken:
        print("⚠️  无效变异（先修它们再说结论）：")
        for name, detail in broken:
            print(f"   {name}: {detail.splitlines()[0] if detail else ''}")
    # 统一输出契约（kit#22）：CI/汇总用这一行做机械判读，
    # 与其余 mutate-* 脚本同形。
    total = len(M)
    killed = total - len(fake) - len(broken)
    survivors = [n for n, _ in fake]
    print(f"MUTATIONS: killed={killed} total={total} survivors={' '.join(survivors) if survivors else 'none'}")
    return 1 if fake or broken else 0


if __name__ == "__main__":
    sys.exit(main())
