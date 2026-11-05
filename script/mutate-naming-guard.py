#!/usr/bin/env python3
"""变异测试：把「IDL、生成包与模型目录同名」这条规则的每一处实现退回一次，
看 pkg/arch 的夹具测试**会不会变红**。

为什么它在仓里：一份「全都验过了」的证据，如果只躺在 /tmp 里，机器一重启
就没了，下一轮谁也复现不了 ⇒ 而「守卫必须自证会红」正是本仓的规矩。

用法（在底座仓根目录）：

    python3 script/mutate-naming-guard.py            # 跑全部变异
    python3 script/mutate-naming-guard.py -v         # 顺带打印每个变异做了什么

这条守卫与 mutate-version-guard.py 那批不同：守卫的体和夹具测试**都在本仓**
（pkg/arch/arch.go + naming_test.go），夹具树是 t.TempDir() 现场写的 ——
没有「运行时读真仓源码树」的部分 ⇒ 全部变异都是 **overlay**（被编译的那一边），
副本只需要 kit 一个仓，GOWORK=off 跑。

每个变异都是**一处**改动：把一条规则退回旧行为（或者把守卫的一处识别摘掉），
然后跑那条本该拦住它的守卫测试。
变红 = 那个守卫是真的；仍绿 = 那个守卫是假的（脚本会列出来并以非零码退出）。
"""
import json
import os
import shutil
import subprocess
import sys

# ⚠️ realpath, NOT abspath: on macOS /tmp is a symlink to /private/tmp, and
# a path that disagrees with the one the tooling resolves is a path that
# silently does nothing.
OUT = os.path.realpath("/tmp/jms-mutants-naming")

ROOT = os.path.realpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
WS = os.path.join(OUT, "ws")
KIT = os.path.join(WS, "jumpserver-kit")

GUARD = os.path.join(ROOT, "pkg/arch/arch.go")
TEST = os.path.join(ROOT, "pkg/arch/naming_test.go")

guard_src = open(GUARD, encoding="utf-8", errors="replace").read()
test_src = open(TEST, encoding="utf-8", errors="replace").read()

# SOURCES is the snapshot every mutation was built FROM — the source as it
# was when this script started.
SOURCES = {GUARD: guard_src, TEST: test_src}

STALE = []

# ALLOWED_SITES holds the mutations that MUST change more than one place,
# and why.
#
# ⚠️ "One mutation, one place" is what keeps the sweep honest: a mutation
# that changes two places exercises two guards at once, and the report then
# says one thing while two things happened.
ALLOWED_SITES = {
    "两处一致性检查一起摘：混合命名空间放行": "「全目录一个命名空间」有**两道独立的 Enforcement**："
                        "flatVocabulary 的先收一致（平铺布局的入口推导用它）与主循环的"
                        "逐文件比对（两种布局共用）。只摘一道，另一道照样把混合命名空间的"
                        "夹具打红 ⇒ 报告会说「牙齿是真的」而真相是「还剩一道」。"
                        "两处分担一条规则 ⇒ 合在一起才是「这条规则没了会怎样」这个问题。",
    "两处缺命名空间检查一起摘：缺 namespace go 放行": "「文件不得缺 namespace go」同样有两道：flatVocabulary 的"
                          "case ns == \"\" 与主循环的 case \"\"。只摘一道，另一道仍拦"
                          "⇒ 必须一起摘才测得出这条规则独立有没有牙齿。",
}

# M holds the mutations that MUST be caught: each one breaks the rule, and
# the guard has to go red.
M = {}

# BLIND_SPOTS holds the edits that are deliberately NOT caught. They are not
# failures — they are the **documented boundary** of this guard.
#
# ⚠️ Why they are in the script at all: a guard's boundary that lives only
# in someone's head is a boundary that moves. ⇒ These are asserted to stay
# GREEN, and when one of them turns RED the script says so — that means the
# boundary got TIGHTER, which is good news and a reason to delete the entry.
BLIND_SPOTS = {}


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


def mut(name, files):
    M[name] = files


def blind(name, files, why):
    BLIND_SPOTS[name] = (files, why)


# ---- 变异 -------------------------------------------------------------------

# A1 「摘掉平铺分支」：base == "idl" 的分支删掉 ⇒ 平铺布局被当成嵌套布局判
# （base = "idl"，入口 idl/idl.thrift 不存在）⇒ 平铺合规夹具也必须红。
FLAT_BRANCH = '''		if base == "idl" {
			base = flatVocabulary(t, root, dir, idls, fail)
			if base == "" {
				continue
			}
		}
'''
mut("摘掉平铺分支：平铺布局回退成按目录名判", {
    GUARD: sub1(guard_src, FLAT_BRANCH, "", "摘掉平铺分支"),
})

# A2 「入口存在检查摘掉」：删掉入口文件必须存在的检查 ⇒ 缺入口夹具
# （想要违规、拿到零条）必须红。
ENTRY_CHECK = '''		if _, err := os.Stat(entry); err != nil {
			fail("%s: the IDL files name the package %s, but there is no "+
				"entry %s.thrift: the entry is the file the package is "+
				"reassembled from", relToInternal(root, dir), base, base)
			continue
		}
'''
mut("入口存在检查摘掉：没有 <包名>.thrift 也放行", {
    GUARD: sub1(guard_src, ENTRY_CHECK, "", "入口存在检查摘掉"),
})

# A3 「两处一致性检查一起摘」（ALLOWED_SITES 登记了两处必须一起改）。
#
# 「全目录一个命名空间」有两道独立 Enforcement：flatVocabulary 的一致
# 性（平铺布局拿它推入口名）与主循环的逐文件比对（两种布局共用）。
# 只摘一道，另一道照样把混合命名空间的夹具打红 ⇒ 一起摘才测得出这条
# 规则本身有没有牙齿。
CONSIST_MAIN = '''			default:
				fail("%s: declares namespace go %s, but the package is %s: "+
					"every file in an IDL directory speaks for one package",
					relToInternal(root, idl), ns, base)
				ok = false
			}
'''
CONSIST_MAIN_GONE = '''			default:
			}
'''
CONSIST_FLAT = '''		case ns != pkg:
			fail("%s: declares namespace go %s, but this directory already "+
				"speaks %s: one flat idl/ directory speaks ONE package",
				rel, ns, pkg)
			ok = false
		}
'''
CONSIST_FLAT_GONE = '''		case ns != pkg:
		}
'''
a3 = sub1(guard_src, CONSIST_MAIN, CONSIST_MAIN_GONE, "两处一致性检查一起摘(主循环)")
a3 = sub1(a3, CONSIST_FLAT, CONSIST_FLAT_GONE, "两处一致性检查一起摘(flatVocabulary)")
mut("两处一致性检查一起摘：混合命名空间放行", {GUARD: a3})

# A4 「包存在检查摘掉」：no package called … 那一条永不触发 ⇒ 「契约声明了
# 但仓里没这个包」的夹具（想要违规、拿到零条）必须红。
mut("包存在检查摘掉：声明了包不存在也放行", {
    GUARD: sub1(guard_src, "\t\tswitch len(found) {\n\t\tcase 0:",
                 "\t\tswitch len(found) {\n\t\tcase 999:", "包存在检查摘掉"),
})

# A5 「平铺锚点错名」：base == "idl" 改成 "IDL" ⇒ 平铺分支永远不触发 ⇒
# 平铺合规夹具被误报（想要零条、拿到违规）必须红。
#
# ⚠️ 这一条钉的是**极性/拼写**：守卫认平铺布局靠的就是这一个字符串，
# 写错一个字，所有单词汇仓全被误报。
mut("平铺锚点错名：idl 写成 IDL", {
    GUARD: sub1(guard_src, '\t\tif base == "idl" {', '\t\tif base == "IDL" {',
                 "平铺锚点错名"),
})

# A6 「两处缺命名空间检查一起摘」（ALLOWED_SITES 登记了两处必须一起改）。
NOSNS_FLAT = '''		case ns == "":
			fail("%s: declares no `namespace go` at all: a flat idl/ "+
				"directory speaks the one package its files declare", rel)
			ok = false
'''
NOSNS_FLAT_GONE = '''		case ns == "":
'''
NOSNS_MAIN = '''			case "":
				fail("%s: declares no `namespace go` at all: every file in "+
					"an IDL directory speaks for the package the directory names",
					relToInternal(root, idl))
				ok = false
'''
NOSNS_MAIN_GONE = '''			case "":
'''
a6 = sub1(guard_src, NOSNS_FLAT, NOSNS_FLAT_GONE, "两处缺命名空间检查一起摘(flat)")
a6 = sub1(a6, NOSNS_MAIN, NOSNS_MAIN_GONE, "两处缺命名空间检查一起摘(主循环)")
mut("两处缺命名空间检查一起摘：缺 namespace go 放行", {GUARD: a6})

# ---- 守卫的边界（必须仍然绿） ------------------------------------------------

# B1 「thrift 语法不查」：夹具树里塞一份**语法全坏**但带 namespace 行的
# 文件 ⇒ 守卫照常绿。
#
# ⚠️ 这不是缺陷，是**这条守卫到哪儿为止**：namespaceGo 是按行 grep，不解析
# thrift 语法 —— 语法错在 `./script/gen-idl.sh` 生成时由 thriftgo 兜住
# （生成物入库，编不过就是红）。⇒ 它登记在这儿，是为了让「这条边界在哪儿」
# 有一处可以查的地方。
FLAT_OK_BUILD = '''			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
			},'''
FLAT_OK_BROKEN = '''			build: func(t *testing.T, root string) {
				writeThrift(t, root, "idl/jmsexec.thrift", "jmsexec")
				writeThrift(t, root, "idl/run.thrift", "jmsexec")
				writeGoPkg(t, root, "biz/model/jmsexec/x.go", "jmsexec")
				// 语法全坏但带 namespace 行：守卫只查命名，不解析 thrift。
				broken := filepath.Join(root, "idl/broken.thrift")
				if err := os.WriteFile(broken,
					[]byte("this is not thrift at all\\nnamespace go jmsexec\\n"), 0o600); err != nil {
					t.Fatalf("write %s: %v", broken, err)
				}
			},'''
blind("边界：thrift 语法不查（行 grep，语法由生成时兜住）", {
    TEST: sub1(test_src, FLAT_OK_BUILD, FLAT_OK_BROKEN, "边界：thrift 语法不查"),
}, "namespaceGo 是按行 grep：语法合法性由 gen-idl.sh 生成时 thriftgo 兜住，"
   "本守卫只管命名 —— 想让它管语法，先给守卫找一把 thrift 解析器再说")

# CANARY: the guard reports a spurious violation on every directory ⇒ every
# subtest MUST go red.
#
# ⚠️ It has to make the test FAIL (not fail to compile): a canary that breaks
# the build is caught by the compiler, not by the guard, and proves nothing
# about the overlay.
CANARY = ("【canary】守卫对每个目录都报一条假违规", {
    GUARD: sub1(guard_src,
                 "\tvar errs []string\n\tfail := func(",
                 "\tvar errs []string\n\terrs = append(errs, \"canary violation\")\n\tfail := func(",
                 "canary"),
})

GUARD_TEST = "TestContractVocabularyNaming"
GUARD_PKG = "./pkg/arch/"


def make_copy():
    """Copy the repository into OUT/ws — the real one is never touched."""
    if os.path.exists(WS):
        shutil.rmtree(WS)
    os.makedirs(WS)
    shutil.copytree(ROOT, KIT,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))


def in_copy(path):
    return os.path.join(KIT, os.path.relpath(path, ROOT))


def source_of(path):
    return SOURCES[path]


def effective_sites(original, content):
    """How many places one mutation touched.

    ⚠️ The unit is the CONTIGUOUS EDIT REGION, not the line: deleting one
    logical block of six lines is ONE site (one decision), and two blocks
    far apart are TWO sites — which is what ALLOWED_SITES is for.
    """
    a = original.split("\n")
    b = content.split("\n")
    if b[:len(a)] == a:
        return 1
    import difflib
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    changed = 0
    for tag, _i1, _i2, _j1, _j2 in sm.get_opcodes():
        if tag != "equal":
            changed += 1
    return max(1, changed)


def run_one(name, files, verbose, expect="red"):
    """Run one mutation. Returns "red", "green" or "build-failed"."""
    replace = {}
    for path, content in files.items():
        tmp = os.path.join(OUT, f"{name}_{os.path.basename(path)}")
        open(tmp, "w").write(content)
        replace[in_copy(path)] = tmp
    overlay = os.path.join(OUT, f"overlay_{name}.json")
    json.dump({"Replace": replace}, open(overlay, "w"))
    cmd = ["go", "test", "-v", "-overlay=" + overlay, GUARD_PKG, "-run", "^" + GUARD_TEST + "$"]
    p = subprocess.run(
        cmd, cwd=KIT, capture_output=True, text=True,
        env={**os.environ, "GOFLAGS": "-mod=readonly", "GOPROXY": "off", "GOWORK": "off"})
    out = p.stdout + p.stderr
    # ⚠️ The test has to have RUN. A -run pattern that matches nothing
    # exits 0 — and "nothing ran, so it is green" is exactly how a
    # mutation sweep lies to you.
    ran = ("--- PASS: " + GUARD_TEST) in out or ("--- FAIL: " + GUARD_TEST) in out
    if not ran:
        if "build failed" in out or "[setup failed]" in out or "cannot use" in out:
            if verbose:
                print(f"🧱 {name}: 编译失败（编译器逮住了改动，测试没跑到 —— 不算守卫立功）")
            return "build-failed"
        print(f"⚠️  {name}: 测试**没跑**（包 {GUARD_PKG} 里没有 {GUARD_TEST}）—— 这个变异不算数")
        return "green"
    red = p.returncode != 0
    if verbose:
        if expect == "red":
            print(("✅" if red else "❌") + f" {name}: {GUARD_TEST} "
                  + ("变红" if red else "仍绿 —— 守卫是假的"))
        else:
            print(("✔️" if not red else "⬆️") + f" {name}: {GUARD_TEST} "
                  + ("仍绿（边界没变）" if not red else "变红了 ⇒ 边界收紧了（或坏了）"))
    return "red" if red else "green"


def report_stale():
    """⚠️ 一次报全部 —— 不是第一个就退出。"""
    if not STALE:
        return False
    print(f"⚠️  变异目标有问题（{len(STALE)} 处）：锚点不唯一或没匹配上")
    for old, n, name in STALE:
        print(f"   - {name}: {n}处: {old!r}")
    return True


def check_effective(name, files):
    """这条变异生效了吗？没生效（内容没变）说明锚点没匹配上。"""
    for path, content in files.items():
        if content == source_of(path):
            print(f"⚠️  {name}: 变异没生效（模式没匹配上）")
            return False
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
    cname, cfiles = CANARY
    if not check_effective(cname, cfiles):
        return 1
    print("先跑 canary：")
    if run_one(cname, cfiles, True) != "red":
        print("❗ canary 没有变红 ⇒ overlay 没生效，后面每条变异都会跑在**未变异的代码**上。")
        print("   （这一轮的数字不作数。）")
        return 1
    print()

    # ⚠️ 一次变异只能改一处（登记过的多处变异除外）。
    site_checked = 0
    site_violations = []
    for name, files in M.items():
        for path, content in files.items():
            sites = effective_sites(source_of(path), content)
            site_checked += 1
            if sites > 1 and name not in ALLOWED_SITES:
                site_violations.append((name, sites, path))

    survivors = []
    build_failed = []
    prints = {}
    for name, files in M.items():
        for path, content in files.items():
            fp = (path, content)
            if fp in prints:
                print(f"⚠️  {name}: 与「{prints[fp]}」是同一处编辑 —— 这一条没有新增检查")
                survivors.append(name)
            else:
                prints[fp] = name

    for name, files in M.items():
        if name in survivors:
            continue
        if not check_effective(name, files):
            survivors.append(name)
            continue
        outcome = run_one(name, files, verbose)
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
    for name, (files, why) in BLIND_SPOTS.items():
        if not check_effective(name, files):
            tight.append(name)
            continue
        outcome = run_one(name, files, verbose, expect="green")
        if outcome == "red":
            print(f"   ⬆️  {name}: 变红了 ⇒ 这条边界**收紧**了（或坏了）—— 请复核")
            tight.append(name)
        else:
            print(f"   ✔️  {name}: 仍绿（边界没变）—— {why}")

    print()
    print(f"🔍 锚点唯一性：{len(M) + len(BLIND_SPOTS) + 1} 条变异的锚点全部唯一（无重复、无未匹配）")
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
    if survivors or tight:
        if survivors:
            print("存活（假守卫）:", survivors)
        if tight:
            print("边界变紧或损坏:", tight)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
