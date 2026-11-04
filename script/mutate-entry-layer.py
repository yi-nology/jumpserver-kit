#!/usr/bin/env python3
"""变异测试：入口层的两条新守卫（最外层 / 一个仓一个二进制）会不会变红。

为什么它在仓里：一条「看起来在管」的守卫，如果没人证明它会红，那它就是
一句安慰话。入口层这次**搬了家**（从 `cmd/<binary>/` 到仓根），判据也跟着
改了 ⇒ 新的判据必须自证会红。

用法（在底座仓根目录）：

    python3 script/mutate-entry-layer.py            # 跑全部变异
    python3 script/mutate-entry-layer.py -v         # 顺带打印每个变异做了什么

工作集（哪些仓参与这一轮）：

    JMS_SIBLING_ROOTS=/path/to/jumpserver-mcp:/path/to/jumpserver-mcp-exec

没有这个环境变量时用同级目录约定（见 script/workset.py）。

⚠️ **为什么用整仓副本**（而不是 mutate-audit.py 那套 overlay）：这两条守卫
**在运行时扫源码树**（它们读仓里的 .go 文件，自己判断「哪个包是入口层」）
⇒ overlay 只影响编译器、看不见运行时的读盘 ⇒ 用 overlay 注入的源码树变异
**根本不会落地** ⇒ 每一条都会「仍绿」⇒ 报告会说「守卫全是假的」而真相是
「它压根没扫到变异」。
⇒ 所以这里把工作集复制到 /tmp，在副本里改、在副本里跑，**真仓一个字节都不碰**
（脚本末尾逐字节核对这一点）。

每条变异都是**一处**改动：把一条规矩退回旧行为，然后跑那条本该拦住它的
守卫。测试**变红** = 那个守卫是真的；测试**仍绿** = 那个守卫是假的
（脚本会列出来并以非零码退出）。
"""
import filecmp
import os
import shutil
import subprocess
import sys

# 同仓的另一个脚本：工作集的定义。
# ⚠️ 与守卫是同一套约定，别另造一份 —— 一份拷贝会漂，而漂了的那份决定
# 报告对着的是哪一份代码。
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import workset

# ⚠️ realpath, NOT abspath: macOS 的 /tmp 是 /private/tmp 的符号链接，
# 而路径对不上时 go 命令会**默默地**按错误的路径找包。
OUT = os.path.realpath("/tmp/jms-mutants-entry-layer")

ROOT = workset.own_root(__file__)
ROOTS = workset.roots(__file__)

# 副本里三个仓**保持原来的目录名**并排放在 OUT/ws/ 下 ⇒ go.work 里的相对
# 路径（../jumpserver-mcp-kit）与守卫的同级目录约定在副本里照样成立。
WS = os.path.join(OUT, "ws")
COPY_ROOTS = [os.path.join(WS, os.path.basename(r)) for r in ROOTS]
COPY_SIBLING_ENV = ":".join(COPY_ROOTS)

# 两个服务仓：入口层的守卫在它们各自的 internal/arch/ 里。
MGMT = "jumpserver-mcp"
EXEC = "jumpserver-mcp-exec"


def repo_by_name(name):
    """按仓名找到**副本**里那个仓。

    ⚠️ 副本，不是真仓：变异写在副本里 ⇒ 测试必须跑在副本上 ⇒ 跑在真仓上
    看到的永远是**未变异**的代码 ⇒ 每条变异都会「仍绿」。
    """
    for r in ROOTS:
        if os.path.basename(r) == name:
            return os.path.join(WS, os.path.basename(r))
    raise SystemExit("⚠️  工作集里没有 %s 这个仓（工作集：%s）" % (name, ", ".join(ROOTS)))


def make_copy():
    """Copy every repository of the working set into OUT/ws — the real ones
    are never touched."""
    if os.path.exists(WS):
        shutil.rmtree(WS)
    os.makedirs(WS)
    for src, dst in zip(ROOTS, COPY_ROOTS):
        shutil.copytree(src, dst,
                        ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))


def write_in(repo, relpath, content):
    """在**副本**里写一个文件，返回它的绝对路径。"""
    p = os.path.join(repo_by_name(repo), relpath)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return p


def clean_in(repo, relpath):
    """删掉副本里那个文件（上一条变异留下的）。"""
    p = os.path.join(repo_by_name(repo), relpath)
    if os.path.exists(p):
        os.remove(p)


# The mutations: each one breaks ONE rule, and a guard has to go red.
#
# (名字, 仓, {相对路径: 内容}, 该由哪条测试拦住, 期望)
M = []


def mut(name, repo, files, test, expect="red"):
    M.append((name, repo, files, test, expect))


# M1 「子目录里长出一个 package main」：一个仓一个二进制 —— 仓根之外不许
# 再有第二个 main。⚠️ 它放在 internal/ 下（不是 cmd/ 下）：放在 cmd/ 下会与
# cmd/serve 的包名冲突 ⇒ **编译失败** ⇒ 那说明编译器逮住了它，而不是守卫。
mut("子目录里长出一个 package main", MGMT, {
    "internal/entrylayer/main.go":
        "package main\n\n// A second entry point that nobody meant to add.\n"
        "func main() {}\n",
}, "TestTheEntryLayerIsOneBinaryAtTheRoot")

# M2 「internal/ 的包 import 了 cmd/」：入口层是最外层 ⇒ 谁都不许 import 它。
# ⚠️ 用**空导入**（_）��� 引用它 ⇒ 编译得过 ⇒ 变红只能来自守卫。
mut("internal/ 的包 import 了 cmd/", MGMT, {
    "internal/repository/zz_stray.go":
        "package repository\n\nimport _ \"github.com/yi-nology/jumpserver-mcp/cmd/serve\"\n",
}, "TestTheBinariesAreTheOutermostLayer")

# M3 「cmd/ 下多了一个二进制」：子命令是**入口层 import 的普通包**，不是各自
# 的二进制 ⇒ cmd/ 下出现 package main 就是一个多出来的入口。
mut("cmd/ 下多了一个二进制", EXEC, {
    "cmd/tools2/main.go":
        "package main\n\nfunc main() {}\n",
}, "TestTheEntryLayerIsOneBinaryAtTheRoot")

# M4 边界（登记在案，必须仍然绿）：入口层**自己**import 入口层是允许的 ——
# 它只许向里叫。⚠️ 这一条钉住的是「判据没有把入口层自己也当成越界者」。
mut("边界：cmd/ 根上的包 import 了子命令（仍然绿）", MGMT, {
    "cmd/zz.go":
        "package cmd\n\nimport _ \"github.com/yi-nology/jumpserver-mcp/cmd/serve\"\n",
}, "TestTheBinariesAreTheOutermostLayer", expect="green")


def run_one(name, repo, files, test, expect, verbose):
    """Run one mutation. Returns "red", "green" or "build-failed"."""
    for rel in files:
        clean_in(repo, rel)
    for rel, content in files.items():
        write_in(repo, rel, content)
    repo_dir = repo_by_name(repo)
    cmd = ["go", "test", "-v", "./internal/arch/", "-run", "^" + test + "$"]
    try:
        p = subprocess.run(
            cmd, cwd=repo_dir, capture_output=True, text=True,
            # ⚠️ JMS_SIBLING_ROOTS 指着**副本**里的三个仓：守卫读的是源码树，
            # 不是编译产物 ⇒ 它得知道另外两个仓在哪。
            env={**os.environ, "GOFLAGS": "-mod=readonly", "GOPROXY": "off",
                 "PWD": repo_dir, "JMS_SIBLING_ROOTS": COPY_SIBLING_ENV})
    finally:
        for rel in files:
            clean_in(repo, rel)
    out = p.stdout + p.stderr
    # ⚠️ The test has to have RUN. A -run pattern that matches nothing exits 0 —
    # and "nothing ran, so it is green" is exactly how a mutation sweep lies.
    ran = ("--- PASS: " + test) in out or ("--- FAIL: " + test) in out
    if not ran:
        if "build failed" in out or "[setup failed]" in out or "cannot use" in out:
            if verbose:
                print("🧱 %s: 编译失败（编译器逮住了改动，测试没跑到 —— 不算守卫立功）" % name)
            return "build-failed"
        print("⚠️  %s: 测试**没跑**（internal/arch/ 里没有 %s）—— 这个变异不算数" % (name, test))
        return "green"
    red = p.returncode != 0
    if verbose:
        if expect == "red":
            print(("✅" if red else "❌") + " %s: %s %s"
                  % (name, test, "变红" if red else "仍绿 —— 守卫是假的"))
        else:
            print(("✔️" if not red else "⬆️") + " %s: %s %s"
                  % (name, test, "仍绿（边界没变）" if not red else "变红了 ⇒ 边界收紧了（或坏了）"))
    return "red" if red else "green"


def main():
    verbose = "-v" in sys.argv
    make_copy()
    # ⚠️ canary：先跑一条**必须变红**的。它不红 ⇒ 副本没生效 / 测试没跑到 ⇒
    # 后面每一条都会「仍绿」⇒ 报告会说「守卫全是假的」而真相是「什么都没跑」。
    canary = M[0]
    print("先跑 canary：")
    outcome = run_one(canary[0], canary[1], canary[2], canary[3], canary[4], True)
    if outcome != "red":
        print("⚠️  canary 没变红 ⇒ 这一轮的数字不算数（副本或测试没生效）")
        return 1
    print()
    survivors = []
    build_failed = []
    for name, repo, files, test, expect in M:
        outcome = run_one(name, repo, files, test, expect, verbose)
        if outcome == "green" and expect == "red":
            survivors.append(name)
        elif outcome == "build-failed":
            build_failed.append(name)
        elif outcome == "red" and expect == "green":
            survivors.append(name)   # the boundary got tighter
    total = len(M)
    caught = total - len(survivors) - len(build_failed)
    print()
    print("%d/%d 个变异被**测试**杀掉" % (caught, total))
    if build_failed:
        print("另有 %d/%d 个变异编译失败（编译器逮住，测试没跑到 —— 不算守卫立功）："
              % (len(build_failed), total))
        for n in build_failed:
            print("   -", n)
    if survivors:
        print()
        print("❌ 这些变异**仍绿** —— 守卫是假的：")
        for n in survivors:
            print("   -", n)
    # ⚠️ 真仓一个字节都没碰：逐字节核对。
    dirty = []
    for src, dst in zip(ROOTS, COPY_ROOTS):
        for dirpath, dirnames, filenames in os.walk(src):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            for fn in filenames:
                a = os.path.join(dirpath, fn)
                b = os.path.join(dst, os.path.relpath(a, src))
                if not os.path.exists(b) or not filecmp.cmp(a, b, shallow=False):
                    dirty.append(os.path.relpath(a, src))
    if dirty:
        print()
        print("⚠️  真仓被改了（%d 个文件）—— 这一轮的数字不算数：" % len(dirty))
        for d in dirty[:20]:
            print("   -", d)
        return 1
    print()
    print("🔍 真仓未被触碰：%d 个仓逐字节未变（变异全在 %s 里）" % (len(ROOTS), WS))
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
