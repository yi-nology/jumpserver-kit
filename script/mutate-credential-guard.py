#!/usr/bin/env python3
"""变异测试：明文凭据那条守卫是不是真的会红。

为什么它在仓里：一条「看起来在管」的守卫，如果没人证明它会红，那它就是
一句安慰话。本仓的历史里真的躺过一枚堡垒机管理员的令牌（发布脚本与 e2e
测试里都有），它是被人**手工翻历史**才发现的 —— 构建、抓包、审计都没
报 ⇒ 那条守卫当时根本不存在。

⚠️ 这条守卫是**新加**的，所以它也得自证会红。

用法（在底座仓根目录）：

    python3 script/mutate-credential-guard.py       # 跑全部变异
    python3 script/mutate-credential-guard.py -v    # 顺带打印每个变异做了什么

工作集（哪些仓参与这一轮）：

    JMS_SIBLING_ROOTS=/path/to/jumpserver-mcp:/path/to/jumpserver-mcp-exec

没有这个环境变量时用同级目录约定（见 script/workset.py）。

⚠️ **为什么用整仓副本**（而不是 overlay）：这条守卫**在运行时扫源码树**
⇒ overlay 只影响编译器、看不见运行时的读盘 ⇒ 用 overlay 注入的源码树
变异**根本不会落地** ⇒ 每一条都会「仍绿」⇒ 报告会说「守卫全是假的」而
真相是「它压根没扫到变异」。

⚠️ **变异落在服务仓里**：守卫的**体**在底座（pkg/arch），而**入口**在两个
服务仓的 internal/arch/ 里 ⇒ 「实现只有一份、两个入口都接上了它」这件事，
只能靠「改服务仓的工作树 ⇒ 服务仓那条守卫变红」来证明。

⚠️ 本脚本源码里**不许出现**连续的长十六进制串：底座自己那条守卫会扫
kit 仓的工作树 ⇒ 一枚写在脚本里的「假凭据」也会被它当成泄漏。⇒ 这里的
凭据是**拼**出来的。
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
OUT = os.path.realpath("/tmp/jms-mutants-credential")

ROOTS = workset.roots(__file__)

# 副本里三个仓**保持原来的目录名**并排放在 OUT/ws/ 下 ⇒ 守卫的同级目录
# 约定在副本里照样成立。
WS = os.path.join(OUT, "ws")
COPY_ROOTS = [os.path.join(WS, os.path.basename(r)) for r in ROOTS]
COPY_SIBLING_ENV = ":".join(COPY_ROOTS)

MGMT = "jumpserver-mcp"
EXEC = "jumpserver-mcp-exec"
KIT = "jumpserver-mcp-kit"

# The guard: one name, three entry points (the kit itself and the two
# services).
GUARD = "TestThePlaintextCredentialsAreNotInTheRepository"

# A credential-shaped value, assembled so that this script holds no
# forty-hex literal of its own.
#
# ⚠️ It is NOT a real credential: it is the same shape, so the guard has
# to treat it as one.
LEAK = "a1b2c3d4" * 5


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


# The mutations: each one breaks ONE rule, and the guard has to go red.
#
# (名字, 仓, {相对路径: 内容}, 期望)
M = []


def mut(name, repo, files, expect="red"):
    M.append((name, repo, files, expect))


# M1 「发布脚本里写死了令牌」：这正是本仓历史上真实发生过的事 —— 令牌被
# 写进 script/publish-mcp.py，然后一个 push 就把它公开了。
mut("发布脚本里写死了令牌", MGMT, {
    "script/leaked.py":
        "# a credential typed into a file\n"
        "JUMPSERVER_TOKEN = \"" + LEAK + "\"\n",
})

# M2 同一条规则在执行面那边也要有人守：底座的体是**一份**，两个入口都得
# 接上它 ⇒ 改执行面的工作树，执行面那条守卫必须红。
mut("执行面的脚本里写死了令牌", EXEC, {
    "script/leaked.py":
        "# a credential typed into a file\n"
        "JUMPSERVER_TOKEN = \"" + LEAK + "\"\n",
})

# M3 「私钥块」：私钥不进仓，形状本身就说明了一切，不需要语境。
mut("仓里躺着一个私钥块", MGMT, {
    "deploy/leaked.pem":
        # jms:allow-credential
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEA\n"
        "-----END RSA PRIVATE KEY-----\n",
})

# M4 底座自己也守着：kit 仓的工作树同样不许有明文凭据。
mut("底座仓里写死了令牌", KIT, {
    "script/leaked.py":
        "# a credential typed into a file\n"
        "JUMPSERVER_TOKEN = \"" + LEAK + "\"\n",
})

# M5 边界（登记在案，必须仍然绿）：**形状**像凭据但**语境**不是 —— 一枚
# commit SHA 与一个 digest 都不是凭据。⚠️ 这一条钉住的是「判据没有把
# 整个仓库的哈希都当成凭据」：守卫一旦收紧成「看见长十六进制就报」，
# .github/workflows/ 里的每一个 pin 都会把它叫醒。
mut("边界：一枚 commit SHA（仍然绿）", MGMT, {
    ".github/workflows/pin.yml":
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: actions/checkout@" + LEAK + " # v7\n",
})

# M6 边界（仍然绿）：键名不是凭据 ⇒ 值再长也不是凭据。
mut("边界：非凭据键下的长摘要（仍然绿）", MGMT, {
    "docs/digest.md":
        "digest: " + LEAK + "\n",
})

# M7 边界（仍然绿）：**文件里没有**那个值，就不是这个守卫的事 —— 值是运行
# 时拼起来的，静态读树看不见它。
mut("边界：值是运行时拼起来的（仍然绿）", MGMT, {
    "script/assembled.py":
        "value = \"" + LEAK[:20] + "\" + \"" + LEAK[20:] + "\"\n",
})


def run_one(name, repo, files, expect, verbose):
    """Run one mutation. Returns "red", "green" or "build-failed"."""
    for rel in files:
        clean_in(repo, rel)
    for rel, content in files.items():
        write_in(repo, rel, content)
    repo_dir = repo_by_name(repo)
    cmd = ["go", "test", "-v", "./internal/arch/", "-run", "^" + GUARD + "$"]
    try:
        p = subprocess.run(
            cmd, cwd=repo_dir, capture_output=True, text=True,
            env={**os.environ, "GOFLAGS": "-mod=readonly", "GOPROXY": "off",
                 "PWD": repo_dir, "JMS_SIBLING_ROOTS": COPY_SIBLING_ENV})
    finally:
        for rel in files:
            clean_in(repo, rel)
    out = p.stdout + p.stderr
    # ⚠️ The test has to have RUN. A -run pattern that matches nothing exits 0 —
    # and "nothing ran, so it is green" is exactly how a mutation sweep lies.
    ran = ("--- PASS: " + GUARD) in out or ("--- FAIL: " + GUARD) in out
    if not ran:
        if "build failed" in out or "[setup failed]" in out or "cannot use" in out:
            if verbose:
                print("🧱 %s: 编译失败（编译器逮住了改动，测试没跑到 —— 不算守卫立功）" % name)
            return "build-failed"
        print("⚠️  %s: 测试**没跑**（internal/arch/ 里没有 %s）—— 这个变异不算数" % (name, GUARD))
        return "green"
    red = p.returncode != 0
    if verbose:
        if expect == "red":
            print(("✅" if red else "❌") + " %s: %s %s"
                  % (name, GUARD, "变红" if red else "仍绿 —— 守卫是假的"))
        else:
            print(("✔️" if not red else "⬆️") + " %s: %s %s"
                  % (name, GUARD, "仍绿（边界没变）" if not red else "变红了 ⇒ 边界收紧了（或坏了）"))
    return "red" if red else "green"


def main():
    verbose = "-v" in sys.argv
    make_copy()
    # ⚠️ canary：先跑一条**必须变红**的。它不红 ⇒ 副本没生效 / 测试没跑到 ⇒
    # 后面每一条都会「仍绿」⇒ 报告会说「守卫全是假的」而真相是「什么都没跑」。
    canary = M[0]
    print("先跑 canary：")
    outcome = run_one(canary[0], canary[1], canary[2], canary[3], True)
    if outcome != "red":
        print("⚠️  canary 没变红 ⇒ 这一轮的数字不算数（副本或测试没生效）")
        return 1
    print()
    survivors = []
    build_failed = []
    for name, repo, files, expect in M:
        outcome = run_one(name, repo, files, expect, verbose)
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
