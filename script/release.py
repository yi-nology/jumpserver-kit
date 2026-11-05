#!/usr/bin/env python3
"""发版链编排：把「改源码 ≠ 生效」那条长链固化成一条命令。

用法（在任意一个仓根目录跑都行，脚本自己按同级目录约定找齐三仓）：

    # 发底座：commit 已在树上 ⇒ 打 tag 推远端
    python3 ../jumpserver-kit/script/release.py kit v0.8.1

    # 发服务：可选 --kit 先把 require 抬到已发布的底座版本
    python3 ../jumpserver-kit/script/release.py exec 0.12.0 --kit v0.8.1
    python3 ../jumpserver-kit/script/release.py mgmt 0.12.0 --kit v0.8.1

    # 只看步骤不动手：
    python3 ../jumpserver-kit/script/release.py exec 0.12.0 --dry

为什么它在仓里（而不是继续靠 memory 里的清单）：这条链有 20+ 步，顺序错一步
就假红——「先 build 再打 tag」会被版本守卫拦、「go mod download 不带
GOWORK=off」会被 go.work 静默跳过、「publish 完不改 mcp.json」会让真调
永远打在旧二进制上。每一步的坑都是真踩过的；踩过的坑应该变成代码，不是
变成下一次还会再踩的记忆。

链的形状（服务仓；底座只有第 1、8 步）：
    1.  预检：工作树干净、在 main、tag 不存在
    2.  [--kit] 抬 require → GOWORK=off 补 go.sum → 同步 restore 清单
    3.  抬 main.go 的 Version 常量
    4.  重生成 swagger（版本进了 OpenAPI，守卫逐字节比对）
    5.  commit（把 2-4 的改动收进一个提交）
    6.  tag —— 顺序是刻意的：**先 tag 再 build**（版本守卫拿
        git describe --exact-match 比对，build 时 HEAD 上必须有 tag）
    7.  build.sh（编译 + 全量测试含 -race；绿之前什么都不往外推）
    8.  push main + tag
    9.  publish-mcp.py（新时间戳目录，不覆盖旧二进制）
    10. 改 ~/.minimax/mcp.json 的 command 指向新目录
    11. JSON-RPC 冒烟：tools/list 数工具 + exec 多验一次 dry_run
        （环境变量从 mcp.json 该 server 的 env 块继承——脚本不碰凭据，
        只复用配置里已有的）

⚠️ 冒烟通过 ≠ 生效：MCP 工具目录是客户端启动时缓存的，**要重启会话**。
脚本最后会把这句话再打印一遍。
"""
import json
import os
import re
import subprocess
import sys

# ---- 工作集 -----------------------------------------------------------------

HERE = os.path.dirname(os.path.realpath(__file__))
KIT = os.path.realpath(os.path.join(HERE, ".."))
WORKSET = os.path.dirname(KIT)  # 三仓同级
EXEC = os.path.join(WORKSET, "jumpserver-exec")
MGMT = os.path.join(WORKSET, "jumpserver-mgmt")

REPOS = {
    "kit": KIT,
    "exec": EXEC,
    "mgmt": MGMT,
}

# MCP 配置名 ≠ 仓名（这套名字是当初配置时定的，改配置的代价大于记一张表）。
MCP_JSON = os.path.expanduser("~/.minimax/mcp.json")
MCP_SERVER_NAME = {"exec": "jms-exec", "mgmt": "jumpserver"}

# 工具数钉值（policy 守卫的对外口径；改了工具就要来这里对齐）。
TOOL_COUNT = {"exec": 16, "mgmt": 97}

# 冒烟时 exec 的 dry_run 探针：必判 READ（危险分类回归的第一个信号）。
SMOKE_PROBE = {"asset": "smoke-probe", "command": "df -h", "dry_run": True}

DRY = "--dry" in sys.argv


# ---- 小工具 -----------------------------------------------------------------

def run(cmd, cwd=None, env=None, capture=True):
    """跑一条命令；--dry 模式下只打印。失败抛异常（链就此停住）。"""
    shown = " ".join(cmd) if isinstance(cmd, list) else cmd
    where = f"  [{os.path.relpath(cwd, WORKSET)}]" if cwd else ""
    print(f"  $ {shown}{where}")
    if DRY:
        return ""
    p = subprocess.run(cmd, cwd=cwd, env=env, text=True,
                       capture_output=capture)
    if p.returncode != 0:
        out = (p.stdout or "") + (p.stderr or "")
        raise SystemExit(f"❌ 命令失败（exit {p.returncode}），链在此停住：\n{out[-2000:]}")
    return p.stdout or ""


def git(repo, *args):
    return run(["git", *args], cwd=repo)


def replace_once(path, pattern, repl, what):
    """正则替换**一处**；零处或多处都拒动（锚点漂移宁可停住也不瞎改）。"""
    body = open(path, encoding="utf-8").read()
    new, n = re.subn(pattern, repl, body)
    if n != 1:
        raise SystemExit(f"❌ {what}: 模式命中 {n} 处（期望 1 处），锚点漂移，停住。")
    if not DRY:
        open(path, "w", encoding="utf-8").write(new)


_STEP = [0]


def step(title):
    _STEP[0] += 1
    print(f"\n── 步骤 {_STEP[0]} · {title} " + "─" * max(4, 60 - len(title)))


def tree_dirty(repo):
    out = subprocess.run(["git", "status", "--porcelain"],
                         cwd=repo, capture_output=True, text=True).stdout
    return [l for l in out.splitlines() if l.strip()]


# ---- 各步骤 -----------------------------------------------------------------

def preflight(repo, version):
    step("预检：干净树 / main / tag 不存在")
    dirty = tree_dirty(repo)
    if dirty:
        raise SystemExit(f"❌ 工作树不干净（{len(dirty)} 处）。发版从一个干净的提交开始：\n"
                         + "\n".join("   " + l for l in dirty[:10]))
    branch = subprocess.run(["git", "branch", "--show-current"], cwd=repo,
                            capture_output=True, text=True).stdout.strip()
    if branch != "main":
        raise SystemExit(f"❌ 不在 main 上（在 {branch!r}）。发版只从 main 发。")
    tag = "v" + version if not version.startswith("v") else version
    exists = subprocess.run(["git", "rev-parse", "--verify", "--quiet", tag],
                            cwd=repo).returncode == 0
    if exists:
        raise SystemExit(f"❌ tag {tag} 已存在。要重打先手动删（git tag -d {tag}），别覆盖。")
    print(f"  ✓ 树干净、在 main、{tag} 未占用")


def bump_kit_require(repo, kit_version):
    """抬 require → 补 go.sum → 同步 restore 清单（三方一致守卫盯着）。"""
    step(f"抬底座 require 到 {kit_version}（go.mod / go.sum / restore 清单）")
    replace_once(os.path.join(repo, "go.mod"),
                 r"(github\.com/yi-nology/jumpserver-kit\s+)v\d+\.\d+\.\d+",
                 rf"\g<1>{kit_version}", "go.mod 的 kit require")
    run(["go", "mod", "download", "github.com/yi-nology/jumpserver-kit"],
        cwd=repo, env={**os.environ, "GOWORK": "off"})
    replace_once(os.path.join(repo, "script/restore-go-modcache.sh"),
                 r'github\.com/yi-nology/jumpserver-kit@v\d+\.\d+\.\d+',
                 f"github.com/yi-nology/jumpserver-kit@{kit_version}",
                 "restore 清单的 kit 版本")


def bump_version_constant(repo, version):
    step(f"抬 Version 常量到 {version}")
    replace_once(os.path.join(repo, "main.go"),
                 r'const Version = "[^"]+"',
                 f'const Version = "{version}"', "main.go 的 Version 常量")


def regen_openapi(repo):
    if not os.path.exists(os.path.join(repo, "script/gen-openapi.sh")):
        return
    step("重生成 swagger（版本进了 OpenAPI，守卫逐字节比对）")
    run(["./script/gen-openapi.sh"], cwd=repo)


def commit(repo, message):
    step("提交")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", message)


def tag(repo, version):
    step(f"打 tag v{version} —— 先于 build：版本守卫要 HEAD 上有 tag")
    git(repo, "tag", "v" + version)


def build(repo):
    step("build.sh：编译 + 全量测试（绿之前不往外推任何东西）")
    run(["./script/build.sh"], cwd=repo, capture=False)


def push(repo, version):
    step("push main + tag")
    git(repo, "push", "origin", "main", f"v{version}")


def publish(repo):
    step("publish-mcp.py（新时间戳目录，不覆盖旧二进制）")
    out = run(["python3", "script/publish-mcp.py"], cwd=repo)
    if DRY:
        return "<dry-run 占位>"
    m = re.search(r"(/\S*jumpserver-\S*-runtime/\d{8}-\d{6}/\S+)", out)
    if not m:
        raise SystemExit("❌ publish 输出里找不到运行时路径，拿不到新目录，停住。")
    return m.group(1)


def repoint_mcp_config(server_name, binary_path):
    step(f"改 {MCP_JSON} 的 command 指向新目录")
    cfg = json.load(open(MCP_JSON, encoding="utf-8"))

    def find(o):
        if isinstance(o, dict):
            if server_name in o and isinstance(o[server_name], dict) \
                    and "command" in o[server_name]:
                return o[server_name]
            for v in o.values():
                r = find(v)
                if r:
                    return r
        if isinstance(o, list):
            for v in o:
                r = find(v)
                if r:
                    return r
        return None

    entry = find(cfg)
    if entry is None:
        raise SystemExit(f"❌ {MCP_JSON} 里找不到 server {server_name!r}，停住（手工接线，别猜）。")
    print(f"  {entry['command']}\n  → {binary_path}")
    if not DRY:
        entry["command"] = binary_path
        json.dump(cfg, open(MCP_JSON, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)
    return entry


def smoke(server_name, entry, which):
    step("JSON-RPC 冒烟：tools/list 数工具" +
              (" + dry_run 探针" if which == "exec" else ""))
    env = dict(os.environ)
    env.update(entry.get("env", {}))
    script = (
        "import json,subprocess,sys\n"
        "p=subprocess.Popen([sys.argv[1]],stdin=subprocess.PIPE,"
        "stdout=subprocess.PIPE,text=True,env=" + repr(env) + ")\n"
        "def rpc(i,m,pa=None):\n"
        " r={'jsonrpc':'2.0','id':i,'method':m}\n"
        " if pa is not None:r['params']=pa\n"
        " p.stdin.write(json.dumps(r)+'\\n');p.stdin.flush()\n"
        " while True:\n"
        "  l=p.stdout.readline()\n"
        "  if not l:sys.exit('eof')\n"
        "  try:r=json.loads(l)\n"
        "  except:continue\n"
        "  if r.get('id')==i:return r\n"
        "init=rpc(1,'initialize',{'protocolVersion':'2024-11-05','capabilities':{},"
        "'clientInfo':{'name':'release-smoke','version':'1'}})\n"
        "print('version:',init['result']['serverInfo']['version'])\n"
        "p.stdin.write(json.dumps({'jsonrpc':'2.0','method':'notifications/initialized'})+'\\n');p.stdin.flush()\n"
        "n=len(rpc(2,'tools/list')['result']['tools'])\n"
        "print('tools:',n)\n"
    )
    if which == "exec":
        script += (
            "r=rpc(3,'tools/call',{'name':'jmsx_exec','arguments':"
            + json.dumps(SMOKE_PROBE) + "})\n"
            "sc=r['result'].get('structuredContent',{})\n"
            "print('probe:',sc.get('risk'),'would:',sc.get('would_execute'))\n"
        )
    script += "p.terminate()\n"
    tmp = os.path.join(os.path.realpath("/tmp"), "jms-release-smoke.py")
    if not DRY:
        open(tmp, "w").write(script)
        run(["python3", tmp, entry["command"]], capture=False)
        os.unlink(tmp)


# ---- 入口 -------------------------------------------------------------------

def main():
    args = [a for a in sys.argv[1:] if a != "--dry"]
    if len(args) < 2:
        raise SystemExit(__doc__)
    which, version = args[0], args[1]
    kit = None
    if "--kit" in args:
        kit = args[args.index("--kit") + 1]
    if which not in REPOS:
        raise SystemExit(f"❌ 不认识 {which!r}；要 kit / exec / mgmt 之一。")
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", version):
        raise SystemExit(f"❌ 版本号 {version!r} 不像 semver（0.12.0 这样写）。")
    version = version.lstrip("v")
    repo = REPOS[which]

    print(f"发版：{which} v{version}" + (f"（底座 {kit}）" if kit else "") +
          ("　【--dry 只看步骤】" if DRY else ""))

    preflight(repo, version)
    if which == "kit":
        tag(repo, version)
        # 底座没有二进制与发布面：tag → push 即完成。
        push(repo, version)
        print(f"\n✅ kit v{version} 已推。两个服务仓接着各自发（--kit v{version}）。")
        return
    if kit:
        bump_kit_require(repo, kit)
    bump_version_constant(repo, version)
    regen_openapi(repo)
    commit(repo, f"release v{version}" +
           (f"：底座抬 {kit}" if kit else ""))
    tag(repo, version)
    build(repo)
    push(repo, version)
    binary = publish(repo)
    entry = repoint_mcp_config(MCP_SERVER_NAME[which], binary)
    smoke(MCP_SERVER_NAME[which], entry, which)

    want = TOOL_COUNT[which]
    print(f"\n✅ {which} v{version} 全链走完：tag 已推、二进制 {binary}")
    print(f"   工具数应为 {want}（冒烟输出对不上就回查 policy 守卫）")
    print("⚠️ 需要重启会话才生效：MCP 工具目录是客户端启动时缓存的。")


if __name__ == "__main__":
    main()
