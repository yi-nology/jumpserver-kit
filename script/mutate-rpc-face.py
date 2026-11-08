#!/usr/bin/env python3
"""变异测试：RPC 面与启动模型的新守卫，每条退回一次，看对应测试**会不会变红**。

覆盖的守卫：

  - pkg/rpcapi/rpcapi_test.go —— token 校验（常量时间、逐方法）、unknown tool
    的 is_error 答案语义、text 的唯一定义（render.ResultText）；
  - pkg/faces/faces_test.go —— dispatch 矩阵（http/rpc/all 的拒绝与放行）、
    缺地址提示的措辞（JMS_HTTP_ADDR + 服务自己的示例端口）。

用法（在底座仓根目录）：

    python3 script/mutate-rpc-face.py          # 跑全部变异
    python3 script/mutate-rpc-face.py -v       # 顺带打印每条变异做了什么

⚠️ overlay 落地在 /tmp（realpath 过）：键必须是 go 解析出的路径，macOS 的
/tmp 是符号链接（见 mutate-primitive-guards.py 的 canary 注记）。
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = "/tmp/jms-mutants-rpc-face"
RPCAPI = "pkg/rpcapi/rpcapi.go"
FACES = "pkg/faces/faces.go"

rpc_src = open(os.path.join(ROOT, RPCAPI)).read()
faces_src = open(os.path.join(ROOT, FACES)).read()

STALE = []
M = []


def anchor_in(text, marker):
    hits = [l for l in text.split("\n") if marker in l]
    if len(hits) != 1:
        STALE.append((marker, len(hits)))
        return None
    return hits[0]


def swap_line(text, marker, old, new):
    """把含 marker 的那一行里的 old 换成 new；其余一行不动。"""
    line = anchor_in(text, marker)
    if line is None or line.count(old) != 1:
        STALE.append((old[:60], line.count(old) if line else 0))
        return text
    return text.replace(line, line.replace(old, new))

# ① 摘 token 校验：authorize 恒真 ⇒ 错 token 畅通 ⇒ auth 测试红
mut_token = swap_line(rpc_src, "if !e.authorize(call.Token) {", "!e.authorize(call.Token)", "false")
M.append(("rpc_token_check_bypassed", {RPCAPI: mut_token},
          "TestRPCFaceRefusesWrongToken", "./pkg/rpcapi/"))

# ② unknown tool 放行：不再拦 ⇒ CallTool 报传输错 ⇒ is_error 答案语义红
mut_unknown = swap_line(rpc_src, "e.reg.Has(call.Tool)", "!e.reg.Has(call.Tool)", "false")
M.append(("rpc_unknown_tool_passes_through", {RPCAPI: mut_unknown},
          "TestRPCFaceAnswersUnknownToolWithErrorAnswer", "./pkg/rpcapi/"))

# ③ text 不走唯一定义：硬编码空串 ⇒ 双块对拍红
mut_text = swap_line(rpc_src, "Text: render.ResultText(res)", "render.ResultText(res)", 'fmt.Sprintf("~%s", render.ResultText(res))')
M.append(("rpc_text_not_the_one_definition", {RPCAPI: mut_text},
          "TestRPCFaceTextIsTheOneDefinition", "./pkg/rpcapi/"))

# ④ serve all 没配任何面也不拒 ⇒ 矩阵测试红
mut_all = swap_line(faces_src, "!hasHTTP && !hasRPC", "!hasHTTP && !hasRPC", "hasHTTP && hasRPC")
M.append(("faces_all_without_any_face_serves", {FACES: mut_all},
          "TestThePlanRefusesWhatTheConfigCannotServe", "./pkg/faces/"))

# ⑤ 缺地址的 http 提示丢了 JMS_HTTP_ADDR ⇒ 矩阵测试红（自 primitive-guards 迁入）
mut_hint = swap_line(faces_src, "serve http needs an address", " — JMS_HTTP_ADDR", "")
M.append(("faces_http_refusal_loses_env_name", {FACES: mut_hint},
          "TestThePlanRefusesWhatTheConfigCannotServe", "./pkg/faces/"))

# ⑥ 示例端口硬编码回共享文案（不再来自 ExampleAddr）⇒ 矩阵测试红（迁移）
mut_example = swap_line(faces_src, 'return ", e.g. " + h.ExampleAddr', 'return ", e.g. " + h.ExampleAddr', 'return ""')
M.append(("faces_http_refusal_hardcodes_example", {FACES: mut_example},
          "TestThePlanRefusesWhatTheConfigCannotServe", "./pkg/faces/"))

SOURCES = {RPCAPI: rpc_src, FACES: faces_src}


def source_of(path):
    return SOURCES.get(path, open(path).read())


def run_one(name, files, test, pkg):
    """跑一条变异：落地 overlay 副本 → go test 该测试 → 判红。"""
    os.makedirs(OUT, exist_ok=True)
    replace = {}
    for path, content in files.items():
        if content == source_of(path):
            return ("stale", "变异没落地（内容与源码相同）: " + os.path.basename(path))
        mpath = os.path.realpath(os.path.join(OUT, name + "-" + os.path.basename(path)))
        with open(mpath, "w") as f:
            f.write(content)
        replace[path] = mpath
    opath = os.path.realpath(os.path.join(OUT, name + ".json"))
    with open(opath, "w") as f:
        json.dump({"Replace": replace}, f)
    # ⚠️ -overlay 写在子命令之后：go test -overlay=... <pkg> -run ...
    cmd = ["go", "test", "-overlay=" + opath, pkg, "-run", "^" + test + "$", "-count=1"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "GOPROXY": "off"})
    out = r.stdout + r.stderr
    if "no tests to run" in out:
        return ("broken", "测试名不存在: " + test)
    if "--- FAIL" in out:
        return ("red", "")
    if r.returncode != 0:
        return ("broken", "变异没编译/包坏了:\n" + out[-1500:])
    return ("green", "")


def main():
    if STALE:
        print("⚠️  锚点有问题的变异（先修再谈结论）:")
        for what, n in STALE:
            print("   %r 命中 %s 处" % (what, n))
        sys.exit(2)
    red = green = broken = stale = 0
    red_names = []
    for name, files, test, pkg in M:
        verdict, why = run_one(name, files, test, pkg)
        mark = {"red": "✅ 变红（守卫是真的）", "green": "❌ 仍绿（守卫是假的）",
                "stale": "⚠️ 无效", "broken": "⚠️ 无效"}[verdict]
        print("%-44s %s %s" % (name, mark, why if why else ""))
        if verdict == "red":
            red += 1
            red_names.append(name)
        elif verdict == "green":
            green += 1
        else:
            broken += 1
    print("\n合计：%d 红 / %d 仍绿 / %d 无效" % (red, green, broken))
    # 统一输出契约（kit#22）：与其余 mutate-* 脚本同形。
    survivors = [n for n in [e[0] for e in M] if n not in red_names]
    print(f"MUTATIONS: killed={red} total={len(M)} survivors={' '.join(survivors) if survivors else 'none'}")
    if green or broken or len(M) != red:
        sys.exit(1)


if __name__ == "__main__":
    main()
