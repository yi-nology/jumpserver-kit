#!/usr/bin/env bash
# 从 idl/jmsrpc/jmsrpc.thrift 生成 kitex 生成物（kitex_gen/，入库）。
#
# 为什么有这个脚本：契约（IDL）是承诺，生成物是兑现。生成物**入库**与
# biz/model/ 同一规矩：构建不该依赖 kitex CLI 装没装，生成物是审阅时要读
# 的那一份。改了 IDL 不重新生成 ⇒ 面的机器（pkg/rpcapi）编译不过
# （生成物改了接口，实现没跟上），漂移当场暴露。
#
# 用法（kit 仓根）：./script/gen-rpc.sh
# 需要 kitex CLI：go install github.com/cloudwego/kitex/tool/cmd/kitex@latest
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT"
echo "==> 生成 kitex_gen/jmsrpc（kitex 工具，产物入库）"
KITEX="$HOME/go/bin/kitex"
command -v kitex >/dev/null 2>&1 && KITEX=kitex
"$KITEX" -type thrift -module github.com/yi-nology/jumpserver-kit idl/jmsrpc/jmsrpc.thrift
echo "==> 完成；生成物入库，记得一起提交"
