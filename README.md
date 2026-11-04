# jumpserver-kit — JumpServer MCP 服务的**共用底座**

两个 MCP 服务（[管理面](https://github.com/yi-nology/jumpserver-mgmt)、
[执行面](https://github.com/yi-nology/jumpserver-exec)）共同认的那一部分：
JumpServer 协议层、工具注册与门禁、HTTP 面（REST + MCP over streamable HTTP）、
RPC 面（kitex/thrift）、serve 生命周期、结果整形与输出契约、工具调用留痕、
凭据脱敏、命令风险分类、失败分类、共用词汇。

**这是一个库，不是可执行程序。** 本仓没有二进制，也没有配置。

| 仓库 | 是什么 |
|---|---|
| [`yi-nology/jumpserver-mgmt`](https://github.com/yi-nology/jumpserver-mgmt) | 管理面 MCP 服务（97 个工具） |
| [`yi-nology/jumpserver-exec`](https://github.com/yi-nology/jumpserver-exec) | 执行面 MCP 服务（15 个工具） |
| **`yi-nology/jumpserver-kit`**（本仓） | 两者共用的底座 |

---

## 1. 为什么底座要有自己的仓

底座是**两个服务都认的东西**：同一套协议、同一个门禁、同一份契约、同一个发布节奏。

放一个服务仓里，它就成了那个服务披着共用名字的私有代码 —— 另一个服务迟早也会伸手进去，
两个服务就这么耦上了，**而没有人决定过**。

⇒ 它有自己的仓、自己的版本、自己的守卫。底座**不认识任何一个服务**：
它一旦伸手进某个服务，就不再是共用的。

---

## 2. 里面有什么

| 包 | 干什么 |
|---|---|
| `pkg/jmsapi` | **JumpServer 协议层**：端点表、认证头、连接令牌体、响应形状、委派凭据、版本协商、重试与限流 |
| `pkg/reg` | **工具注册与门禁**（唯一注册入口）：confirm 规则、风险侧、留痕挂钩、schema 捕获、`CallTool` / `StreamableHTTPHandler` |
| `pkg/httpapi` | **HTTP 面**：REST `/api/v1/…` + MCP over streamable HTTP `/mcp`，与 stdio 共用同一注册表（同一道门禁、同一份留痕）；Bearer 认证（常量时间比较）、OpenAPI 3.1 文档生成 |
| `pkg/rpcapi` | **RPC 面（kitex/thrift）**：注册表的第三张脸——`Invoke(tool, args, token, caller)` + `Catalogue(token)`，同一扇门同一道门禁同一份留痕；token 逐调用常量时间校验，无匿名访问；bootstrap 栅栏（自调用探针）关死 kitex 启动/停止竞态窗 |
| `pkg/faces` | **serve 生命周期（唯一主人）**：子命令变数据（stdio+rides / http / rpc / all），常驻模式组合在 `oekit/bootstrap` 上 |
| `idl/jmsrpc` + `kitex_gen/jmsrpc` | RPC 契约与生成物（kitex 工具生成，**入库**；`script/gen-rpc.sh`） |
| `pkg/render` | **结果整形 + 输出契约**：从 Go 类型派生 JSON Schema，返回前校验 |
| `pkg/risk` | **命令风险分类**：用真 shell 解析器把命令解析成 AST，再按策略表判只读性（不是字符串匹配） |
| `pkg/audit` | **工具调用留痕**：每次调用一行 JSONL（调了什么、参数是什么、门禁每一段的判定与理由、放行与否、耗时） |
| `pkg/redact` | **凭据脱敏**：**唯一一份**凭据词表。两个出口（答复 / 留痕）用同一份词表 ⇒ 遮蔽强度一致 |
| `pkg/errs` | **失败分类**：把失败归成「调用方能据此做决定」的几种 |
| `pkg/textx` | 截断 |
| `pkg/fspath` | `~` 展开与路径处理 |
| `pkg/testsupport` | 测试底座（起一个内存会话、把答案读成 JSON、起名字、`MustLoad`） |
| `pkg/contractscan` | **契约守卫的机械**：认 thriftgo 生成物、抽出声明的类型、扫出引用点 |
| `pkg/arch` | **架构守卫的机械**：扫源码树、读 import、把文件路径翻译成导入路径 |
| `model/jms` | **共用词汇**的生成物（诊断结论 / 列表信封 / 工具声明 / 资产） |
| `idl/jms` | 共用词汇的 thrift 定义 |

⚠️ **词表只有一份**：凭据词表在 `pkg/redact`，不在两个服务里各抄一份。
这个仓已经吃过两次亏 —— 两套脱敏词表差 14 条、两套 audit 检查漂移。
**要加词就加 `pkg/redact` 那一份。**

---

## 3. 怎么用

```bash
go get github.com/yi-nology/jumpserver-kit@latest
```

```go
import (
    "github.com/yi-nology/jumpserver-kit/pkg/reg"
    "github.com/yi-nology/jumpserver-kit/pkg/render"
)
```

⚠️ **本仓只保证公开 API 的稳定性**：`pkg/*` 的导出符号是承诺，
`model/jms` 的生成物是契约。内部实现随便改。

### 3.1 发版节奏

**只在底座的公开 API 变了才发版。**

```
改了底座 ⇒ 先发 kit 的 tag ⇒ 再更新两个服务的 require ⇒ 再发服务
```

底座的版本是**承诺**：语义化版本，破坏性改动走 major。
两个服务各自 `require` 一个版本 —— **不写 `replace`**：
指向本机路径的 replace 会让 go.mod 与机器绑定，`go list -m` 报的是路径而不是版本，
require 里的版本号变成一句空话。

---

## 4. 守卫

底座的守卫住在**底座自己仓里**，但有几条必须**跨仓**才判得出来 —— 这正是底座独立成仓的代价，
也是它独立成仓的理由。

| 守卫 | 在哪 | 判什么 |
|---|---|---|
| 契约类型写了没人产出 | `model/jms/contract_test.go` + `pkg/contractscan` | IDL 里声明的类型，**必须有人真的产出** —— 否则它只是一段注释 |
| 工具答复必须是契约类型 | 两个服务仓的 `internal/arch/` + 本仓 `pkg/arch` | 手搓的 map 与契约在 JSON 上分不出来，只有源码扫描分得开 |
| 凭据词表不许误判自己的参数 | 两个服务仓的 `internal/arch/` + 本仓 `pkg/redact` | 误判 = 留痕不再记录那个参数 |
| **底座必须被两个服务都用** | 本仓 `internal/arch/` | 一个包只有一个服务到达 ⇒ 它就是那个服务的私有代码 |
| **底座不得依赖任何一个服务** | 本仓 `internal/arch/` | 编译器接手 + go.mod 断言 |

⚠️ 最后两条**跨仓**：本地要三个仓同时在手（同级目录或 `JMS_SIBLING_ROOTS`）。
**找不齐 ⇒ 跳过并说明缺哪棵树；CI 里强制**（`JMS_REQUIRE_SIBLINGS=1` ⇒ 缺树即失败，
不许假绿）。

`script/mutate-audit.py` 与 `script/mutate-version-guard.py` 是这些守卫的**变异测试**：
把每一处修复退回一次，看对应的守卫**会不会变红**。守卫会「说一切正常」是最糟的失败方式，
所以每个守卫都得先证明自己抓得住。

---

## 5. 目录布局

```
.
├── pkg/
│   ├── jmsapi/                 ← JumpServer 协议层
│   ├── reg/                    ← 工具注册与门禁
│   ├── httpapi/                ← HTTP 面（REST + MCP over HTTP + OpenAPI 文档）
│   ├── render/                 ← 结果整形 + 输出契约
│   ├── risk/                   ← 命令风险分类（真 shell AST 解析）
│   ├── audit/                  ← 工具调用留痕
│   ├── redact/                 ← 凭据脱敏（唯一词表）
│   ├── errs/                   ← 失败分类
│   ├── textx/                  ← 截断
│   ├── fspath/                 ← ~ 展开与路径处理
│   ├── testsupport/            ← 测试底座
│   ├── contractscan/           ← 契约守卫的机械
│   └── arch/                   ← 架构守卫的机械
├── model/jms/                  ← 共用词汇的生成物（thriftgo，产物入库）
├── idl/jms/                    ← 共用词汇的 thrift 定义
├── script/                     ← 变异测试等开发脚本
├── docs/                       ← 文档
└── AGENTS.md                   ← 给 AI 的迭代指南（改代码前先读）
```

---

## 6. 文档

| 文档 | 内容 |
|---|---|
| [`AGENTS.md`](AGENTS.md) | 给 AI 的迭代指南：架构不变量、铁律、验证要求 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 怎么参与：跑测试、改协议层、提交约定 |
| [`SECURITY.md`](SECURITY.md) | 漏洞报告与凭据处理纪律 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | 三仓的边界与依赖方向 |

---

## 7. 参与

欢迎提 issue 和 PR。动手前请读 [`CONTRIBUTING.md`](CONTRIBUTING.md) 与
[`AGENTS.md`](AGENTS.md)。

⚠️ **底座的改动会波及两个服务** ⇒ 改这里之前想清楚它是不是**两个服务都认**的东西。
只被一个服务用的代码，**属于那个服务，不属于底座**。

⚠️ **别把凭据贴进 issue / PR / 日志**。详见 [`SECURITY.md`](SECURITY.md)。

## 8. 许可

[Apache-2.0](LICENSE)。
