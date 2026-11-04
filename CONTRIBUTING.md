# 参与贡献（jumpserver-kit）

感谢你愿意动手。这个仓的规矩比一般项目多几条 —— 不是为了仪式感，是因为**这个仓的前任栽过跟头，
而那些跟头现在都写成了守卫**，绕开守卫的 PR 会在评审时被挡回来。

## 动手之前

1. 读 [`AGENTS.md`](AGENTS.md) —— 它记着架构不变量（底座不得依赖服务、
   契约类型必须真被产出）与「已经在哪些地方栽过」的清单；
2. 读 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) —— 三仓的边界与依赖方向；
3. 认领一个 issue（或者自己开一个，说清要改什么行为）。

## 这个仓是什么

**共用底座**（库，没有二进制）：协议层（`pkg/jmsapi`）、工具注册与门禁（`pkg/reg`）、
结果整形与输出契约（`pkg/render`）、工具调用留痕（`pkg/audit`）、
凭据脱敏（`pkg/redact`）、命令风险分类（`pkg/risk`）、失败分类（`pkg/errs`）、
共用词汇（`model/jms`）、契约守卫与架构守卫的机械。

两个服务仓：[`yi-nology/jumpserver-mgmt`](https://github.com/yi-nology/jumpserver-mgmt)（管理面，97 个工具）、
[`yi-nology/jumpserver-exec`](https://github.com/yi-nology/jumpserver-exec)（执行面，15 个工具）。

## 环境

Go **1.26+**。不需要真堡垒机就能跑全量测试（打真堡垒机的那部分由环境变量 gate 住）。

```bash
go build ./...            # 编译
go test ./...             # 全量单测
gofmt -l .                # 格式化检查（应无输出）
go vet ./...              # 静态检查
```

### ⚠️ 跨仓守卫需要三个仓同时在手

本仓有三条守卫**要三棵树同时在手**（底座的可达性、共用词汇的产出者、能力的措辞）：

```bash
# 三个仓并排放着（同级目录约定）就能直接跑：
#   ../jumpserver-kit  ../jumpserver-mgmt  ../jumpserver-exec
go test ./...

# 或者显式指路：
JMS_SIBLING_ROOTS=/path/to/jumpserver-mgmt:/path/to/jumpserver-exec go test ./...
```

⚠️ **找不到兄弟仓 ⇒ 守卫跳过**（不是失败）。**跳过 ≠ 通过** ⇒ CI 设
`JMS_REQUIRE_SIBLINGS=1`，缺树时**失败**而不是跳过。**本地也建议这么跑**：

```bash
JMS_REQUIRE_SIBLINGS=1 go test ./...
```

## ⚠️ 改底座前先发 kit 的 tag（发版节奏）

**底座改动会波及两个服务。** 底座是**承诺**：语义化版本，破坏性改动走 major。

1. 改本仓 ⇒ 跑本仓的测试；
2. **先发本仓的 tag**（例如 `v0.2.0`）；
3. 再更新两个服务仓的 `require` 到那个版本；
4. 再发两个服务。

⚠️ **不许在服务仓的 `go.mod` 里写 `replace`** —— 那会让 `go.mod` 与机器绑定，
`go list -m` 报的是路径而不是版本，`require` 里的版本号变成一句空话。
本地联调用**不入库**的 `go.work`。

## 改代码的规矩

| 规矩 | 为什么 |
|---|---|
| **底座不许伸手进某个服务** | 它就不再是共用的，而是那个服务披着共用名字的私有代码 |
| **一个包只能被一个服务够到** | 只被一个服务够到的包就是那个服务的私有代码（守卫：`pkg/arch` 的 `CheckBaseSharedByBoth`） |
| **要加的词/规则只加这一份** | 凭据词表在 `pkg/redact`，两份会漂（历史上差过 14 条） |
| **声明输出形状**（`OutputSchema`） | 服务端在返回前按它校验，形状不对直接报错 |
| **别跑 `go mod tidy`** | 受限网络下会失败；手工同步 `go.mod` 的 `require` |
| **别提交构建产物** | 本仓是库，没有二进制；产物落在 `./bin/`（服务仓） |
| **`go.work` 不入库** | 它是本机的联调接线，入库会让 `go.mod` 与机器绑定 |
| **改了 IDL 要重新生成** | `./script/gen-idl.sh`，生成物（`model/jms/`）入库 |

## 验证要求（交付前必须过）

- `go build ./...`、`go test ./...`、`gofmt -l .`（无输出）、`go vet ./...` 全绿；
- **跨仓守卫真跑了**（`JMS_REQUIRE_SIBLINGS=1 go test ./...`）——
  「跳过」不算通过；
- **两个服务仓也要跑一遍**（底座的 API 变了，两个服务都要跟着改 require 并跑测试）。
  **只跑本仓的测试不算交付**；
- 改动 ≥ 300 行，或动了**协议 / 并发 / 权限身份 / 失败路径 / 存量行为** ⇒
  起一个**没参与过的独立审阅代理**看一遍。提示词模板在 [`script/review-prompt.md`](script/review-prompt.md)。

## 提交信息

用中文，说明**改了什么行为**，不是「更新代码」。

```
feat(redact): 凭据词表加 pass_phrase，覆盖 ssh 私钥口令
```

好标题：`feat(kit):` `fix(kit):` `chore(script):` `docs:`
—— 行为变了用 `feat`/`fix`，只动文档或脚本用 `docs`/`chore`。
⚠️ **底座的改动单独成一个提交**，提交信息里写清它是**破坏性**还是**兼容的** ——
两个服务仓要跟着改 require。

## 别做的事

- ❌ 把凭据贴进 issue / PR / 日志（token、私钥、内网地址）—— 见 [`SECURITY.md`](SECURITY.md)；
- ❌ 顺手改不属于这次改动的代码（review 的人会问「这行为为什么变了」）；
- ❌ 在底座里伸手进某个服务；
- ❌ 用 `git commit -a` 把别人的在制品一起卷进来 —— **只 add 你自己动过的文件**。

## 报告安全问题

**别开公开 issue**，见 [`SECURITY.md`](SECURITY.md)。
