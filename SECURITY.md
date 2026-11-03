# 安全策略（jumpserver-mcp-kit）

## 报告漏洞

**别开公开 issue，也别发公开 PR。**

请用 GitHub 的 [Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidelines/reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
（Security → Report a vulnerability），或直接联系维护者。

请一并给出：受影响版本、复现步骤、你观察到的行为、你认为的影响面。

## 这个项目碰什么敏感东西

本仓是**库**，它本身**不存**任何凭据、不发起任何网络请求，但它的代码**经手**这些：

| | 说明 |
|---|---|
| **凭据的明文形态** | `pkg/redact` 是**唯一一份**凭据词表与擦洗器 ⇒ 它决定了什么被当成凭据、什么被漏掉。**词表漏一条 = 一条凭据进留痕、进 agent 的上下文窗口** |
| **留痕内容** | `pkg/audit` 决定留痕的形状：哪些列写、哪些列截断、**留痕的文件名是不是契约**（读回只认那一个形状） |
| **投递状态** | `pkg/reg` 的 `DeliveryAware` 声明 `not_sent` / `maybe_sent` ⇒ **这一格错了 ⇒ 一条可能还在跑的 `rm -rf` 被跑第二遍** |
| **命令原文** | `pkg/risk` 对命令做 AST 解析 ⇒ 它判错只读性，就等于少了一道门禁 |

⚠️ **底座的漏洞会同时落在两个服务上** ⇒ 报告时请说明你看到的是哪个服务的行为。

## 使用者的纪律

- ⚠️ **别把 token / 私钥贴进 issue、PR、聊天、日志**；
- ⚠️ **词表只加这一份**（`pkg/redact`）—— 答复路径与留痕路径**共用**它；
  往答复路径里另加一条 ⇒ 同一个词在两条路径上**一个抹一个不抹**；
- ⚠️ **别把凭据放进散文或命令行**（`the password was x`、`mysql -p'x'` 这两种形态
  脱敏器**抓不到**）—— 脱敏器认的是**键名**；
- ⚠️ **要加凭据词就加 `pkg/redact` 那一份**，别在别处写第二份。

## 留痕（audit trail）本身也是数据

留痕文件（默认 `~/.local/state/jumpserver-mcp/audit`，一进程一文件，0600）里记着
「谁在这台机器上试图跑什么」。**它也是敏感数据**：把它当审计资料保管，
别整目录丢进共享盘或日志系统。

## 依赖与供应链

本仓依赖 `oagentkit/*`、`oekit/*`（MIT）、`modelcontextprotocol/go-sdk`（MIT→Apache-2.0 过渡）、
`google/jsonschema-go`（MIT）。构建**不写 `replace`**（依赖按普通方式解析，`go.sum` 钉住内容）。

发现依赖有问题 ⇒ 按上面的私密渠道报，别在公开 issue 里贴 exploit。
