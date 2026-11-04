# 变更记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 变更

### 新增

### 修复

## [0.1.6] - 2026-11-04

### 变更

### 新增

- ⚠️ **明文凭据不许进仓**（守卫体在 `pkg/arch/credential.go`）：扫工作树，
  报「凭据形状的值躺在凭据语境里」。
  - **动机**：本机一个未推送远端的归档仓的 git 历史里，明文躺着一枚
    JumpServer 堡垒机 **admin 用户的 PrivateToken**（40 位十六进制）——
    在发布脚本、校验脚本与 e2e 测试里。**三个公开仓全历史 0 命中**
    （公网没有这把令牌），但它是被人**手工翻历史**才发现的：构建抓不到它，
    因为脚本里的凭据是一个完全合法的程序（它编译通过、它跑得动、它把活干完了）。
  - **判据是「形状 + 语境」两半**：形状（PEM 私钥块 / `Authorization: Token|Bearer|Basic <值>`
    / 长的十六进制串）说「这可能是秘密」；语境（键名经 `redact.IsCredentialKey`
    判定为凭据）说「它本来就是一个凭据」。
    ⚠️ **只认形状会误伤** `.github/workflows/` 里每一个 commit SHA pin
    （40 位十六进制，与堡垒机令牌同长）；**只认语境会误伤**任何写在
    `digest` 键下的长哈希。
  - **凭据词表不另写一份**：用 `redact.IsCredentialKey`（要求凭据词在键名
    **结尾**）⇒ 与留痕、答复两条路径认的是同一批词 ⇒ 不会漂。
  - **行级显式豁免**：标记 `jms:allow-credential`（写在当行或上一行）
    ⇒ 豁免当行；**每一处豁免都被守卫用 `t.Logf` 列出来**。
    ⚠️ 作用域刻意窄：文件级的豁免是「整个文件不再被读」⇒ 真凭据可以藏在
    里面而没人看见。
  - 守卫体一份，三个入口都接上：底座自己、两个服务仓各一条
    `TestThePlaintextCredentialsAreNotInTheRepository`。
- **`script/mutate-credential-guard.py`**：这条守卫的自证（7 条变异：
  4 条必须变红 —— 两个服务仓各一条、底座仓一条、私钥块一条；3 条必须仍绿
  —— commit SHA 形状 / 非凭据键 / 运行时拼接）。⚠️ 与版本守卫一样用
  **整仓副本**（守卫运行时扫源码树 ⇒ overlay 看不见）。

### 修复

- **管理面的脱敏规则本身长得像凭据**：`biz/handler/redact.go` 的 PEM
  替换模板、`redact_test.go` 的 PEM/JWT 夹具 —— 它们**必须**长得一模一样
  才能匹配 ⇒ 逐行加了 `jms:allow-credential` 豁免标记（并写清为什么）。

## [0.1.5] - 2026-11-04

### 变更

- ⚠️ **`CheckBinariesAreOutermost` 的允许集合补上「`cmd/` 根上那个包」**：
  一个叫 `cmd` 的包（文件直接放在 `cmd/` 里）的包路径是
  `<module>/cmd`（**无尾斜杠**）⇒ 旧判据（按 `/cmd/` 前缀比）不认它是
  入口层 ⇒ 它 import `cmd/<子命令>` 时会**误报**。
  ⇒ 判据改成「仓根 / `<module>/cmd` / `<module>/cmd/**` 三处都算入口层」。
  ⚠️ 今天两个服务仓都没有这种文件 ⇒ **零实际影响**，但那是个**静默**的
  不对称 ⇒ 现在说清楚。

### 新增

- **`script/mutate-entry-layer.py`**：入口层的两条守卫（最外层 / 一个仓一个
  二进制）自证会红的变异脚本（4 条，含 1 条边界）。
  ⚠️ 它用**整仓副本**而不是 overlay —— 那两条守卫是**运行时扫源码树**的，
  overlay 只影响编译器、看不见运行时的读盘 ⇒ 用 overlay 注入的源码树变异
  根本不会落地 ⇒ 每一条都会「仍绿」⇒ 报告会说「守卫全是假的」而真相是
  「它压根没扫到变异」。

### 修复

- **文档里的旧路径**：AGENTS.md 里 `biz/<面>/…` 那个模板在两个服务仓
  去掉服务名前缀之后整体失效（`biz/handler/`、`internal/service/`、
  `internal/service/policy/`、`biz/model/<包名>/`）⇒ 改成真实路径。
  ⚠️ 底座的 AGENTS.md 是**跨仓的「代码放哪」地图** ⇒ 它指错的地方，两个
  服务仓照着就会写错。

## [0.1.4] - 2026-11-04

### 变更

- ⚠️ **入口层从 `cmd/<binary>/` 搬到仓根**（两个服务仓跟着搬）⇒
  「最外层」的判据变了：`pkg/arch` 的 `CheckBinariesAreOutermost`
  原来判的是「`cmd/` 谁都不许 import」，现在判的是「**仓根与 `cmd/`** 两处
  都只许向里叫」⇒ 仓根那个 `package main` 也进了这条守卫。
- `CheckBinariesAreOutermost` 的判据改按 **module path** 说（仓根包 =
  module path 本身，`cmd/` = module path + `/cmd/`），不再靠「`cmd/` 这个
  目录名」⇒ 目录名与 module path 不必一致。
- `pkg/contractscan` 的守卫体注释跟着改：服务仓的契约守卫根从
  `biz/jumpserver` 变成 `biz`。

### 新增

- **`pkg/arch` 的 `CheckTheEntryLayerIsOneBinaryAtTheRoot`**：仓里
  **只有一个** `package main`，而且它在**仓根**；`cmd/` 下**没有**
  `package main`（子命令是入口层 import 的普通包，不是各自的二进制）
  ⇒ 「一个仓一个二进制」从约定变成机械守卫。
- **`pkg/arch` 的 `PackageNameOf`**：读一个 Go 文件的包子句。

### 修复

- ⚠️ **`CheckBinariesAreOutermost` 漏掉了仓根本身**：入口层搬到仓根
  之后，只判 `cmd/` 的话，仓根那个 `package main` 就是「最外层」却没进
  守卫。⚠️ Go 本来就不许 import 一个 main 包 ⇒ 编译器已经拦了一道，
  但**守卫里那一格是空的** —— 而空着的守卫会让人以为它还在管这件事。

## [0.1.3] - 2026-11-04

### 修复

- ⚠️ **`v0.1.2` 的 Release 没发出来**：release workflow 少了
  `go mod download` ⇒ 依赖没在 module cache 里解包 ⇒
  `TestTheDependenciesArePinned` 卡住发版（实测：golang.org/x/crypto、
  oekit/core、oekit/network 三个没解包）。
  ⇒ 加上那一步。
  ⚠️ **模块内容本身没问题** —— `v0.1.2` 作为 Go 模块是能用的
  （`go get`/`go build` 都正常），坏的只是那次 Release。

## [0.1.2] - 2026-11-04

### 新增

- **GitHub Release**（`.github/workflows/release.yml`）：tag 触发 ⇒ 先跑
  vet + 测试（含跨仓守卫，缺兄弟仓即失败），**红了就不发**；然后发一条
  带变更清单的 Release。
  ⚠️ 本仓**没有二进制、没有产物附件** —— 它是 Go 模块，`go get` 即可。

### 变更

- **AGENTS.md 落一份「拆仓带来的已知偏差」清单**：四条偏差各写清
  **方向**（更强还是更弱）与**可复现的证据** ——
  ① 契约词汇同名检查按仓分开查了（更弱）；
  ② `pkg/arch` 被显式排除在「底座必须被两个服务都用」之外（**更强**）；
  ③ ⚠️ 共用词汇的契约守卫**比它声称的更弱**（实测：底座自己的
  `pkg/audit`/`pkg/reg`/`pkg/render`/`pkg/arch` 提到了全部 9 个共享类型
  ⇒ 把执行面换成空仓，那道守卫仍然绿）；
  ④ 委派密钥缺失的报错文案变了（见 0.1.1）。
  ⇒ 「大概弱了一点」这种话，下一个人没法据此判断要不要修。

- README 的 `go get` 改用 `@latest`；ARCHITECTURE 的 `go.work` 示例
  抬到 v0.1.1，并写明「`replace` 的版本号要与 `go.mod` 的 `require` 一致
  —— 只写 `use` 不够，Go 仍会去取 `require` 那个版本的 `go.mod`」。

## [0.1.1] - 2026-11-04

### 修复

- ⚠️ **三条底座守卫其实从未执行过**（`pkg/arch/version.go`）：
  `protocolLayerFile` 拿**带 `.go` 后缀**的文件名去比 `ImportPathOf`
  （后者给的是**不带后缀**的导入路径）⇒ **永不相等** ⇒
  「状态词汇」「能力监视名单」「发行版词汇」这三条检查**一条都没跑过**，
  而守卫**仍然报绿** —— 改掉 `pkg/jmsapi` 里的状态词都不会有人听见。
  ⇒ 改成 `strings.TrimSuffix(name, ".go")`。
  ⇒ 并且：**协议层在、却找不到那个文件**时，现在**报错**（而不是在日志里
  写一句没人看的话）—— 守卫自己坏了就该红。
  ⇒ 回归用三组变异（状态词改名 / 监视名单塞假名 / 发行版词改名）验证**全红**。

### 变更

- ⚠️ **委派密钥缺失时的报错文案变了**（`pkg/jmsapi/delegation.go`）：
  原来只有 `"no delegation secret configured"`；现在额外说出**去哪找**
  （`JMS_DELEGATION_SECRET` 环境变量，或 `~/.config/jumpserver-mcp/delegation.key`
  等几个文件、权限 0600）。
  ⇒ **这条文案在拆分前的仓里从未存在过** ⇒ 它是一次**独立的行为变化**，
  不是改名，所以在这里声明。

### 修复（开发工具）

- ⚠️ **`script/mutate-version-guard.py` 拆仓后彻底失效**：它按旧结构找
  `internal/arch/version_test.go`，拆仓后那个文件不存在 ⇒ 脚本在**第一个变异
  之前**就退出，**canary 根本没机会跑**。
  ⇒ 改成按底座的 `pkg/arch/version.go` 定位，支持「守卫源码走 overlay +
  调用点走落盘」的混合改法，并按仓选择测试运行位置。
  ⇒ 修掉一个致命 bug：脚本曾在**真仓**跑测试、变异落在**副本** ⇒
  7 条变异**全假绿**。
  ⇒ 现在：canary 变红、7/7 变异被测试杀掉、登记的边界仍绿、真仓逐字节未变。

## [0.1.0] - 2026-11-04

首个发布。

### 新增

- **JumpServer 协议层**（`pkg/jmsapi`）：传输、端点表、认证头、连接令牌体、响应形状、
  委派凭据、版本协商、重试与限流、边界守卫。
  ⚠️ **端点表只有一份**：`jmsapi.ResPermissions` 这样的常量**就是**堡垒机的 URL，
  工具层只说「我要权限列表」，不说「GET /perms/asset-permissions/」。
- **工具注册与门禁**（`pkg/reg`）：唯一的注册入口（`reg.Add`）、confirm 规则、
  风险侧、留痕挂钩；以及 SDK 在链前拒掉调用时的补记（`pkg/reg/rejected.go`）。
- **结果整形与输出契约**（`pkg/render`）：从 Go 类型派生 JSON Schema，返回前校验；
  `OutcomeOf` 按约定名读答复里的 `Blocked`/`Error`/`Delivery`/`DryRun`/`WouldExecute`。
- **工具调用留痕**（`pkg/audit`）：每次调用一行 JSONL（调了什么、参数是什么、
  门禁每一段的判定与理由、放行与否、耗时、出参字节数、投递状态）、轮转与读回、体检。
- **凭据脱敏**（`pkg/redact`）：**唯一一份**凭据词表 —— 留痕与各面答复共用它。
- **命令风险分类**（`pkg/risk`）：真 shell AST 解析 + 只读命令表。
- **失败分类**（`pkg/errs`）：把失败归成「调用方能据此做决定」的几种。
- **共用词汇**（`model/jms`）：诊断结论、列表信封、工具声明、资产；
  以及契约字段的指针助手（`Opt`/`OptBool`/`OptInt32`/`OptInt64`/`OptFloat64`）。
- **契约守卫的机械**（`pkg/contractscan`）：三道守卫（底座 + 两个服务）共用一个守卫身。
- **架构守卫的机械**（`pkg/arch`）：扫源码树、读 import、把文件路径翻译成导入路径；
  跨仓守卫的「兄弟仓在哪」的约定（`JMS_SIBLING_ROOTS` / `JMS_REQUIRE_SIBLINGS`）。
- **辅助包**：截断（`pkg/textx`，rune 边界）、`~` 展开与路径处理（`pkg/fspath`）、
  测试底座（`pkg/testsupport`）。
- **跨三个仓共用的开发工具**（`script/`）：变异脚本（`mutate-audit.py`、
  `mutate-version-guard.py`）、多仓工作集定义（`workset.py`）、
  独立审阅的提示词模板（`review-prompt.md`）、`gen-idl.sh`、`restore-go-modcache.sh`。

### 变更

- ⚠️ **留痕目录与凭据文件目录改名**：从 `~/.local/state/jms-mcp/audit` 改为
  `~/.local/state/jumpserver-mcp/audit`；凭据文件目录从 `~/.config/jms-mcp/` 改为
  `~/.config/jumpserver-mcp/`（口令文件、委派 secret）。
  ⇒ **升级时要把旧目录里的东西挪过去**（或设 `JMS_AUDIT_DIR` 指回旧路径），
  否则留痕会从零开始、旧记录查不到。
