# 变更记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 变更

### 新增

### 修复

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
