# AGENTS.md — jumpserver-mcp-kit 迭代指南

> 给 AI agent 的作业说明。**改这个仓的代码前先读完本页**，尤其第 2、3 节。

本仓 = 两个 JumpServer MCP 服务**共用的底座**：协议层、门禁、输出契约、留痕、
脱敏、风险分类、失败分类、共用词汇、契约守卫与架构守卫的机械。
**它是库，不是服务** —— 本仓没有二进制，也没有配置。
面向人读的完整说明在 [`README.md`](README.md)，
**配置与排障看两个服务仓各自的 `docs/CONFIGURATION.md`**
（[管理面](https://github.com/yi-nology/jumpserver-mcp/blob/main/docs/CONFIGURATION.md) /
[执行面](https://github.com/yi-nology/jumpserver-mcp-exec/blob/main/docs/CONFIGURATION.md)）。

---

## 1. 三个仓的关系与边界

| 仓 | 是什么 | 干什么 | 工具数 |
|---|---|---|---|
| [`yi-nology/jumpserver-mcp`](https://github.com/yi-nology/jumpserver-mcp) | MCP server `jumpserver` | **管理面** — 改堡垒机自己的配置：资产/账号/权限/标签/命令过滤/用户 | 97 |
| [`yi-nology/jumpserver-mcp-exec`](https://github.com/yi-nology/jumpserver-mcp-exec) | MCP server `jumpserver-exec` | **执行面** — 经堡垒机在**受管机器**上跑命令、传文件 | 15 |
| **`yi-nology/jumpserver-mcp-kit`（本仓）** | 共用底座（**库**） | 两个服务**共用**的东西：协议层（`pkg/jmsapi`）、门禁（`pkg/reg`）、结果整形与输出契约（`pkg/render`）、留痕（`pkg/audit`）、脱敏（`pkg/redact`）、风险分类（`pkg/risk`）、失败分类（`pkg/errs`）、契约守卫的机械（`pkg/contractscan`）、架构守卫的机械（`pkg/arch`）、共用词汇（`model/jms`） | — |

**依赖方向是单向的**：两个服务仓 `require github.com/yi-nology/jumpserver-mcp-kit`，
本仓**不 require** 任何一个服务。

目录按 **CloudWeGo hz 的标准骨架**摆（`cmd/` `biz/` `idl/` `model/` `conf/`
`script/`），只是**底座没有 `cmd/`**（它是库），
而两个服务仓各自是**一个模块一个服务**，所以它们的 `biz/` 下只有一个服务。

⚠️ **共用底座（`pkg/`、`model/`）不得依赖任何一个服务。** 底座是两个服务都认的东西：
它一旦伸手进某个服务，就不再是共用的，而是那个服务披着共用名字的私有代码
（另一个服务迟早也会伸手进去，两个服务就这么耦上了，而没有人决定过）。
守卫：`internal/arch/kit_test.go` 的 `TestTheSharedBaseDoesNotDependOnAService`
（判据是**别的 module path** —— 三个 module path 互为字符串前缀，
判定必须带尾斜杠，见 `pkg/arch.IsImportOf`）。

⚠️ **两个服务不得互相 import。** 它们答的不是同一个问题，
部署时用的配置也不同（管理面要 API token，执行面要 koko 私钥）。
守卫在各自的仓里（服务仓的 `internal/arch/`）。

**判断某个需求该改哪个**：
- 要登记/修改资产、账号、授权 → **管理面仓**（`biz/jumpserver/`）
- 要在机器上执行命令、传文件 → **执行面仓**（`biz/exec/`）
- 要改**门禁/契约/结果格式/留痕/脱敏/协议**（两个服务都受影响）→ **本仓**（`pkg/`）
- 要改**某个工具返回什么形状** → 该服务自己的 `idl/<包名>/`（thrift）→ `script/gen-idl.sh` 生成 → 工具产出它
  ⚠️ **契约类型写了没人产出 = 契约不存在**（三个仓各有一道守卫盯着：
  管理面 `biz/jumpserver/model/jmsms/contract_test.go`、
  执行面 `biz/exec/model/jmsexec/contract_test.go`、
  本仓 `model/jms/contract_test.go`）。
  加了新类型就要有工具真的产出它，否则它只是一段注释。
  三道守卫共用一个守卫身（本仓 `pkg/contractscan` 的
  `CheckProduced`）：机械与失败文案一份；各守卫**自己的判据**（扫哪棵树、
  什么不算生产者、枚举算不算声明）留在守卫上，以 `Scope` 传入。守卫身曾经
  是三份拷贝——拷贝已经漂出过「同一句话写了两遍」。
- 两者都要「先查资产列表」→ 管理面查，执行面用查到的名字执行

**共用词汇住在 `model/jms`**（两个服务共用，改它要顾两边）：
- 它装的是**两个面都要说的词**：诊断的结论、列表的信封、工具声明，以及
  **资产**（两个面读的是同一批堡垒机记录、问的是同一个问题，各写一份形状
  就会漂 —— 同一个 agent 在两个 server 上问「有哪些机器」，拿到两种字段，
  那不是两个工具，是一个工具说了两遍）。
- 它有自己的守卫（`model/jms/contract_test.go`，扫**全仓**）：契约类型
  写了没人产出 = 契约不存在。这道守卫上线当天就逮住了一个从一开始就没人
  兑现的 `ToolFailure`（失败分类的真相在 `pkg/errs`，答复在文字里）。
- **契约字段的指针助手也住这里**（`model/jms/opt.go`：`Opt` / `OptBool` /
  `OptInt32` / `OptInt64` / `OptFloat64`）：thriftgo 把可选字段生成裸值，
  「没答」和「答了零值」靠助手撑开。曾经两个模型包各一份拷贝、拼法还不一样
  （`OptInt` 与 `OptInt32`）——一份拷贝会漂，拼法不同更是同名不同义的来路。
  ⚠️ `jmsapi` 的 `FieldStr` / `FieldBool` / `FieldInt32` 是**另一回事**（取
  线上 JSON 字段的可空读取器），别再叫回 `Opt*` —— 同名不同义正是要拆开的。

**发版节奏**（底座是**承诺**，语义化版本，破坏性改动走 major）：
1. 改本仓 ⇒ **先发本仓的 tag**（例如 `v0.2.0`）；
2. 再更新两个服务仓的 `require` 到那个版本；
3. 再发两个服务。
⚠️ **不要在服务仓的 `go.mod` 里写 `replace`** —— 那会让 `go.mod` 与机器绑定，
`go list -m` 报的是路径而不是版本，`require` 里的版本号变成一句空话。
本地联调用 `go.work`（**不入库**，见 `.gitignore`）。

⚠️ ⚠️ **打 tag 之前，main 的 CI 必须已经绿。**
踩过的坑：`v0.3.0` 是在 CI 还红的时候打的 ⇒ 那个 tag 缺一个源码文件
（`.gitignore` 的 `coverage.*` 把同名源码 `coverage.go` 吞了）⇒
`go install github.com/yi-nology/jumpserver-mcp/cmd/jumpserver-mcp@v0.3.0`
**编译失败**，而**没有人收到通知**（tag 推上去不会让人看见 CI 红了）。
⇒ 顺序是：**推 main → 等 CI 绿 → 打 tag → 推 tag**。
⇒ 三个仓的 CI 都配了 `on: push: tags: ['v*']` ⇒ tag 也会跑一遍 CI，
坏掉的 tag 会当场红（**但它已经发出去了** ⇒ 前一条才是真正的防线）。

**跨仓守卫需要三棵树同时在手**（底座的可达性、共用词汇的产出者、能力的措辞）：
- 兄弟仓在哪：环境变量 `JMS_SIBLING_ROOTS`（`:` 分隔）优先，
  否则用同级目录约定 `../jumpserver-mcp` 与 `../jumpserver-mcp-exec`；
- 找不到 ⇒ **跳过**（消息写清楚缺哪棵树、怎么补）；
- ⚠️ **跳过 ≠ 通过** ⇒ CI 设 `JMS_REQUIRE_SIBLINGS=1`，缺树时**失败**而不是跳过。
  机械在 `pkg/arch/siblings.go`。

### 拆仓带来的已知偏差（**比声明的更弱/更强，就写在这儿**）

拆仓不是「原样搬走」，有几条守卫的**覆盖面真的变了**。写下来是为了
「下一个读代码的人」与「下一个审阅的人」**看到同一份事实** —— 藏起来的偏差
才是坏的那种。

| # | 偏差 | 方向 | 事实与证据 |
|---|---|---|---|
| 1 | **契约词汇同名检查**（`CheckContractVocabularyNaming`）**按仓分开查了** | 更弱 | 归档仓扫**全仓**，判「同名包只能有一个」；现在每仓只扫自己 ⇒ 同名包出现在**另一个**仓不会被抓到（同名包会编译冲突，影响很小，但**确实抓不到了**）。三仓各有这道守卫（`internal/arch/{kit,management,execution}_test.go`）。 |
| 2 | **`pkg/arch` 被显式排除在「底座必须被两个服务都用」之外** | **更强** | `pkg/arch/shared.go` 的 `guardMachinery` 列明了它；底座自己的 `_test.go` 不产生可达性边 ⇒ 守卫不会误报自己。这条**不是**偏差，是有意排除。 |
| 3 | ⚠️ **共用词汇的契约守卫比它声称的更弱** | **更弱** | 它守的是「**契约类型写了没人产出 = 契约不存在**」（`model/jms/contract_test.go`）。实测：**底座自己的 `pkg/audit`/`pkg/reg`/`pkg/render`/`pkg/arch` 提到了全部 9 个共享类型** ⇒ 把执行面换成**空仓**（一个工具都没有），这道守卫**仍然绿**。<br>⇒ **它守的不是「服务面产出它」，是「全仓有代码提到它」** —— 共享词汇住在底座，底座自己用它是正常的。<br>⇒ 要判「产出者在服务仓」，得**排除底座自己的引用**再扫 —— 那是**判据**的改动（`Scope` 加一个字段），**不是**本轮该顺手做的事。 |
| 4 | **委派密钥缺失的报错文案变了** | 更啰嗦，无语义变化 | 归档仓：`"no delegation secret configured"`；本仓：额外说出**去哪找**（`JMS_DELEGATION_SECRET` 或哪几个文件、权限 0600）。**这条文案在归档仓的历史里从未存在过** ⇒ 它是一次**独立的行为变化**，不是改名。已写进 [`CHANGELOG.md`](CHANGELOG.md)。 |

⚠️ **写偏差的规矩**：**方向要写准**（更强还是更弱），**证据要能复现**。
「大概弱了一点」这种话，下一个人没法据此判断要不要修。

### 目录约定（CloudWeGo hz）

```
kit/                          # 本仓：库，没有 cmd/
├── pkg/                      # 共用底座
│   ├── jmsapi/               # JumpServer 协议层：传输 + 端点表 + 响应形状 + 边界守卫
│   ├── reg/                  # 工具注册与门禁（唯一注册入口）+ 留痕挂钩
│   ├── render/               # 结果整形 + 输出契约（Schema 派生 + 校验）
│   ├── audit/                # 工具调用留痕（写 / 读 / 体检）
│   ├── redact/               # 凭据脱敏（**唯一一份词表**）
│   ├── risk/                 # 命令风险分类（真 shell AST）
│   ├── errs/                 # 失败分类
│   ├── textx/                # 截断（rune 边界）
│   ├── fspath/               # `~` 展开与路径处理
│   ├── contractscan/         # 契约守卫的机械
│   ├── arch/                 # 架构守卫的机械
│   └── testsupport/          # 测试底座
├── model/jms/                # 共用词汇的生成物
├── idl/jms/                  # 共用词汇的 thrift 定义
├── internal/arch/            # 本仓自己的机械守卫（判据；守卫体在 pkg/arch）
└── script/                   # 三个仓共用的开发工具（见 script/README.md）
```

两个服务仓各自是：

```
cmd/<binary>/        # 入口（package main）：serve / doctor / tools / version
biz/<服务>/          # 那个服务的实现（handler / model / policy / router / service）
conf/<服务>/         # 配置（环境变量 → 结构体）
idl/<包名>/          # 契约的 thrift 定义：入口 <包名>.thrift + 按域拆的多份
internal/<服务>/     # 该服务自己的基础设施：client（管理面）/ koko（执行面）
internal/arch/       # 机械守卫（判据；守卫体在 kit 的 pkg/arch）
script/              # 构建 / 发布 / 生成 / 校验
skills/              # 给 AI 的操作手册
```

hz 的 `router.go` / `router_gen.go` 在这里没有对应物：本仓没有 HTTP 路由，
服务仓的 `biz/<服务>/router` 就是它们的对应物。

**分层的方向是硬的，有守卫盯着**（判据在各自仓的 `internal/arch/`，守卫体在 `pkg/arch`）：
- **共用底座（`pkg/`、`model/`）不得依赖任何一个服务**。
  ⚠️ 这条规则以前写成「基础设施不得依赖业务层」——那是 hz 布局之前的说法，
  在 hz 的布局里 `biz/` **就是一个服务**，不是「另一个服务之上的业务层」。
  服务自己的部分用它自己的契约词汇是天经地义的（koko 直接产出 `SessionStats`，
  三个仓里只有这一份定义，不会漂）。
- **两个服务之间不得互相 import**；`cmd/` 是最外层，谁都不许 import。
- ⚠️ **kit 自己不许长出 `cmd/`**（守卫：`TestTheKitHasNoBinaryDirectory`）：
  kit 一旦长出入口层，它就开始有「谁把它当库用」的问题，而它是个库。
- **IDL 目录名 == 生成包名 == 模型目录名**：`idl/<包名>/` 生成的包必须叫
  `<包名>`，放在叫 `<包名>` 的目录里。三者是同一件东西的三个侧面，
  名字对不上，找契约就得猜。契约按域拆成同目录多份 thrift：入口是
  `<包名>.thrift`（include 各域文件），**每一份**都声明 `namespace go <包名>`
  —— 拆的是文件，不是词汇，生成物仍是一个包、类型名不变（跨文件引用要写
  `域名.类型名`，且 `gen-idl.sh` 必须带 `-r`，否则 include 的文件没有生成物）。

**测试底座在 `pkg/testsupport`**：起一个内存会话、把答案读成 JSON、起名字、
`MustLoad`（配置装载失败即 fail）。三个仓都用它（此前同样的会话搭建抄了
6 遍，抄本会漂）。只有管理面才有的
「打真堡垒机」那套在管理面仓的 `internal/jumpserver/livetest/`。唯一手写会话搭建的
地方是 `pkg/reg/registry_test.go` —— 那是注册表自己的测试，而 testsupport
import 注册表，反过来 import 就是环。

### oekit 模块矩阵的规矩（已落地的那几条）

本仓用了矩阵里的 `pkg`（微工具集）、`concurrency`（并发/重试/限流）、`core`（配置）、
`logx`（日志），以及 `oagentkit/guardx`（门禁）与 `oagentkit/tools`（命令解析）。
矩阵的权威索引是 <https://oekit.github.io/llms.txt>，版本矩阵是
<https://oekit.github.io/versions.json>，每仓根目录的 AGENTS.md 是该仓的硬规则。

遵守的：

1. **禁止裸 `go func()`** —— 用 `concurrency/async`（`GoSafe` / `GoSafeLabeled` /
   `GoSafeWithErr`）。裸 goroutine 里的 panic 会**打掉整个进程**：MCP server 崩了，
   这个会话的两个服务一起没了，审计留痕的写入方也一起没了。
   `pkg/arch` 的守卫扫源码盯着这条。
2. **错误处理用 `pkg/errors`**（类型同一性红线）。**基础设施层**（`pkg/` 与
   `internal/*/`）一律用 `%w` 传链，`errors.Is` / `errors.As` 一路看得穿；
   工具层那 150 多处 `%v` 是**把错误渲染成给 agent 看的文本**（`render.Failf`），
   链在那里本来就该断——不是错误在传播，是错误在变成一句话。
3. **日志用 logx 的 kv 风格**（`logx.Error("…", "key", value)`），不要裸 `log.Printf`。
4. **路径闸门用 `pkg/pathx`**：`SanitizeRelStrict`（严格档，连能抵消的 `..` 也拒）。
5. **不写自研的等价物**：手搓的 `containsString` → `slicex.Contains`，
   本地 `min` → Go 内建。重复的原语会漂移。
6. **SSH 与 CLI 的通用能力已经在 oekit 家族库里了**（改前先看那里）：
   - **SSH**：`github.com/oekit/network/sshx` —— `Dial`（连接/握手**两段界限** +
     调用方总预算 `Budget`）、`LoadSigner`、`DetectKeyType(ctx, path)`、
     `ParsePublicKey`、`PublicKeyType`、`StartKeepAlive`、`KeepAliveRequest`、
     `ErrBusy`。执行面仓的 `internal/exec/koko/` 只留 koko 特有的部分
     （PTY/TUI 驱动、连接令牌、池化）。
   - **CLI**：`github.com/oekit/pkg/cli` —— 子命令分发 + 退出码 0/1/2 +
     **内建 help/version**（问帮助的退出码是 0，不是 2）+ 默认子命令 + 别名 +
     `Table`（列宽自适应）+ `Report`（doctor 式清单渲染）。两个二进制的
     `cmd/*/root.go` 都不再手写 `--help` / `--doctor` 的 workaround。
   ⇒ 要加新的 SSH/CLI 能力时**先问 oekit 有没有**，有就用；没有再在 oekit 里加，
     不要在任何一个仓里写第二份。
7. **依赖地板跟 latest**（矩阵的 `versions.json` 是准）。当前 oekit 依赖
   都在 latest：pkg v0.31.0 / network v0.6.1 / concurrency v0.23.0 / logx v0.8.0 /
   core v0.12.1。

⚠️ 改依赖版本要**手改 go.mod 的 require**（本仓不写 `replace`），
并且 `go mod tidy` 不能跑（它要抓测试专用依赖，沙箱下拿不到）。

---

## 2. 铁律（违反了会白干一轮）

1. **改源码 ≠ 生效。** 必须走完：`./script/build.sh` → `script/publish-mcp.py` →
   `mcp update` → **重启会话**。只改代码就汇报「已完成」是错的。
   ⚠️ **`publish-mcp.py` 不会改 MCP 配置** —— 配置还指着旧的运行时目录，
   于是「真调」调的是**旧二进制**，而你会以为是新代码坏了。
   `mcp get <server>` 看 `command` 字段，确认它指向刚发布的那一版，再真调。
   （⚠️ 本仓是**库**，没有二进制 ⇒ 这条落在两个服务仓上；改本仓时它是
   「先发 tag、再更新两个服务的 require」。）

2. **不要原地覆盖二进制。** 沙箱按路径执行策略，覆盖已存在路径的二进制会被 SIGKILL
   （exit 137、无 stderr）。发布必须进新的时间戳目录 —— `publish-mcp.py` 已经这么做了，
   别自己写 `cp` 覆盖。

3. **构建报 `replacement directory ... does not exist`** ⇒ Go module cache 被清空了。
   跑 `./script/restore-go-modcache.sh`，**不要**去改 go.mod 的 replace 路径。

4. **别跑 `go mod tidy`** —— 它要抓测试专用依赖（x/tools、x/term），沙箱下必失败。
   改依赖版本就手工同步 `go.mod` 里的 `require`。

5. **构建用 `GOPROXY=off`**（脚本已经设了），**且不要带 `-mod=mod`** ——
   只接受 `readonly`/`vendor`，带了会直接报错。
   本机 `proxy.golang.org` 不可达，`goproxy.cn` 可用 —— 但依赖全靠
   module cache 里已解压的副本。

6. **源码树里不要留构建产物。** 产物落在 `./bin/`（服务仓）或
   `~/.local/<...>-runtime/<stamp>/`（发布后）。
   历史上编辑器备份文件（`main.go.1281232157774820236`）、swap 文件（`.!6188!xxx.go`）、
   零字节标记（`*-go-tmp-umask`）把源目录搞得像垃圾场，**已清理，别再产生**。

7. **大改之后要有一双没参与过的眼睛。** 改动 ≥ 300 行，或动了**协议 / 并发 /
   权限身份 / 失败路径 / 存量行为**其中任何一项，就必须起一个**独立 verifier 子代理**
   审一遍，提示词用 [`script/review-prompt.md`](script/review-prompt.md) 里的模板
   （它住在本仓，是因为**三个仓共用这一份** —— 抄三份，漂了的那份就是最少有人看的那份）。
   - **为什么不是「自己再读一遍」**：自己写的代码自己看不出盲区。本仓有过一次
     独立审阅挑出 3 个 HIGH：超时根本不是超时（还会把同机其他会话一起卡死）、
     兜底路径在最需要时失效、计划里的成本数字错 18 倍。**三个都不会自己暴露**。
   - **审阅结论要贴进汇报**：修了哪几条、哪几条判定为不属实。**没贴就等于没审。**
   - ⚠️ **审阅起不来时的退路**：子代理审阅会长时间零输出（两轮实测）⇒
     **别干等**，改成**按审阅清单逐条自己核**（把清单写成问题，逐条对上游源码
     与真机核）。**审阅的价值是「问对问题」，不是「谁来问」** ——
     本仓账号自动化那一轮，自审就核出了一处真缺陷
     （上游 snapshot 没有 `account_amount` 这个键，而**编出来的测试 fixture
     里偏偏有它** ⇒ 实现去读它 ⇒ 测试全绿、真机上永远读到空）。
   - 那份模板里有一份**「已经在哪些地方栽过」**的清单（本仓的伤疤），
     审的人重点看那里 —— 审阅要有效，就得知道往哪儿使劲。

8. **底座改动会波及两个服务** ⇒ **改底座前先发本仓的 tag**，
   再更新两个服务仓的 `require`。⚠️ **不许在服务仓的 `go.mod` 里写 `replace`** ——
   那会让 `go.mod` 与机器绑定，`require` 里的版本号变成一句空话；
   本地联调用**不入库**的 `go.work`。

9. **本仓是库，不是服务。** 它没有 `cmd/`、没有二进制、没有配置。
   ⚠️ 一旦本仓伸手进某个服务（import 它、或把它的私有逻辑搬进来），
   它就不再是共用的，而是那个服务披着共用名字的私有代码。

10. **一个包只能被一个服务够到 ⇒ 它就不该在底座。** 底座是「**两个服务都用的东西**」。
    只有一个够得到的包，是那个服务的私有代码披着共享的名字 —— 而另一个服务迟早会
    伸手进去，于是两者就在**没有人决定过**的情况下耦上了。
    守卫：`pkg/arch` 的 `CheckBaseSharedByBoth`（**跨仓** ⇒ 需要三棵树同时在手）。

---

## 3. 在服务仓里加一个新工具怎么做

以管理面加一个只读查询为例（执行面同理，只是层的位置不一样）：

0. **先想清楚代码该落在哪一层**（这是这一版架构的核心，别跳过）：
   - 工具本身（解码参数、编排调用、拼结果）→ 服务仓的 `biz/<面>/handler/`
   - 领域规则（「这个授权到底能不能让人进去」这类**判断**）→ 服务仓的 `biz/<面>/service/`
     ——写成**纯函数**，不碰网络，这样能离线单测
   - 堡垒机的资源与数据 → 服务仓的 `internal/jumpserver/client/`
   - URL 怎么拼、响应长什么样 → **本仓的 `pkg/jmsapi/`**（**别在别处再写一份**）

1. **在服务仓的 `biz/<面>/handler/` 里写实现。** 按职责选文件（一个域一个文件）。
   管理面 `biz/jumpserver/handler/`：

   | 文件 | 装什么 |
   |---|---|
   | `admin.go` | 资产/账号/权限/用户（管理动作） |
   | `status.go` | 清单读：资产/账号/用户/授权/平台/节点的列表与单条 |
   | `audit.go` | 审计/会话/日志 |
   | `auditview.go` | 单机全貌/结论 |
   | `coverage.go` | 节点继承展开/覆盖范围 |
   | `bulk.go` | 批量/对比 |
   | `gather.go` | 采集/标签/角色 |
   | `extra.go` | 角色/平台/节点等杂项读 |
   | `filter.go` | 命令组/过滤 ACL |
   | `job.go` | 批量作业 |
   | `security.go` | 安全体检 |
   | `scope.go` | 资产树/用户组/终端 |
   | `onboarding.go` | 上线流程/体检 |
   | `evidence.go` | 取证时间线 |
   | `touch.go` | 接触历史 |
   | `transfer.go` | 文件传输留痕 |
   | `delegation.go` | 委派凭据 |

   执行面 `biz/exec/handler/`：`exec.go`（单命令/连通性）、`transfer.go`（文件传输
   /多机/后台）、`inventory.go`（资产清单）、`plan.go`（演练的成本估算）、
   `dryrun.go`+`blocked.go`（演练与拒绝的答复）。

   - 新领域 → **新建 `biz/<面>/handler/<domain>.go`**，别往 `admin.go` 里堆。

2. **用 `reg.Add` 注册，不要用 `mcp.AddTool`。**
   `reg.Add(reg, &mcp.Tool{Name: ..., Description: ...}, func(ctx, req, args) {...})`
   —— `pkg/reg`（在本仓）是**唯一**的注册入口，也是门禁所在。用 `mcp.AddTool` 就绕过了门禁，
   而门禁是「写操作必须 confirm」这条规则的唯一执行者。
   工具的 `description` 是 AI 选工具的唯一依据，**要写「什么时候用这个工具」**，
   不是「这个工具做什么」。反例：`List assets`。正例：
   `List managed assets with address, platform and connectivity. Filter by platform, connectivity or a search string. Use it to find a machine's exact name and address before opening a session on it; the execution plane's jmsx_inventory is the same list seen from the other side.`

   ⚠️ **两个工具容易混时，各自的描述要点名对方**（说清差在哪儿）。
   这一条**没有机械守卫** —— 词面相似度量不出来：`jms_commands_search` 与
   `jms_command_audit` 改写前的相似度只有 0.20（比任何一对正常工具都低），
   可它们读的是同一份数据、差在「带不带输出」「服务端筛还是本地筛」，
   而 agent 只能看描述来分辨。现在两条描述互相点名了。

3. **声明它的输出形状。** 每个工具都要有 `OutputSchema`：
   ```go
   reg.Add(r, &mcp.Tool{
       Name: "jms_xxx",
       Description: "...",
       OutputSchema: render.Schema[render.ListOf[jmsms.XxxSummary]](),  // 或自己的契约类型
   }, ...)
   ```
   服务端会**在返回前按这个 schema 校验**（`render.Text` 把值交回 SDK），
   形状不对就报错，不会悄悄返回一个别的形状。列表类工具统一用
   `render.ListOf[行类型]` 信封（`count`/`total`/`truncated`/`items`/`note`）。
   ⚠️ 少了 `OutputSchema` 的工具会被服务仓的 `biz/<面>/router/policy_test.go` 拦下；
   让列表的行退回自由 map 的，会被管理面的 `biz/jumpserver/router/shape_test.go` 拦下。
   ⚠️ **自由行的出口已经没有了**：`render.List`（行是自由 map）与
   `render.Object`（整个答复是自由 map）都已删除。写不出行类型就是契约没写完。

   ⚠️ **形状已知的工具要直接产出契约类型，不要现拼 map。**
   map 的键名写错编译期不报错（少一个字段要等运行时），而契约类型写错
   编译期就红。**两个面现在都是这么做的**，而且有**第三道守卫**盯着这件事：
   `internal/arch/answer_test.go` 扫源码，发现「`render.Text` 拿到的是手拼
   map」或「列表的行是手拼 map」就红。
   ⚠️ 这道守卫第一次跑就报了 **82 处**：那些答复从契约落地那天起就一直
   是手拼的键，只有 schema 说的是另一回事 —— SDK 分不出这两种答复
   （都是同一个 JSON），所以只有这条规则分得出。
   ⚠️ 契约类型写在 IDL 里，但**工具必须直接产出它** —— 只把 schema 换成
   具名类型、答案还是现拼的 map，键名写错同样只有运行时才发现。
   ⚠️ **两个面都要用的词要放在本仓的 `model/jms`**，不是各写一份：
   执行面的 jmsx_inventory 与管理面的 jms_assets_list 问的是同一个问题，
   现在答的是同一份形状（共用 `jmsapi.AssetSummary` 这个助手）。
   ⚠️ 同一个工具的**跑完了 / 被拦下了 / 演练过**三种答复要用**同一个**契约
   类型，区别只在填了哪些字段 —— 否则「results 在演练时是 `{}`、被拦时是
   `[]`」这种同名字段多种含义会一直漂移。

4. **在服务仓的 `biz/<面>/policy/policy.go` 里给它分类。** 每个工具一条：
   - 只读 → `{Risk: jms.Risk_read}`
   - 写操作 → `{Risk: jms.Risk_write, Confirm: "set confirm=true to ..."}`
   - 不可逆（删除资产/权限）→ `jms.Risk_destructive`，description 里写明「不可逆 + 影响范围」
   - 确认要求随入参变化（只有 DANGEROUS 命令才要确认）→ `{Risk: ..., Conditional: true}`

   ⚠️ **`confirm` 必须是入参里的必填字段**（`json:"confirm"` 不带 `omitempty`）：
   SDK 的 schema 校验会先于门禁拒掉没带 confirm 的调用，报的是
   `required: missing properties: ["confirm"]`。门禁是第二道防线（schema 一旦放松就顶上）。
   ⚠️ **代价：这类调用原本不进留痕**。schema 校验发生在链之前 ⇒ 门禁没跑 ⇒
   留痕里没有这一行（「谁试过写配置但没带确认」这个问题答不了）。
   执行面不受影响（它的 `confirm` 是**可选**字段，条件确认 ⇒ 门禁会拒 ⇒ 有留痕 ✓）。
   ⇒ **已补**：注册表在 SDK 的服务端上挂了一层中间件（`pkg/reg/rejected.go`，在本仓），
   记下「**工具压根没跑到**就被 SDK 拒掉」的调用。
   这一行的形状：**`allowed=false`、`failed=true`、`stages[]` 为空**（门禁没跑过）
   + `error` 是 SDK 的拒绝理由 ⇒ 读的人靠**stages 为空**认出它不是门禁拒的。

5. **写测试。** 服务仓的 `biz/<面>/handler/*_test.go`（工具行为）、
   `biz/<面>/router/policy_test.go`（目录与注册表一致、门禁不可绕过、每个工具都声明了输出形状），
   `pkg/reg/registry_test.go`（门禁机制，在本仓），
   `biz/<面>/model/<包名>/contract_test.go`（**契约类型必须真被产出**）。
   **新工具要有覆盖它的测试**，否则等于没写。

   ⚠️ **写测试的形状只能对着假堡垒机验**：它们会改真数据，不能真调。
   假堡垒机是 `http.HandlerFunc`，按 `r.URL.Path` 分支
   （见管理面 `biz/jumpserver/handler/contract_test.go` 的
   `fakeBastionForWrites`）。对着它调一遍，schema 校验才会真的跑一遍 ——
   `jms_permission_grant` 的形状不符就是这样被抓出来的。

   ⚠️ ⚠️ **假堡垒机的数据要用真机读到的字节，别自己编形状** ——
   **编出来的形状会替实现掩盖缺陷**（本轮实测踩到）：账号自动化的 execution 里，
   上游的 snapshot 给的是 `accounts`（**数组**）+ `node_amount` + `asset_amount`，
   **没有 `account_amount` 这个键** ⇒ 而我编的 fixture 里写了
   `account_amount` ⇒ 实现去读它 ⇒ **测试全绿，真机上永远读到空**。
   ⇒ **fixture 必须照抄真机字节**（真机没有的键，fixture 里也不能有）。
   ⚠️ 这跟「恒真断言」是同一族病：**编造让断言通过的形状**。

   ⚠️ **假堡垒机里必须留「负对照」，否则「过滤失效」测不出来。**
   只有一个资产的假堡垒机，**过滤**与**不过滤**的答案一模一样 ⇒
   「资产过滤被悄悄删掉」照样全绿（实测踩过：变异打掉过滤，测试仍绿）。
   ⇒ 假堡垒机至少要放**两台机器各自的记录**，再断言「另一台的不在答案里」。
   ⚠️ 同理：**limit 截断要有用例**，否则「截断失效」也测不出来。

6. **构建 + 验证**（在**服务仓**里跑）：

   ```bash
   cd <服务仓>
   ./script/build.sh
   python3 script/publish-mcp.py
   # 按 publish 输出的命令 mcp update
   ```

7. **真调一次。** 重启会话后用新工具跑一次真实查询，确认不是「编译过但运行挂」。
   编译通过 ≠ 工具可用。

   ⚠️ **本会话的工具目录是启动时缓存的**，新工具在本会话里调不到
   （`Unknown tool_name`）。想在重启前就真调，用 JSON-RPC 直接驱动已发布的二进制：
   写 `initialize` → `tools/list` → `tools/call`，参考
   `script/verify-mcp-launch.py` 的做法。**只编译过就汇报「已完成」是错的。**

8. **自检。** 两个二进制都有 `--doctor`（不依赖 MCP 会话，退出码 0/1/2，
   沿用 OEKIT `pkg/cli` 的约定；**`--help` 的退出码是 0** —— 问帮助不是错误
   路径）和 `tools`（打印工具目录：名字/风险/确认要求）：
   `jumpserver-mcp --doctor` 查接线 + 堡垒机配置（资产没 protocols / 没账号、
   授权一个账号都没授予），`jumpserver-mcp-exec --doctor` 查密钥类型（**必须 RSA**）+
   端口 + 真实 koko 登录。改完接线先跑它。

9. **改了契约就重新生成模型**：`./script/gen-idl.sh`（thriftgo slim 模板，产物入库）。
   ⚠️ **本仓的共用词汇**（`idl/jms/` → `model/jms/`）也用它生成 ——
   脚本在本仓，生成物也入库。

10. **新工具要过一遍变异扫描**（`script/mutate-audit.py` 是现成的形状）：
    「测试全绿」不等于「测试有判据」——**一个恒真的断言和没有断言是一回事**。
    ⚠️ **扫描脚本自己也要验**：变异**没跑起来**（编译失败）和**变异存活**是两件事，
    而脚本很容易把它们都报成「没被抓住」⇒ **一轮全是「存活」时，先确认 canary
    是不是真的跑起来了**（本节顶部那条纪律）。
    ⚠️ **等价变异不算覆盖漏洞**：改了代码但行为不变的变异，「存活」是正常的 ——
    别为了让扫描好看去改判据。
    ⚠️ **判据恒真是最隐蔽的一种**：拿两边的字符串直接比大小，而两边的**格式不同**
    ⇒ 比较恒成立 ⇒ 用例永远绿。本仓实测踩过：`stamp < "2026/10/29"` 而
    `stamp` 是 `"2026/10/29 11:20:00 +0800"` ⇒ **空格排在数字前 ⇒ 恒真**。
    ⇒ 断言要比**同一格式**的两边，或者比**明确切出来的部分**（日期前 10 字符）。

### 3.1 底座这边要做什么（改本仓时）

上面 1–10 步绝大多数落在**服务仓**。只有下面这些落在**本仓**：

| 你改的东西 | 本仓这边 |
|---|---|
| 协议（URL、认证头、响应形状、版本协商） | `pkg/jmsapi/` —— 改端点只改这一个文件；**别在服务仓里再写一份** |
| 门禁规则、confirm 口径、留痕挂钩 | `pkg/reg/` |
| 输出契约机制、结果整形 | `pkg/render/` |
| 留痕的形状、轮转、读回 | `pkg/audit/` |
| 凭据词表 | `pkg/redact/` —— **只加这一份**，两个服务共用 |
| 命令风险分类 | `pkg/risk/` |
| 失败分类 | `pkg/errs/` |
| 两个面都要说的词 | `idl/jms/` → `model/jms/`（生成物入库） |
| 守卫的判据 | `pkg/arch/` + `pkg/contractscan/` 的**守卫体**（各仓的 `internal/arch/` 只放判据） |

⚠️ **改完本仓，顺序是**：跑本仓的测试 → **发 tag** → 更新两个服务仓的
`require` → 在两个服务仓里跑测试 → 再发两个服务。
⚠️ **别在服务仓的 `go.mod` 里写 `replace`**（见 §2 第 8 条）。

---


## 4. 底座的实现要点（两个服务都要认的那部分）

### 4.1 协议层 `pkg/jmsapi/`（传输 + 端点表 + 响应形状 + 边界守卫）

- **端点表是一份**：`jmsapi.ResPermissions` 这样的常量**就是**堡垒机的 URL。
  工具层只说「我要权限列表」，不说「GET /perms/asset-permissions/」——
  所以改端点只改一个文件，写错路径编译器当场报错，机器上也跑不出 404。
- **两个服务共用同一份 REST 协议实现**（传输、重试、限流、v5 的两种列表形状、**端点表**）。
  协议只有一份，所以在管理面修好的东西（比如按字符边界截断、避免切坏多字节字符）
  执行面自动就有。
- ⚠️ **读嵌套字段一律用 `jmsapi.Str`，不要用 `convert.AnyToStr`**：
  **`convert.AnyToStr(nil)` = `fmt.Sprintf("%v", nil)` = 字符串 `"<nil>"`** ——
  它**不是空串** ⇒ `if x == ""` 这种判空**抓不住它**。
  本轮真实踩到（网络拓扑）：`Asset.zone` 是 null 时，
  `jmsapi.Nested(row,"zone","name")` 返回 nil ⇒ 被当成「区域名叫 `<nil>`」
  ⇒ **每台没归区的机器都被编出了一条假路径**（答复看着完整、其实全错）。
  ⚠️ **同一个坑在「字段名拼错」时也一样**：读不到 ⇒ nil ⇒ `"<nil>"` ⇒
  看起来像有值。⇒ **凡是「嵌套字段可能为 null」的地方都要查这一条**。
- ⚠️ **端点的过滤器不能信：不被声明的参数被静默忽略**（这坑连踩两轮）：
  | 想做的事 | 上游实际认的 | 发错的会怎样 |
  |---|---|---|
  | 按用户过滤 | `user`（**iexact 整个显示串** `Ops User(opsuser)` ⇒ `user=opsuser` 匹配不到） | 发 `username=` ⇒ **参数不存在 ⇒ 静默忽略 ⇒ 过滤没生效** |
  | 按日期过滤 | `date_from` / `date_to`（**严格 `DateTimeField`**） | 发 `date_start__gte=` ⇒ 静默忽略；且**格式不合 ⇒ 解析异常被 `print(e); continue` 吞掉** ⇒ 过滤没生效 |
  | 排序 | **`order`**（`ORDERING_PARAM`） | 发 `ordering=` ⇒ 静默忽略 ⇒ 靠视图默认排序**恰好**同向才没出事 |
  ⇒ **django-filter 不报错**：`BaseFilterSet` 没有 strict ⇒ **一个没被声明的参数就是
  「没有过滤」，不是「过滤了」**。
  ⇒ **结论：过滤一律在本地做**，服务端只用来**缩小窗口**。
  ⚠️ 这条不是洁癖：服务端过滤一旦没生效，答复**看起来完整**（`total` 照样算、`truncated=false`）
  ⇒ 「没传过文件」这个**取证假阴性**就是这么来的。
  ⇒ **本地比较前先把日期归一化**（`normDate`：ISO `2026-10-20` ⇒ `2026/10/20`）：
  记录的时间戳是 `2026/10/28 00:05:33 +0800`，直接拿 `2026-10-20` 去比字符串，
  **`/` 排在 `-` 之后 ⇒ 每一行都通过** ⇒ 返回了请求日期之前的记录。
  ⇒ **读不出来的日期要报错**（`cannot read since=...`），不能当成「没有记录」——
  「没有记录」与「你的日期看不懂」是两件事，答错前者就是假阴性。
- ⚠️ **本地过滤读到的可能只是窗口，不是全部**：端点会**夹住**页大小
  （`MAX_PAGE_SIZE`，默认 1000，部署可配得更小）⇒ 翻页读到的行数少于请求量时，
  「读完了」是**假的** ⇒ `total`/`truncated` 会说谎。
  ⇒ `pkg/jmsapi` 的 `ListAllCounted` 会带回**服务端自己说的总数**
  （`EnvelopeCount` 读信封的 `count`）⇒ 读到的行数少于它时，答复里**必须写明**
  「只读到了最新 N 条，更早的可能存在且不在本答复里」。
- ⚠️ **差异写在「能力」上，不写在「版本」上** —— 这是维护差异的规矩：
  - **差异只有一张清单**：`pkg/jmsapi/capability.go` 的 `capabilityDecls`。
    哪一版**有**哪个能力、这个能力怎么被交出去（`SchemeCalls`）、没有它要付什么代价
    （`Cost`），**全在那一行里**。别的地方不许再写一份。
  - **代码问能力，不问版本**：`api.State(ctx, jmsapi.CapDelegation)`。
    ⚠️ **控制流里不许出现版本号** —— 版本是**操作员填的**（`JUMPSERVER_VERSION`），
    是输入不是问题；问「这个部署能不能委派」才是问题。
    （散文里可以出现版本号：解释给人听时，说「这台是 v4」比说「这台没有委派能力」更好懂。）
    ✅ **这条现在有机械守卫了**（`pkg/arch` 的
    `TestTheVersionDoesNotLeaveTheProtocolLayer`）：`pkg/jmsapi/` 之外的
    **非测试**文件里不许出现 `VersionV4` / `VersionV5` / `versionAuto`。
    ⚠️ 散文里出现版本号**不犯规**（守卫只扫标识符，不扫注释）。
  - ⚠️ **能力是三态的（present / absent / unknown），没有「折叠布尔」**：
    一个 `Has()` 只能把「确实没有」和「没测出来」压成同一个 false，而这两种 false
    对两类调用方**意思相反**（门禁要「没确认就别用」，报告要「确实没有」）⇒
    报告面会把没建立的事实说成事实。
    ⚠️ **真发生过**：探测失败时（能力 = unknown），doctor 的 `delegation` 一行
    **只字不提「没测出来」** —— 它报的是「委派已配置」（配置确实配了），
    把「这个部署到底有没有这个能力」**整个吞掉了**。
    ⇒ 事实问 `State`（三态），决策各问各的：`Present`（已确认有）/ `MayPresent`
    （没确认缺 ⇒ 未知算有）。两个 doctor **必须**按三态措辞。
  - **「部署有没有」与「这里配没配」是两个问题**：能力是部署的（配不出来），
    配置是本机的（能配）。⚠️ 这两问以前合成一个答案，答复就只能说一句含混的话 ——
    现在分开问、各说各的（`State(...)` 与 `DelegationConfigured()`）。
  - **措辞只有一份**：`jmsapi.Reason/Advice/Explain(cap, state)`。
    两个 doctor、三个委派工具、执行面都要说「这里没有更窄的凭据」这件事 ——
    以前各写各的，漂了。⚠️ 事实句与建议句**分开**：事实是事实（「没有这个能力」），
    建议是建议（「用普通 API 凭据」），而且**建议随状态不同**（absent 没法配，
    unknown 差一个设置）。
    ✅ **这条现在也有机械守卫了**（`TestTheCapabilityWordingIsNotRewrittenElsewhere`）：
    `pkg/jmsapi/` 之外的**字符串字面量**不许重述能力的两种状态
    （句子由清单里的 `Name` 拼出来 ⇒ 加新能力自动覆盖）。
    ⚠️ 守卫只扫**字面量**、不扫注释 ⇒ 调用方仍可加自己的补充句。
  - **「版本行」也是一份措辞**：`jmsapi.VersionRowFor(rep, state, policy)` ——
    两个 doctor 的 `version` 一行以前**各写了一遍**同样的三句话，而且已经漂开：
    一个长出了慢路径的补充句，另一个长出了建议列，而**两句都说「按可用处理」**，
    可管理面的委派工具在未知态其实是**拒绝**的 ⇒ doctor 把自己这个面说错了。
    ⇒ 现在判定与句子都在 `pkg/jmsapi`，两个面只贡献**自己的策略**
    （`UnknownPresented` / `UnknownRefused`）⇒ 事实同一句，策略各自说清。
  - **守卫从清单里读**：`pkg/arch` 的守门名单来自
    `jmsapi.CapabilityDeclarations()`，不是自己维护的一份函数名。
    ⚠️ **自己维护的名单会悄悄失效**（改了函数名，守卫就不报了 ⇒ 以为有人守，其实瞎了）。
  - ⇒ **加一个版本差异 = 加一行清单**（外加一条探测）。不是去工具层找版本判断、
    不是去改三处 doctor 的措辞、不是去改守卫的名单。
- ⚠️ **端点表里的路径不能按名字推**：`gather-account-records` 看着该有，
  实际上没有（真机实测 **404**）⇒ **写工具前要真机打一次**（或对上游 `urls.py` 核）。
- ⚠️ **读源码不等于跑真机**：实测推翻过两条源码推断 ——
  ① v4 的列表端点也是**裸数组**（按源码推断成标准信封就错了）；
  ② `perm_account_invalid` 在 v4 上**不是**「账号字段错」，而是
  「**没人被授权用这个资产**」—— 同一句话两个意思，极易误诊。

### 4.2 门禁与注册 `pkg/reg/`

- `pkg/reg` 是**唯一**的注册入口，也是门禁所在（guardx/invoke 链 + permgate 能力判定）。
- `pkg/reg/rejected.go`：SDK 的输入契约校验先于门禁 ⇒ 那一类调用**门禁没跑过**，
  注册表在 SDK 的服务端上挂了一层中间件，把它们记下来（否则「谁试过写配置但没带确认」
  这个问题答不了）。
- ⚠️ 门禁放行 ≠ 命令执行了：危险命令是被**工具层**拒绝的（门禁只知道 capability
  和 confirm 标志，命令是什么只有工具知道）⇒ 留痕的判定以**工具的结论**为准。

### 4.3 工具调用留痕 `pkg/audit/`

两个服务每次工具调用都留一行痕：调了哪个工具、**参数是什么**（注册表已脱敏）、
门禁每一段的判定与理由、放行与否、耗时、出参字节数。

- ⚠️ **执行面尤其需要它**：被门禁拦下的危险命令**根本没到堡垒机**，所以堡垒机
  没有会话可查；没有这行留痕，「谁试图在那台机器上跑 rm -rf、被拦下了」就**两边
  都查不到**。
- ⚠️ **门禁放行 ≠ 命令执行了**。危险命令是被**工具层**拒绝的（门禁只知道 capability
  和 confirm 标志，命令是什么只有工具知道），所以留痕的判定以
  **工具的结论**为准：工具答复里有非空 `blocked` 字段 ⇒ 这行 `allowed=false`。
  识别靠 `pkg/render.OutcomeOf`（反射找 `Blocked` 字符串字段）—— 只认字符串，
  所以 `OffendingIP.blocked`（布尔，IP 是否被拉黑）那种**同名不同义**的字段落不到它。
  ⚠️ 反射找的是 **Go 字段名**（`Blocked`/`DryRun`/`WouldExecute`），不是 JSON 名 ——
  thriftgo 用 IDL 名生成 Go 名，所以**改 IDL 字段名会同时挪走 Go 名**，留痕会静默地
  读不到它。`pkg/arch` 的 `verdict_test.go` 就是钉这层名字的机械守卫。
- ⚠️ **工具层的「失败」也要看得见**。MCP 的错误结果在协议上**仍是成功的一次调用**，
  链看不见失败（`invoke.Result` 没有失败位）—— 所以本仓自己把失败带进留痕
  （`reg.Record.ToolError` → 留痕的 `error` 列）。
  没有它，一次死在半路的命令在留痕里长得跟一次跑成功的**一模一样**。
  ⚠️ 因此 `allowed=true` 的读法是「**没被拒绝**」，不是「跑成功了」。
  ⚠️ **`error` 列装两种错**（门禁拒的、工具失败的），所以「什么坏了」要看
  **`failed` 列**（只表示「工具的活没干成」）—— 门禁拒一次调用**不是坏了**，
  那是门禁在干活；而工具失败的那种，命令**可能已经送到机器上了**。
- ⚠️ **答复不合契约时，失败必须落在链内**。SDK 校验答复形状是在**链收尾之后**
  （`applySchema`），那时留痕已经写完了 ⇒ 一次「答复违反了自己的形状」在留痕里
  会长得跟成功一模一样。所以注册表**自己**先查一遍（每次调用多 ~60µs），
  不合就当作**失败的调用**收口：留痕记下，agent 拿到一个能读的错。
- ⚠️ **「命令有没有真的送到机器上」也要落在留痕里**。失败之后最要紧的一问是
  「它还在那台机器上跑着吗」—— 答不出来就只能重试，而重试一条**可能还在跑**的
  命令，就是把 `rm -rf` 跑第二遍的来路。
  状态由**知道它的那一层**带着走（执行面会话层）：错误实现 `reg.DeliveryAware`，
  基座只声明形状、不知道服务的类型 ⇒ `delivery` 列（`not_sent` / `maybe_sent`，
  **缺 = 没人说**，不是「肯定没送到」）。
  ⚠️ **两条路都要走到**：
  - **错误结果那条路**（`jmsx_exec` 等）：错误带着状态 ⇒ 登记处取出来 ✓。
  - **答复那条路**（`jmsx_run` / `jmsx_collect` / `jmsx_exec_multi` /
    `jmsx_collect_multi` / `jmsx_reachable` 把逐条失败写在答复里）：**答复自己
    带 `error` 与 `delivery`** ⇒ 留痕按约定读（`render.OutcomeOf` 找 `Error`
    与 `Delivery` 两个名字）。
    ⚠️ 走答复那条路的失败**在留痕里曾经长得跟一次干净的成功一模一样** ——
    「活干砸了」那一列没写、`error` 是空的、`delivery=maybe_sent` 恒为空集。
- ⚠️ **工具层要把带类型的错误原样交上去，别拍平**。`render.Failf("%v", err)` 会把
  错误变成一段文字 ⇒ **投递状态就没了** ⇒ 留痕只会说「它失败了」，不会说
  「它可能还在机器上跑着」—— 而那正是**永不重试**的那一格。
  执行面用 `return fail(err)`（执行面仓 `biz/exec/handler/fail.go` ⇒ 把错误原样交上去）✓。
  ⚠️ agent 看到的文字**一个字没变**（登记处把错误原样转成错误结果）✓。
- **动作层结论是上游的原生件**（`guardx/invoke` 的 `Outcome{Refused,DryRun}`）：
  工具层把结论声明进 `invoke.Result.Outcome`，链原样抄进 `invoke.Record.Outcome`，
  留痕从**那一份**读（`Record.Acted()/Refused()/DryRun()`）。
  ⚠️ 本仓**不再留第二份判定表** —— 两份判定表会漂，而漂的那份决定留痕记什么。
  「演练不是拒绝」这条**读法**写在 `pkg/audit`（一处）：上游的 `Refused()` 对
  带 `blocked` 提示的演练也为真，审计要读成「没被拦下，只是没确认」。
- ⚠️ `would_execute`（这次演练若真跑，会不会跑）**上游还没有**（oagentkit/guardx#39），
  这一格暂时由本仓在链外带着（`reg.Record.WouldExecute`）。上游补上后即可收掉。
  ⚠️ 它的语义是「**这次**演练若真跑会不会跑」：差一次确认才动真格的命令，
  演练出来是 `false`（`blocked` 提示同时在答复里，但留痕故意不把演练记成拒绝）——
  别改成「若确认会不会跑」，那是另一个问题。
  ⚠️ **它是 `*bool`，不是 `bool`**：「答复里没这一格」与「这一格是 false」是两件事。
  答复类型没有 `would_execute` 字段时，留痕**不写**这一格 —— 写了 `false` 就是
  在替工具说「这次演练不会跑」，而工具压根没说过这句话。
- 留痕记下**谁**调的（`client` = MCP 客户端 initialize 时自报的名字）：一台机器上
  跑着两个 agent 时，没有它就分不出是谁。⚠️ 它是**自报**的，不是认证过的身份 ——
  当线索用可以，当证据用不行。（日志行里它叫 `client` 而不是 `caller`：logx 自己
  已经有一个 `caller`，那是这行日志的源码位置，同一个 JSON 对象里两个同名的键，
  不同解析器读出来的还不一样。）
- 留痕**落盘**：每进程一份 JSONL（`<JMS_AUDIT_DIR>/audit-<日期>-<pid>-<随机>.jsonl`，0600），
  读回用执行面的 `jmsx_audit_query`（可按服务、工具、客户端、放行与否、时间筛）。
  落盘那一半才是「事后查得到」的那一半 —— stderr 归启动进程的人管。
- ⚠️ **留痕的文件名是契约，不是随手起的**：读回只认 `audit.FileName()` 那个形状
  （轮转出来的 `.1` 也认）⇒ 目录里别的文件（`.bak`、自己的笔记）**不是留痕**；
  读与写**共用 `audit.FileName()` 这一份** ⇒ 改了名字形状，读回会**静默地瞎掉**。
  同理，一行还必须**有时刻、有服务名、有工具名**才算是「一条事实」⇒ 外来 JSON
  对象不会被报成「一次被拦下的调用」。
- ⚠️ **留痕的每一列自由文本都过同一套脱敏**（参数、错误、**拒绝理由**、门禁每一段
  的理由）—— 拒绝理由与错误**出自同一个答复**，一个洗了另一个不洗就是一行里两个
  水位线。脱敏在**留痕这一层**做（`pkg/audit`），不指望调用方已经洗过。
- ⚠️ **上限是硬边界**：留痕文件超过 32MB 要轮转；**轮转失败就停写**（文件里已有的
  行都还在，但不再追加）—— 一个坏掉的文件系统能抬上去的**不是上限**。
  停写会有一条日志，**两个 `--doctor` 的 `audit_trail` 都会报出来**（检查在
  `pkg/audit.CheckTrail`，两个服务各自跑自己那一份 —— 目录是各自配的）。
  轮转用 rename **原子替换**归档代 ⇒ 轮转失败**什么都不毁**。
- ⚠️ **两侧对同一个空值必须说同一句话**：写侧说「没有目录 = 留痕关闭」，读侧就得
  说「没有留痕文件」。⚠️ 读侧曾经把空目录当成「去**当前工作目录**找」⇒ 工作目录里
  任何**名字**像留痕的文件都会被当成本机的事实 —— 名字是形状，不是来路。
- ⚠️ **写了一半的行要封成一行**：写失败留下的半行没有换行 ⇒ 下一行会粘上去 ⇒
  **一次失败丢两行，而且没人知道**。写侧补一个换行把它封住。
- ⚠️ **答复不能假装自己看全了**：读不了的行（太长 / 写坏了）要**计数**，而且只数
  「**可能与你要的有关的**」那些 —— 把别的工具的坏行算进来，agent 会以为「有一条
  我关心的拒绝记录读不出来」⇒ 去重跑一遍。
- ⚠️ **上限的「值」也要钉住**：文档写「各 4KB」，测试就不能从常量算出期望值 ——
  那样把 4096 改成 65536 测试照样绿，代码与文档**无声漂移**。

---


### 4.4 凭据脱敏 `pkg/redact/`

⚠️ **脱敏用组合版（`redact.Scrub`），它整体是幂等的**：形态规则那一半
**不幂等**（它吃掉被遮蔽值的闭引号，第二遍连分隔符一起吃）⇒ **单用形态规则
洗两次会毁掉更多**；但「形态规则 + 凭据键兜底」的**组合**是幂等的 ⇒
注册表可以洗一次、留痕再洗一次（两个出口读同一个值 ⇒ 逐字节相同）。
⚠️ 兜底按**键名**判，**不依赖**形态规则的形态 ⇒ 上游改了也不会悄悄开洞。
⚠️ ⚠️ 但键名要以凭据词**结尾**（`my_password`/`mytoken` 都算）⇒
**不要**当子串匹配（那会把 `monkey`/`keyword`/`session`/`key_id` 当凭据
抹掉 —— 本仓真实命中过）⇒ 词表里因此**不许**有 `key` 这种词。
⚠️ ⚠️ 键名规则必须是**上游键文法的超集**：上游的键文法前缀任意
（`mytoken`/`dbpassword` 对它是凭据），而它遮蔽时会吃掉键的闭引号 ⇒
**只有兜底能把它补回去** ⇒ 兜底不认 ⇒ 结构坏着 ⇒ 第二遍再吃一个字符 ⇒
**两个出口不再逐字节相同**（注册表那份与留痕那份分岔）。
⚠️ 这条保证覆盖**三种形态**，键名都要在兜底词表里：**引号键值对**
（`{"password":"x"}`）、**转义 JSON 里**的键值对（`{"params":"{\\"password\\":\\"x\\"}"}`）、
**散文里**的 `KEY=value` **或 `KEY: value`**（`export PASSWORD=x`、
日志行里的 `login failed: password: x`）。
⚠️ **散文形态必须在边界之内**：上游的形态规则对**引号内带 `&`** 的值
**一条规则都不匹配**（值形态停在 `&` 又坚持要闭引号 ⇒ 整条规则失配）⇒
`export PASSWORD='p&ssw0rd'` 会**整条明文**落盘 —— 不是尾巴，是全部。
⚠️ ⚠️ **散文规则要跑两遍**：**前面**一遍（形态规则之前）——形态规则会把它们
遮蔽的东西**改形**（值形态 `[^\s&'"]+` 把**反斜杠**当成值吃掉 ⇒
`{"command":"export PASSWORD=\\"SECRET\\""}` 里剩下 `"SECRET\\""` 站在明文里）
⇒ 上游**根本不该看见**那个凭据；**后面**一遍（形态规则之后）——形态规则只遮到
第一个 `&`（`password=****&TAIL`）⇒ 后面那段**没人收** ⇒ 它是收尾的那一道。
⚠️ ⚠️ **只跑前面那一遍是不够的**：散文规则原本跑在**最后**（它是收尾的那道），
把它挪到最前就丢了收尾的职责 ⇒ 冒号形态的凭据尾巴回到留痕里，**而且不再幂等**
⇒ 两个出口分岔 ⇒ 「注册表那份与留痕那份逐字节相同」这条不变量破了。
⚠️ 散文形态遮蔽后要与上游**同形**（`KEY=****`）⇒ 组合才幂等。
⚠️ `&` 到底是「分隔」还是「凭据的一部分」，靠**它前面有没有 `?`**来分：
`?token=abc&user=bob`（查询串 ⇒ `&` 是分隔 ⇒ 后面的参数要留着）、
`PASSWORD=AAA&bbb=1`（一个凭据 ⇒ `&` 是它的一部分 ⇒ 整条遮蔽）、
`export PASSWORD=x&./run.sh`（shell 运算符 ⇒ 留着）。⇒ **判不出来时往安全的一边**
（整条遮蔽）⇒ 尾巴留在明文里就是凭据留在明文里。
⚠️ ⚠️ **那个 `?` 必须是「同一个查询串」的那个**：只看「整段文本里有没有 `?`」
⇒ 前一句里的一个问号就替这条 `&` 开了口子（`did it work? PASSWORD=AAA&bbb=1`
⇒ 尾巴明文进留痕）⇒ 判据是「**最近的** `?` 到匹配点之间不得有空白或引号」
（URL 里没有空白；引号结束 URL 所在的参数）⇒ 判不出来时**整条遮蔽**。
⚠️ **递归要把上下文带进去**：尾巴（`&` 后面那段）要再扫一遍，而那一遍必须
用**同一份**上下文判断同一个 `&` ⇒ 否则两遍给出相反的答案 ⇒ 查询串的参数
会被吃掉（`?token=…&password=…&q=1` ⇒ `q=1` 消失）。
⚠️ **仍在边界之外**的：`the password was x` 这种**没有 `=`/`:`** 的散文、
`mysql -p'x'` 这种**没有键名**的命令行参数 ⇒ **别把凭据放进散文或命令行**。
⚠️ **布尔标志不是凭据**（`{"has_password":true}`）⇒ 不抹（抹了就把事实
变成了字符串）；**数字是凭据**（`{"password":123}`）⇒ 抹；**`null` 是事实**
（`{"password":null}` ⇒ 「没有密码」）⇒ 同样不抹，但它**必须被摘出去**（见下）。
⚠️ 兜底**只作用在字段名像凭据**的 ⇒ **命令照旧保留**（命令的其余部分照旧）。
⚠️ **脱敏后文档多半还得是文档**：输入是 JSON ⇒ 输出**通常**也是 JSON。
⚠️ 上游的形态规则把键的引号**连同值**一起吃掉（`"password":123` ⇒
`"password=****`），无引号的值还会把对象的闭括号一起吃掉 ⇒ 坏掉的 JSON ⇒
**载荷缩减**（base64 私钥）做不成、**读 args 列的人**也拿不到数据。
⇒ 所以**凭据字段整字段摘出、之后放回**：无引号的值（数字/布尔/**`null`**）、
**非标量**（数组/对象）、散文形态，都是这样。
⚠️ 非标量必须**整字段**摘出：形态规则只遮住它的一个碎片 ⇒ 碎片后面
那个**名字不带凭据词**的字段（`{"secret":{"value":"s3cr3t"}}`）里的
凭据就明文留在留痕里。
⚠️ `null` 也必须摘出去：形态规则把它连同后面的 `,`/`}` 一起吃掉 ⇒
**下一个字段整个消失**（`{"password":null,"user":"bob"}` ⇒ `user` 没了）⇒
JSON 当场坏掉、留痕丢掉一条事实。⚠️ 它摘出去之后**原样放回**（`null` 是
「没有密码」这个事实，不是凭据）。
⚠️ **兜底的无引号值形态**（数字/布尔）**不许吃引号**：否则它会顺路吃掉**下一个字段**
（形态规则吃掉键的闭引号之后，兜底从那里一路读到下一个字段的引号）。
⚠️ ⚠️ **值形态不许跨字段**：转义形态的值 `\\"(?:[^"\\]|\\.)*\\"` 里 `\\.` 能匹配
下一个字段开头的 `\\"` ⇒ **一次匹配吞掉两个字段** ⇒ 而回调在「第一个键不是
凭据词」时把整段**原样放过** ⇒ **第二个字段的凭据跟着逃了**
（真留痕里见过：`{\\"username\\":\\"admin\\",\\"password\\":\\"…\\"}`）⇒ 值形态里的
转义**不许跨过下一个字段的开头**（`\\.` ⇒ `\\[^"]`）。
⚠️ ⚠️ **写测试要用留痕里的真实字节**：SDK 序列化之后的形态比「看起来像」的
形态**多一层转义** ⇒ 人手写的用例可能压根没碰到真实形态 ⇒ **真调（读一次
留痕）比单测更容易发现这类问题**。
⚠️ 词边界必须**零宽**（`\b`）：吃掉后继字符的边界会把分隔逗号一起吃掉 ⇒
同一对象里的第二个无引号凭据没有前缀可用 ⇒ 它不被摘出 ⇒ 它的 `}` 被吃掉。
⇒ 「第二个字段」这种毛病**看起来像一个字段的毛病**：第一个字段被摘出去了，
第二个没有 ⇒ 只有一个字段的输入全绿。
⚠️ **例外（上游的设计，本仓改不了）**：上游的 `authorization` 头规则
**吃到行尾** ⇒ 一行里只要有 `Authorization:`，**这行剩下的部分全没了**
（凭据是抹掉了，URL 什么的也没了）⇒ 那一行也不再是 JSON。

### 4.5 两条路径的脱敏是「同一件事的两半」

**词表是同一份**（`pkg/redact.IsCredentialKey`）⇒ 同一个词在两条路径上要么都认、
要么都不认；**形状各走各的**（答复保留键名与 scheme：`Authorization: Bearer [REDACTED]`、
`{"password":"[REDACTED]"}`；留痕塌成 `****`）。
⚠️ **形状不同不是漂，词表不同才是漂**：这一条曾经漂过 —— 答复路径自己带
一份词表，与留痕那份差 **14 条**（`passphrase`/`credential`/`cookie`/
`kubeconfig`/`id_token`/`refresh_token`/…），而且**完全不认 JSON 形态**
⇒ `{"password":"x"}` 原样进 agent 的上下文窗口（实测 12/12 全漏）。
⇒ 现在**只有词表**在底座（`IsCredentialKey`），**形状留在各自的服务里**
（答复的形状归管理面仓的 `biz/jumpserver/handler/redact.go`）⇒ 底座不长出只有
一个服务用的函数（`pkg/arch` 的 `TestTheSharedBaseIsSharedByBoth`
按**包**查这件事：只被一个服务**到达**的底座包就是那个服务的私有代码）。
⚠️ **要加词就加 `pkg/redact` 那一份** —— 别往答复路径里另加一条词表：
那会让同一个词在两条路径上**一个抹一个不抹**。
⚠️ 答复路径**散文形态**的键也走同一份词表（`passphrase=hunter2` 以前明文）。
⚠️ ⚠️ ⚠️ **散文规则的「键」必须由共享词表构造**（`redact.CredentialWordPattern()`），
**不能「匹配任意键再判断」**：后者会让匹配**吃掉凭据前面的那个词**
（`login failed: password: x` ⇒ 键成了 `login`）⇒ **凭据自己拿不到一次匹配**
⇒ 它原样进 agent 的上下文窗口（这是引入的回归：旧版「词表写在正则里」的
反而遮得住）⇒ 模式要从凭据开始。
⚠️ 附带：**命令行参数与通用规则不能都抹**（`--password=x`）⇒ 否则文本带**两个**
标记，且每跑一遍多一个 ⇒ **不幂等**。
⚠️ 答复路径**非标量**的值要**整字段**抹（`{"secret":{"value":"x"}}` ⇒ 整块
抹掉）—— 只抹片段会**留下内层的凭据**并把 JSON 改坏。
⚠️ `Authorization` 的 **scheme 要留下**（`Bearer`/`Basic`）—— 通用
`key=value` 规则会把 scheme 当成值抹掉，记录里就不再说得清「怎么认证的」。
⚠️ 认证头的凭据是**它的参数**，不是**行尾**（上游那条规则吃到行尾 ⇒ 记录里
的 URL 一起没了 ⇒ 读者丢了「跑了什么」）⇒ `curl -H "Authorization: Bearer x"
https://h/api` 里 URL 要留着；而 Digest 的**每一个参数**（`response=…`）都是
凭据的一部分 ⇒ 只抹第一个词不够。
⚠️ **两条路径的「分隔符」要一致**：`--password secret`（**空格**分隔）
答复路径抹、留痕路径不抹 ⇒ 同一个词、同一个形状，两条路径强弱相反 ⇒
分隔符要认 `=`、`:` **和空白**。
⚠️ **URL 里的凭据**（`https://user:pass@host`）**没有键名** ⇒ 按键名的规则
抓不到它 ⇒ 它要自己一条规则；且密码要吃到**最后一个** `@`（密码里可能有
`@` 自己）⇒ 停在第一个就把尾巴漏了。
⚠️ **查询串参数的值可能带引号**（`?token="a b"`）⇒ 值形态要认引号，
否则引号会留在掩码旁边，值**一半**在明文里。
⚠️ **查询串里的凭据参数**（`?token=abc`）散文规则**看不见**：URL 的
`scheme:value` 形状会**先**被匹配 ⇒ 规则认定「https 不是凭据」⇒
**整条 URL 被放过** ⇒ 参数里的 token 活着 ⇒ 查询串参数要自己一条规则
（且**别的参数要留着** —— 记录要说得清「跑了什么」）。
⚠️ **非凭据键的值也要往里看**：「description=token=abc」里的键不是凭据，
但**值里是** ⇒ 键不认时不能把整段（连值）原样放过 ⇒ 值要再扫一遍。
⚠️ **匹配括号要跟踪字符串**：「{"note":"a}b"}」里的 `}` 不是对象的结尾 ⇒
数到它就收尾 ⇒ 内层的凭据留在明文**且文档被改坏**。
⚠️ **转义的散文形态**（`{"cmd":"export PASSWORD=\\"SECRET\\""}`）也要认 ——
值形态停在反斜杠 ⇒ 凭据站在它后面。

### 4.6 输出契约与结果整形 `pkg/render/`

- `render.Schema[T]()` 从 Go 类型派生 JSON Schema；SDK 在**把答案交回去之前**
  按它校验，形状不对直接报错。所以契约不是文档，是**会被执行**的承诺。
- `relax()` 给**结构体**放行额外字段（工具常带 IDL 之外的上下文），但**不能碰
  map 的 `additionalProperties`** —— 那正是 map 的**值的 schema**，放行等于把值的
  类型校验关掉（曾经写错过：map 字段的值类型根本没被校验，形状错了也没人拦）。
- `render.OutcomeOf`：反射找答复里的 `Blocked`/`Error`/`Delivery`/`DryRun`/
  `WouldExecute` 字段 ⇒ 留痕靠它读工具的结论（见 §4.3）。
- ⚠️ **自由行的出口已经没有了**：`render.List`（行是自由 map）与
  `render.Object`（整个答复是自由 map）都已删除。写不出行类型就是契约没写完。

### 4.7 契约守卫的机械 `pkg/contractscan/`

三道守卫（底座 + 两个服务）共用一个守卫身（`CheckProduced`）：机械与失败文案一份；
各守卫**自己的判据**（扫哪棵树、什么不算生产者、枚举算不算声明）留在守卫上，
以 `Scope` 传入。守卫身曾经是三份拷贝——拷贝已经漂出过「同一句话写了两遍」。

### 4.8 变异脚本（守卫的自证）

⚠️ **变异脚本自己得会喊**：overlay 不生效时（在 `/tmp` 这类符号链接路径下就是
不生效）每条变异都在**未变异的代码**上跑 ⇒ 扫描报「守卫全是假的」而真相是
「扫描什么都没做」。⇒ 脚本先跑一条 **canary**（必须变红），不红就中止。
- `script/mutate-audit.py` —— 审计与脱敏那一片的守卫。
- `script/mutate-version-guard.py` —— **委派凭据的门禁**与**两条结构断言**
  （7 条变异：漏门禁 / 包限定伪装 / 错状态门禁 / 藏在 `&&` 里的反门禁 /
  守卫不认三态门禁 / 版本号溜进工具层 / 措辞在别处重写）。
- `script/mutate-identity-guard.py`（在**管理面仓**）—— **身份/status/ACL/RBAC 那一轮**的守卫
  （6 条变异：不可达时捏造「凭据已被接受」/ doctor 失败分支捏造零值身份 /
  清空门退回 `!= ""` / 空 username 当成功 / 同名角色跨 scope 被合并 / 401 当
  `auth_ok=true`）。⚠️ 它用 **overlay**，所以 **`-overlay` 必须写在子命令之后**
  （`go test -overlay=f.json ...`）：写成 `go -overlay f.json test ...` 会被 go 工具
  回「flag provided but not defined」—— **退出码非零，但与「变异被抓」完全无法区分**
  ⇒ 每条变异都会判成「canary 没炸」。这坑本轮真踩过一次（6/6 全误判）。
- ⚠️ **`mutate-audit.py` 与 `mutate-version-guard.py` 这两条用的注入方式不一样，而且是有原因的**：
  版本守卫**在运行时扫源码树**（`go/parser` 读全仓的 .go 文件自己判断）⇒
  **overlay 只影响编译器、看不见运行时的读盘** ⇒ 用 overlay 注入的源码树变异
  **根本不会落地** ⇒ 每条都会「仍绿」⇒ 报告会说
  「守卫全是假的」而真相是「它压根没扫到变异」。⇒ 所以它改成**整仓副本**：
  把工作树复制到 `/tmp`，在副本里改、在副本里跑，**真仓一个字节都不碰**
  （脚本末尾逐字节核对这一点）。
- 实现只有一份（两个面共用），有守卫盯着两个入口都接上了它。

---

## 5. 验证要求（交付前必须过）

| 检查 | 怎么过 |
|---|---|
| 编译 | `go build ./...` 无错（服务仓是 `./script/build.sh`） |
| 单元测试 | `go test ./...` 必须全绿 |
| 格式化 | `gofmt -l .` 无输出 |
| 静态检查 | `go vet ./...` 无错 |
| 工具数 | 管理面 **97**（`biz/jumpserver/router/policy_test.go` 钉住这个数）/ 执行面 **15**（无 REST 凭据时 **14** —— `biz/exec/policy/policy_test.go` 钉住的是**名字集合**，`jmsx_inventory` 只在有 API client 时注册 ⇒ 集合里没有它） |
| 目录一致 | 策略表与注册表必须一一对应（`policy_test.go` 会查） |
| 契约 | 契约类型必须真被产出（三道 `contract_test.go`）；**答案本身必须是契约类型**（`internal/arch/answer_test.go`：不许手拼 map 的答案或行）；两个服务都不许退回自由 map（`render.Object` / `render.List` 已删除） |
| 分层 | 共用底座不得依赖任何服务；两个服务不得互相 import；IDL/包/模型三名对齐（`pkg/arch` + 各仓的 `internal/arch/`） |
| **跨仓守卫** | 本仓有三条守卫**要三棵树同时在手**（底座的可达性、共用词汇的产出者、能力的措辞）⇒ 本地要把三个仓并排放着；CI 用 `JMS_REQUIRE_SIBLINGS=1` ⇒ **缺兄弟仓即失败** |
| 自检 | `jumpserver-mcp --doctor` 与 `jumpserver-mcp-exec --doctor` 退出码 0 |
| 真调 | 重启会话后实际调一次新工具；**重启前**可用 JSON-RPC 直接驱动已发布二进制 |

**别把「编译过」说成「已完成」。** 汇报时给出：编译结果、测试结果、工具数变化、发布路径、
自检结果、以及「需要重启会话才生效」这句话。

⚠️ **改了输出形状一定要真调一次**（读工具对真堡垒机，写工具对假堡垒机）。
schema 校验只在答案被返回时才跑，所以「编译过 + 单元测试绿」**不等于**
形状对 —— `jms_permission_grant` 的契约与答案不符，是真调时才发现的。

⚠️ **本仓改了 ⇒ 还要验证两个服务仓**：底座的 API 变了，两个服务都要跟着改
require 并跑一遍它们的测试。**只跑本仓的测试不算交付。**

---

## 6. 沙箱速查

| 现象 | 原因 | 修法 |
|---|---|---|
| exit 137、无 stderr | 覆盖写二进制，路径被执行策略拒了 | 发布到新时间戳目录 |
| `replacement directory ... does not exist` | Go module cache 被清 | `./script/restore-go-modcache.sh` |
| 依赖解析要去下载（`go: downloading ...`） | module cache 里少了那个模块，缓存被清过 | 跑 `./script/restore-go-modcache.sh`（守卫盯着清单与 go.mod 一致） |
| `missing go.sum entry for module ...` | go.sum 少了那个精确版本的条目 | `GOFLAGS=-mod=mod GOSUMDB=off GOPROXY=off go build ./...`（Go 会从本地缓存补上） |
| `go mod tidy` 失败 | 要抓测试专用依赖（x/tools、x/term），沙箱下拿不到 | 别 tidy，手改 go.mod 的 require |
| `-mod may only be set to readonly or vendor` | 模块模式只接受 readonly/vendor | 去掉这个 flag（构建脚本已去掉） |
| `writing go.mod cache: rename ... not permitted` | 沙箱拦了 module cache 写入 | `GOPROXY=off` + `replace` |
| 源码树里冒出 `.go.1234567890` 之类文件 | 编辑器/工具留下的备份 | 清理掉，别提交 |
| **底座改了编译不过** | 服务仓的 `require` 指向的 kit 版本还没发 | 先发本仓的 tag，再更新两个服务的 require |

---

## 7. 提交约定

本仓是 git 仓（仓库根目录）。

- 提交前确认 `git status` 里**没有**构建产物、备份文件、二进制。
  ⚠️ **`git status` 是提交前的最后一道自查**，不是可选项：
  `.gitignore` 的一个 `coverage.*` 就把源码文件 `biz/jumpserver/handler/coverage.go`
  吞掉过 ⇒ 文件在磁盘上、在工作区里，但**不在提交里** ⇒ 发布出去的 tag 编译不过。
  ⇒ 提交前跑一次 `git status --short`，确认**每个要改的文件都出现在列表里**；
  尤其新建的源码文件，要 `git add` 之后**再看一眼列表**（`git add` 之前它不在列表里）。
- 提交信息用中文，说明**改了什么行为**（不是「更新代码」）。
- 不要提交 `~/.minimax/mcp.json` 里的 token —— 那是仓外的运行时配置。
- ⚠️ **`go.work` / `go.work.sum` 不入库**（见 `.gitignore`）：它是本机的联调接线。
- **底座的改动单独成一个提交**，写清它是**破坏性**还是**兼容的** ——
  两个服务仓要跟着改 require，提交信息里写清「服务侧要做什么」。

---

## 8. 相关文档

| 文档 | 内容 |
|---|---|
| [`README.md`](README.md) | **对外入口**：定位、里面有什么、怎么用 |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | **三仓的边界与依赖方向**：谁 require 谁、为什么底座不认服务、改底座的发版节奏、跨仓守卫要三棵树 |
| [`script/README.md`](script/README.md) | 三个仓共用的开发工具、多仓工作集、变异脚本的 canary |
| [`script/review-prompt.md`](script/review-prompt.md) | **独立审阅的提示词模板** + 本仓的「伤疤清单」（大改之后用它起一个没参与过的眼睛） |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 怎么参与：跑测试、加工具的规矩、提交约定、**改底座前先发 tag** |
| [`SECURITY.md`](SECURITY.md) | 漏洞报告渠道、凭据处理纪律 |
| [`model/jms/`](model/jms/) | 共用词汇的生成物（诊断结论 / 列表信封 / 工具声明 / 资产） |
| [`idl/jms/`](idl/jms/) | 共用词汇的 thrift 定义 |
| [`pkg/`](pkg/) | 共用底座：jmsapi / reg / render / errs / redact / risk / textx / fspath / contractscan / arch / testsupport / audit |

**管理面细节**看 [`yi-nology/jumpserver-mcp`](https://github.com/yi-nology/jumpserver-mcp)，
**执行面细节**看 [`yi-nology/jumpserver-mcp-exec`](https://github.com/yi-nology/jumpserver-mcp-exec)。

**AI 访问机器一律经堡垒机 koko(2222)**，不接受直连 SSH —— 直连会丢审计录像。

