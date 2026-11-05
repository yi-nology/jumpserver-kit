# 变更记录

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
本项目遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### 变更

### 新增

### 修复

## [0.8.0] - 2026-11-05

### 变更

- **契约命名守卫认两种 IDL 布局**：单词汇仓摊平在 `idl/`（包名由全目录一致的
  `namespace go` 命名，入口 `<包名>.thrift`）；多词汇仓保持 `idl/<包名>/`
  （目录名命名包）。历史漂移形态（目录与命名空间不一致）在两种布局下仍被抓。
- 守卫首次有了**仓内夹具测试**（`pkg/arch/naming_test.go`，7 场景）与
  **变异脚本**（`script/mutate-naming-guard.py`：6/6 变异被杀，canary 钉
  overlay 生效，「thrift 语法不查」登记为边界）。

## [0.7.0] - 2026-11-05

### 修复

- **risk：包装/隐藏的破坏性命令全部逃不过确认门禁**（Critical）：`sudo -n rm -rf /x`、
  `nohup/timeout/env/xargs` 包裹的 rm、管道后半的 `true | rm -rf /x`、`$(...)`/反引号里的
  rm、`eval "rm -rf /x"` 此前全被判成 MODIFY——确认门禁一声不吭。根因：bashguard 的
  Invocations 只带最外层调用。判定层改走完整 shell AST（mvdan/sh，已是依赖）：
  每个 simple command 经 wrapper 剥壳（含值旗标消耗）递归判定，shell -c / eval 递归分类。
  20 个新用例钉住；日常命令探针零误伤。
- **jmsapi：翻页中途失败不再静默截断**：listAll/listAllCounted 在第 N 页失败时曾
  break 后返回残页+nil error（「全量」是假的）；现在带 offset 的错误原样上报。
- **jmsapi：assetRows 改翻页**：资产解析原先单发一页（page_size=500），开启分页的部署上
  窗口外资产被报成「不存在」；走 ListAllQuery 全量翻页。
- **jmsapi：matchAssets 的 `<nil>` 字面量**：缺失字段曾以 `fmt.Sprint(nil)` =
  `"<nil>"` 进答案（platform 最典型）；改用 Str()。
- **jmsapi：ReportVersion 不再丢配置版本解析错**：configured 分支现在先取 profileError。
- **reg：OutputSchema 解析失败在启动即 panic**：原先 `resolved=nil` 但仍标 declared，
  「已声明却从未校验」；Add 是启动期入口，与重名注册同一处理。
- **jmsapi 新增 GetBinary**：非 JSON 体（回放归档、HTML 报告）走与 JSON 调用相同的
  凭据（Token/自动刷新 Bearer）、限流与 401 重读——修掉两个调用方手拼
  `Authorization: Token `（登录凭据下是空 key，v4 必 401 且被读成 tar 的 "unexpected EOF"）。
- render.FillVerdict 的字段查找复用 outcome.go 的防 panic fieldByName（原裸 FieldByName
  在 nil 嵌入指针提升时会 panic）。

### 变更

- **jmsapi 新增 ListCounted（网关形状）**：ListAllCounted 的资源形版本；工具层的
  9 处裸路径调用改走它。rawCalls 守卫表补上 ListAllCounted 后立刻抓到这些存量违规
  （守卫之前对它是瞎的）。
- redact：散文空白分隔符的已知过遮面（"the password was x" → 遮蔽 x）钉了测试并写明取舍。

### 依赖

- mvdan.cc/sh/v3 由间接抬为直接（risk 的 AST 判定层使用）。
 - 2026-11-05

### 新增

- **`pkg/confload` —— 两服务共用的配置装载底座**：三段式读档（env → 默认 → 校验，每段
  报自己的错）、HTTP/RPC 两张脸的「地址不带 token 即拒绝」纪律、登录密码与 OTP 的
  文件回退读档。两服务仓的 `Load()` 此前各持一份逐字相同的拷贝，收编成一份。
- **`audit.EffectiveLimit`**：`Read` 实际生效的 limit 的唯一出处，执行面的
  `jmsx_audit_query` 在 note 里复述生效值时不再自持一份钳制副本。
  ⚠️ 与 `render.NormLimit` 语义不同（超上限一个钳到 max、一个回落 def），勿混用。
- **`render.FillRehearsal` / `render.FillRefusal` / `render.RehearsalNote`**：判定词汇
  （risk/dry_run/would_execute/executed/blocked/note）的反射式**写**侧，与
  `render.OutcomeOf` 的读侧同一套 Go 字段名。两面的演练/被拒答复从此一个写法，
  契约类型保持 thrift 生成物、不挂方法。

### 移除

- `arch.ASTFiles` / `jmsapi.ToMap` / `redact.Secrets`：三仓交叉验证零引用的死导出。
  （对 0.x 的消费者构成 API 移除；无人引用，语义上兼容。）

## [0.5.0] - 2026-11-05

### 新增

- **`pkg/rpcapi` —— 注册表的第三张脸（kitex）**：`New` 同步 bind（端口冲突当场失败），
  `RunBackground`（stdio ride）与 `Svr()`（组合根 `oekit/kitex.RunServer`）双生命周期
  入口；token 逐调用、每方法、常量时间校验，**无匿名访问**（Catalogue 同验）；Invoke
  走 `reg.CallTool` 同一扇门——门禁拒绝 / unknown tool / 入参不合 schema 是
  **is_error 答案**，token 错是**传输错误**（与 REST 401 同位，无留痕行）；caller=`rpc`
  （自报姓名经 `/` 附加）；text=`render.ResultText` 唯一定义；目录行= `reg.Catalogue()`
  唯一装配。
- **`pkg/faces` —— 唯一生命周期主人**：serve 子命令变成数据（`''`/`http`/`rpc`/`all`）。
  `plan()` 纯函数钉住 dispatch 矩阵；stdio 模式保持现网形状 + RPC ride（bind 失败按
  启动失败处理，不留静默降级）；常驻模式组合在 `oekit/bootstrap` 上（信号、逐资源
  关闭预算），kitex 面交 `oekit/kitex.RunServer`；调用方 ctx 可干净停机。
  `httpapi.Run/serveUntilSignal` **搬**入 faces（不是拷贝）；`httpapi` 保留
  `Start/ServeOptions/Handler/OpenAPI`。
- **RPC 契约**：`idl/jmsrpc/jmsrpc.thrift`（`ToolCall{tool,args,token,caller}` →
  `InvokeResult{is_error,text,structured}` + `Catalogue(token)`——无匿名目录）→
  `kitex_gen/jmsrpc`（kitex 工具生成，**入库**，`script/gen-rpc.sh`）。工具契约唯一源
  仍是 MCP schema，RPC 面不出现第三份入参形状。
- **守卫与变异**：`script/mutate-rpc-face.py` **6 条变异全红**（rpc: token 校验旁路 /
  unknown 放行 / text 脱离唯一定义；faces: all 无面仍服务 / 提示丢 JMS_HTTP_ADDR /
  示例端口硬编码）；serve 生命周期的 2 条变异自 `mutate-primitive-guards.py` 迁入
  （彼处计 13→11）。

### 变更

- **底座依赖**：+ `cloudwego/kitex v0.16.4`、`oekit/kitex v0.7.6`、`oekit/bootstrap v0.6.8`。
- `CheckBaseSharedByBoth` 现在也守 `pkg/rpcapi` 与 `pkg/faces`（两服务都接线后即绿）。

## [0.4.0] - 2026-11-04

### 变更

- **枚举的 wire 值表收编**：`model/jms.WireEnums`（各枚举的 `*Values` 列表）是 wire 名的
  唯一源，`pkg/render` 的 schema 钉词从它派生（`wireSchemas`）。原来只钉 `Status` 一个
  枚举 ⇒ `CommandClass` / `Risk` / `Delivery` 的字段在契约里说 "integer"、答复却是词
  （`"DANGEROUS"` / `"read"` / `"maybe_sent"`）—— 工具在违自己的声明形状。`Delivery`
  补上名字进出的 Marshal/Unmarshal，与其余枚举一致。两表对账（生成常量 ↔ WireEnums）
  有守卫（`model/jms/enum_values_test.go`）。
- **「工具说了什么」收编为 `render.ResultText`**（所有 text 块按行拼接）：留痕原来只取
  **第一块**、REST 面却全拼 ⇒ 同一个多块答复，留痕记一句、HTTP 面记全文。现在一处定义。
- **门禁拒绝的精确类型判定收编为 `errs.GateDenial`**（`*invoke.DenyError` 精确匹配，
  不用 errors.As）：`pkg/reg` 的 refusal 与 `pkg/audit` 的 toolFailed 共用一个判据。
- **演练判定收编为 `risk.Rehearsal(c, confirmed)`**：「这命令会不会跑、缺什么」的措辞
  唯一源 —— 两个面各拼过一份，其中一面把 "DANGEROUS" 硬编码进本该报**实际**类别的
  句子里。
- **注册表收编**：call 的三个跨界自由变量收进 `callFacts`；新增 `Registry.Has`（唯一
  成员判定）与 `CatalogueEntry` / `Registry.Catalogue()`（目录行的唯一装配，REST 面
  原样上桌 —— 两个面各自拼行就是两份会漂的装配）。
- **脱敏的幂等性不变量只在 `pkg/redact.Scrub` 一处陈述**：audit/reg 原来各自复述一份
  （两份复述就是两个漂移点），现在只指路。

### 新增

- **`render.ListSpec[S,T].Build()` + `render.NormLimit`**：列表信封的唯一形状 ——
  filter → map → sort → truncate → count，`total` = 匹配数，`Max<=0` 无上限，
  `Less=nil` 保源序，动态 Note 在 Build() 后设；`NormLimit` 走 oekit pagination 归一。
- **`httpapi.ServeOptions` + `httpapi.Run` / `httpapi.Start`**：两个服务共用的 serve
  生命周期（`serve` = stdio + 可选随行 HTTP；`serve http` = 信号等待 + 5s 优雅关闭；
  `Start` 回真端口）。两个服务各自的 `startHTTP` / `serveHTTP` 拷贝收编进来（两份拷贝
  的日志措辞已经漂了）。
- **`reg.CatalogueTable(w, specs, hint)`**：`tools` 子命令的目录表格；conditional 确认的
  Hint 经回调传入（policy 表在服务侧，底座不依赖服务）。
- **`testsupport.OpenAPICheck` + `CheckOpenAPI`**：两个服务共用的 OpenAPI 守卫身
  （首差异行、版本 hint、非空探针）—— 守卫两仓各一份就会漂。
- **守卫与变异**：`script/mutate-primitive-guards.py` **13 条变异全红**（list 流水线 ×4、
  枚举两表对账与钉词 ×2、Rehearsal、GateDenial、CatalogueTable、Start 回真端口、
  serve http 缺地址 ×2（含「示例端口必须来自 ServeOptions.ExampleAddr」—— 共用文案
  硬编码某一个面的端口，会把另一个面的操作员指去错误的面）、firstDiffLine）。

### 修复

## [0.3.0] - 2026-11-04

### 变更

### 新增

- **HTTP 面底座 `pkg/httpapi`**：REST（`GET /api/v1/health`、`GET /api/v1/tools`、
  `POST /api/v1/tools/{name}/invoke`）+ MCP over streamable HTTP（`/mcp`），
  与 stdio **共用同一个注册表** ⇒ 同一道风险门禁、同一套确认语义、同一份留痕。
  - Bearer 令牌认证（常量时间比较）；**无 token 拒绝构建**，没有「不开认证」模式；
    `/api/v1/health` 是唯一免认证路由。
  - **结果的读法与 stdio 逐字相同**：拒绝、失败、入参不合形状一律 HTTP 200 +
    `is_error=true`；请求本身坏才 400，没有这个工具才 404。
  - **OpenAPI 3.1 文档生成**（`httpapi.OpenAPI`）：从注册表渲染，字节确定
    （map 键排序）⇒ 服务仓可以把它签入仓库并用守卫逐字节比对。
- **`pkg/reg` 扩展**：schema 捕获（`reg.Add` 自派生 input schema，镜像 SDK 派生）、
  `Registry.Schema`、`Registry.CallTool`（内存会话调用，REST 面用）、
  `Registry.StreamableHTTPHandler`（SDK streamable HTTP 接线）。
- **镜像有钉**：`pkg/httpapi` 的 `TestTheCatalogueSchemaIsWhatTheWireSends` 拿
  REST 目录捕获的 schema 与 `/mcp` tools/list **线上字节**逐字节比对（五种入参形态）——
  SDK 升版若让派生漂移，这道测试会红，而不是两个面静默分岔。

### 修复

- **invoke 的传输层失败改映射 HTTP 500**（原 400）：`CallTool` 返回 err 是
  会话/传输层故障（入参不合 schema 实测走 200 + `is_error`，与 stdio 逐字相同）——
  400 会把进程内部的故障说成「你的请求坏了」。OpenAPI 文档的 400 描述同步改正。

## [0.2.0] - 2026-11-04

### ⚠️ 更名（breaking）

- 项目名去掉 `mcp`（本项目不止 MCP——两个服务接下来同时提供 HTTP API）：
  - **`jumpserver-mcp-kit` → `jumpserver-kit`**（本仓；模块路径
    `github.com/yi-nology/jumpserver-kit`）
  - `jumpserver-mcp` → `jumpserver-mgmt`
  - `jumpserver-mcp-exec` → `jumpserver-exec`
- GitHub 仓名同步更名（旧 URL 自动跳转）。旧模块路径
  `github.com/yi-nology/jumpserver-mcp-kit` 停在 **v0.1.9**（该 tag 的 go.mod
  声明旧路径 ⇒ 旧消费者不受影响）；新路径从本版起。
- 历史条目里的旧名已统一改写为新名，旧 → 新映射以本条为准。

### 变更

- 本次只动名字（模块路径、文档、脚本、CI 里的引用），行为不变。

## [0.1.9] - 2026-11-04

### 变更

- **豁免标记改为锚定识别**（第二轮独立审阅 M-3）：散文里**提到**标记的行
  （「标记叫 jms:allow-credential」）之前会因 `strings.Contains` 被当成标记
  ⇒ 连带豁免下一行 ⇒ **文档自己造盲区**，且被记成合法豁免。现在只认两条
  锚定形态：**整行**标记（可带注释前缀）⇒ 豁免下一行；**行尾注释**标记 ⇒
  豁免当行。
- **同一行按「值」去重**：`Authorization: Bearer <…>` 同时像「认证头」与
  「空白分隔的键值对」（键成了 `Bearer`）⇒ 该形态只报一次。
  ⚠️ 不是通则：`${VAR:-<hex>}` 仍报两条（键值规则捕获的值带前导 `-`、
  默认值规则不带 ⇒ 按捕获值合并不了）——报告噪音，不是漏报。
- **URL 里的值判定收紧为「URL 凭据字母表」**：`looksOpaque` 只看大小写混排，
  CJK 散文、源码碎片、`[REDACTED]@ss` 都算「不透明」⇒ 守卫扫自己仓时三处
  误报。现在 URL 形态的值还必须落在 base64url + `.`（JWT）/ `%`（百分号编码）
  / `@`（密码内嵌）/ `=`（base64 垫）的字母表里。

### 新增

- **漏报规则补齐**（第二轮审阅 O-1…O-6、O-9 的形态；修了的形态不止
  六条 —— 反引号引号类也在其列）：
  - `token := "…"`（Go 短声明 / 海象）：分隔符表补 `:=`；
  - **URL 内嵌凭据**（`db://deploy:<…>@host`）：无键名 ⇒ 自己一条规则，
    密码吃到**最后一个** `@`；
  - **查询串参数**（`?token=<…>`）：键值规则看不见 URL ⇒ 自己一条规则
    （**别的参数要留着** —— 记录要说得清「跑了什么」）；
  - **空白分隔**（`.netrc` 的 `machine … password <…>`）：值须在**行尾**
    （否则 `export K=V` 会被吞成键 `export`）；
  - **无后缀文件的 PEM 头嗅探**（`id_rsa`/`id_ed25519` 那一类）。
    ⚠️ 边界：只对**完全无后缀**的文件嗅探 ⇒ `id_rsa.bak` 这类副本不被读
    （与 O-3 口径一致；连同 YAML 块标量（O-7）、AKIA 标识符（O-8）记为
    已知边界）；
  - **已知名字的变体**（`Dockerfile.prod`/`Makefile.local`）。
- **缩写键名改成「分隔符边界后缀」**（O-5）：`MY_TOK`/`api-tok`/`TOK2`
  之前两边都不认；`oauth` 仍不误伤（窄名单留在守卫内，**不进 `pkg/redact`**）。
- **测试 13 个**（M-1/M-2 的钉子 + 新规则各一）：含 `${VAR-<…>}` 单横线
  形态**断言 Kind**（`:-` 形态键值规则也会命中 ⇒ 钉不住默认值规则）、
  `.env.secrets` 点文件、散文提及标记不豁免、JWT 查询串断言 Kind+Key 等。
- **变异 12→24 条**（M13–M24）：点文件 / 单横线默认值 / 散文标记 /
  裸标记行 / `:=` / URL 内嵌 / 无后缀 PEM / 反引号 / `.netrc` /
  `Dockerfile.prod` / 查询串 JWT，外加「文档里的 URL 仍是绿」边界。⚠️ 夹具路径避开了仓根真实的 `main.go`
  （撞名会误报「真仓被改」）。

### 修复

- **M-1**：点文件规则无测试钉住 ⇒ 补单测 + 变异 M13。
- **M-2**：`defaultValueRE` 无测试与变异钉住（M10 靠键值规则偶然命中而
  「假死」）⇒ 单测断言 Kind + 变异 M14 用**独占形态**（单横线）。

## [0.1.8] - 2026-11-04

### 修复

- **删除误入库的临时脚本** `script/.tmp-mutate-cred.py`（`00d9860` 引入、
  `1085700` 删除）：临时产物不进仓。⚠️ 它仍在 git 历史里（内容无凭据）。

## [0.1.7] - 2026-11-04

### 变更

- ⚠️ **凭据守卫的判据补齐了「事故原形」**（v0.1.6 的守卫抓不住它要防的那件事）：
  独立审阅把归档仓历史里**真实带令牌的那几个文件**原样喂给守卫，**0 命中**
  ⇒ 守卫的立论前提没有被它自己复现。三处漏报都已修：
  - **缩写键名**（`TOK = "…"`）：共享词表不认识这个缩写 ⇒ 守卫另立一份
    **窄名单**（`tok`/`auth`/`credentials`，**精确匹配**，不作后缀）。
    ⚠️ 刻意**没有**把它们加进 `pkg/redact` 的词表 —— 那张表决定留痕记什么、
    答复掩什么，加词会改变另外两条路径的行为。
  - **位置参数**（`env.setdefault("JUMPSERVER_TOKEN", "…")`）：键与值之间是
    **逗号** ⇒ 新增一条「位置参数」规则。
  - **shell 默认值**（`JUMPSERVER_TOKEN="${JUMPSERVER_TOKEN:-…}"`）：值躲在
    `${…:-…}` 后面 ⇒ 新增一条「默认值」规则。
  - **JSON 成员**（`{"token": "…"}`）：键与冒号之间隔着一个闭引号 ⇒ 键的
    闭引号改成**可选**。⚠️ 旧注释写着「引号会被连同键一起捕获」，而代码其实
    **没实现**那句话 —— 正是本仓反复警告的「抄本漂移」。
  - **非十六进制的凭据**（base64 形态的密钥 / GitHub PAT / AWS secret）：
    值形态从「必须是 hex」放宽为「hex 或 **不透明**的 base64」。
    ⚠️ 「不透明」是关键：全小写的散文（`my-very-long-service-name`）不算。
- **豁免记账改为打印**（不是 `t.Logf`）：`go test` 在包通过时会丢掉
  stdout ⇒ 记在 log 里等于没记。
  ⚠️ 但**不带 `-v` 时打印同样会被丢** ⇒ **三个仓的 CI 都跑 `go test -v`**
  ⇒ CI 里可见；本地要加 `-v` 才看得到（AGENTS.md 已写明）。
- **点开头的文件一律读**（`.env.local`/`.env.production` 之前是盲区）。

### 新增

- **`pkg/arch/credential_test.go`** 补 6 个用例：JSON 成员 / 位置参数 /
  shell 默认值 / 缩写键名 / base64 凭据 / 散文不误报。
- **`script/mutate-credential-guard.py`** 补 5 条**事故原形**变异
  （缩写键名 / 位置参数 / shell 默认值 / JSON 成员 / base64）⇒ 12 条变异。

### 修复

- **变异脚本的三条边界用例没传 `expect="green"`** ⇒ 脚本把「边界守住了」
  报成「守卫是假的」，并以非零码退出 ⇒ 这条守卫当时**没法用变异脚本证明
  自己会红**（脚本红 ≠ 守卫红，恰恰相反：脚本红是脚本自己接线错）。
  ⚠️ 抄漏了：同仓 `mutate-entry-layer.py` 的边界用例是**显式**写了这句的。

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
  （`JMS_DELEGATION_SECRET` 环境变量，或 `~/.config/jumpserver-mgmt/delegation.key`
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
  `~/.local/state/jumpserver-mgmt/audit`；凭据文件目录从 `~/.config/jms-mcp/` 改为
  `~/.config/jumpserver-mgmt/`（口令文件、委派 secret）。
  ⇒ **升级时要把旧目录里的东西挪过去**（或设 `JMS_AUDIT_DIR` 指回旧路径），
  否则留痕会从零开始、旧记录查不到。
