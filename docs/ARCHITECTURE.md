# 架构：三仓的边界与依赖方向

> 一句话说清：**两个服务仓 depend on 底座仓；底座仓谁都不 depend。**
> 这份文档讲的是**为什么**、**怎么发版**、以及**跨仓的守卫怎么跑**。

---

## 1. 三个仓

| 仓 | module path | 是什么 | 产出 |
|---|---|---|---|
| [`yi-nology/jumpserver-mcp-kit`](https://github.com/yi-nology/jumpserver-mcp-kit)（本仓） | `github.com/yi-nology/jumpserver-mcp-kit` | **共用底座**（库） | 无二进制（只有 Go 包） |
| [`yi-nology/jumpserver-mcp`](https://github.com/yi-nology/jumpserver-mcp) | `github.com/yi-nology/jumpserver-mcp` | **管理面** MCP 服务 | 二进制 `jumpserver-mcp`（97 个工具） |
| [`yi-nology/jumpserver-mcp-exec`](https://github.com/yi-nology/jumpserver-mcp-exec) | `github.com/yi-nology/jumpserver-mcp-exec` | **执行面** MCP 服务 | 二进制 `jumpserver-mcp-exec`（15 个工具） |

```
        ┌──────────────────────────┐
        │  jumpserver-mcp-kit      │   ← 共用底座（库）
        │  pkg/jmsapi  pkg/reg      │     协议层 / 门禁 / 输出契约 / 留痕 /
        │  pkg/render pkg/audit     │     脱敏 / 风险分类 / 失败分类
        │  pkg/redact pkg/risk      │     共用词汇 model/jms
        │  pkg/errs   pkg/arch      │
        └────────────┬─────────────┘
                     │ require（单向）
          ┌──────────┴──────────┐
          │                     │
┌─────────▼──────────┐  ┌───────▼────────────────┐
│ jumpserver-mcp     │  │ jumpserver-mcp-exec    │
│ 管理面              │  │ 执行面                  │
│ biz/jumpserver/    │  │ biz/exec/               │
│ internal/jumpserver│  │ internal/exec/koko      │
│ 97 个工具           │  │ 15 个工具               │
└────────────────────┘  └────────────────────────┘
```

**依赖方向是单向的**：两个服务仓 `require github.com/yi-nology/jumpserver-mcp-kit`；
底座仓**不 require** 任何一个服务，也**不许 import** 它们。

⚠️ **三个 module path 互为字符串前缀**（`…/jumpserver-mcp` 是
`…/jumpserver-mcp-exec` 的前缀，差一个 `-`）⇒ **import 判定必须带尾斜杠**
（`pkg/arch.IsImportOf` 就是这个形状）⇒ 否则底座 import 执行面会被判成
「import 了管理面」。

---

## 2. 为什么底座不认服务

底座是「**两个服务都认的东西**」：同一套协议、同一个门禁、同一份契约、
同一个脱敏词表、同一个留痕形状、同一个发布节奏。

⚠️ **底座一旦伸手进某个服务，就不再是共用的**，而是那个服务披着共用名字的私有代码
—— 另一个服务迟早也会伸手进去，两个服务就这么耦上了，**而没有人决定过**。

⇒ 它的判据不是「代码放哪儿方便」，而是「**两个服务是不是都够得到**」：
- 只被一个服务够得到的**包** ⇒ 它不该在底座（守卫：`pkg/arch` 的
  `CheckBaseSharedByBoth`，按**包**算、按**可达性**算）；
- 只被一个服务用着的共享**定义**（比如 `pkg/redact.IsCredentialKey` 那个词表）
  **仍然是共享的** —— 抄两份就会漂，那正是它要放在一处的原因。

⚠️ 反过来：**服务自己的部分用它自己的契约词汇是天经地义的**
（koko 直接产出 `SessionStats`，三个仓里只有这一份定义，不会漂）。
分层规矩是「底座不认服务」，不是「什么都必须上提到底座」。

---

## 3. 改底座的发版节奏

底座的版本是**承诺**：语义化版本，破坏性改动走 major。

```
改 kit ──▶ kit 测试全绿 ──▶ 发 kit 的 tag ──▶ 两个服务改 require ──▶
两个服务测试全绿 ──▶ 发两个服务
```

⚠️ **不要在服务仓的 `go.mod` 里写 `replace`** —— 那会让 `go.mod` 与机器绑定，
`go list -m` 报的是路径而不是版本，`require` 里的版本号变成一句空话。
本地联调用**不入库**的 `go.work`：

```
# 在服务仓根目录（go.work / go.work.sum 已在 .gitignore 里）
go work init .
go work use ../jumpserver-mcp-kit
go work edit -replace github.com/yi-nology/jumpserver-mcp-kit@v0.1.0=../jumpserver-mcp-kit
```

⚠️ **改底座 ⇒ 两个服务都要跑一遍测试**。只跑本仓的测试不算交付。

---

## 4. 跨仓守卫：需要三棵树同时在手

拆仓之后有几条守卫天生跨仓：

| 守卫 | 为什么跨仓 |
|---|---|
| 底座不得依赖任何服务 | 判据是**别的 module path** |
| 底座的包必须被两个服务都用 | 可达性要穿过两个服务仓的 import 图 ⇒ 三棵树 |
| 共用词汇必须真被产出 | 产出者在服务仓里（底座只有定义） |
| 能力的措辞不许在别处重写 | 措辞在底座、改写可能发生在任一服务仓 |

**兄弟仓在哪**（`pkg/arch/siblings.go`）：
1. 环境变量 `JMS_SIBLING_ROOTS`（`:` 分隔的目录列表）优先；
2. 没给 ⇒ 用同级目录约定：`../jumpserver-mcp` 与 `../jumpserver-mcp-exec`；
3. 找到了 ⇒ **真跑**（不是跳过）。

⚠️ **找不到 ⇒ 跳过，但不是「通过」** ⇒ CI 设 `JMS_REQUIRE_SIBLINGS=1`，
缺树时**失败**。跳过的消息必须写清楚「缺哪棵树、怎么补」，
否则读的人只看到一句 SKIP，不知道这条守卫今天没跑。

本地跑跨仓守卫：

```bash
JMS_REQUIRE_SIBLINGS=1 go test ./...
```

⚠️ **CI 的三个仓要同时在场**：kit 的 CI 把两个服务仓 checkout 到同级目录，
所以**两个服务仓必须先在 GitHub 上存在**（checkout 一个不存在的仓会直接失败）。

---

## 5. 共用的开发工具住在底座仓

`script/` 下的脚本**不属于底座本身**，它们是**三个仓共用的开发工具**。
它们住在底座仓，是因为共用它们的东西（审计与脱敏的守卫、委派凭据的门禁）
也在底座这一侧 —— **抄三份，三份就会漂，而漂了的那份是最少有人看的那份**。

| 脚本 | 干什么 |
|---|---|
| `script/mutate-audit.py` | 把 `pkg/audit`（以及脱敏、留痕、注册表）的每一处修复退回一次，看对应的守卫**会不会变红** |
| `script/mutate-version-guard.py` | 把「委派凭据必须有门禁」这条规则的每一处实现退回一次，看守卫**会不会变红** |
| `script/workset.py` | 多仓工作集的定义（哪些仓参与这一轮） |
| `script/review-prompt.md` | 独立审阅的提示词模板 + 「已经在哪些地方栽过」的清单 |
| `script/gen-idl.sh` | 从 `idl/jms/` 重新生成 `model/jms/` |
| `script/restore-go-modcache.sh` | 把 Go 的 module cache 补回来（离线环境的土办法） |

⚠️ **变异脚本自己得会喊**：先跑一条 **canary**（必须变红），不红就中止 ——
canary 没变红只有一个可能：变异压根没作用在被变异的代码上 ⇒ 后面每条变异
都跑在**未变异的代码**上 ⇒ 报告会说「守卫全是假的」，而真相是「它压根没扫到变异」。
⚠️ 两个脚本的**注入方式不一样**：`mutate-audit.py` 用 **overlay**，
`mutate-version-guard.py` 用**整仓副本**（它要守的那条守卫**在运行时扫源码树**，
overlay 看不见运行时的读盘）。详见
[`script/README.md`](https://github.com/yi-nology/jumpserver-mcp-kit/blob/main/script/README.md)。

---

## 6. 一次跨三个仓的改动长什么样

以「加一个新能力（会改协议形状）」为例：

1. **底座**：`pkg/jmsapi` 加端点与形状、`pkg/arch` 加能力清单的一行 + 探测；
2. **管理面**：工具用它、新契约类型进 `idl/jmsms/`、策略表加一条；
3. **执行面**：工具用它、新契约类型进 `idl/jmsexec/`、策略表加一条；
4. **三个仓都跑测试**（kit 的跨仓守卫要三棵树同时在手）；
5. **发版**：kit 的 tag → 两个服务改 require → 发两个服务。

⚠️ **顺序不能乱**：先发 kit 的 tag，再改两个服务的 require ——
否则服务仓的 CI 拉不到底座那个版本。

