/**
 * jms —— JumpServer MCP 服务的**契约层**。
 *
 * 这个文件定义的是「本服务对外承诺的形状」，不是 JumpServer API 的形状：
 * 上游 v5 的返回体在资产/账号/会话之间形状不统一（有的嵌套、有的扁平），
 * 把它整份建模进来只会把上游的不一致原样复制一遍。因此这里只定义
 * **本服务自己造出来的**那几种形状——它们是本服务对调用方的承诺，
 * 一旦发布就不能悄悄改。
 *
 * 生成方式（slim 模板：不引入 thrift 运行时，只出结构体）:
 *   thriftgo --gen go:template=slim -o biz/model idl/jms/jms.thrift
 *
 * 生成物在 model/jms/，随仓提交；改这个文件后跑 script/gen-idl.sh。
 */
namespace go jms

/**
 * 诊断状态。三个取值各只表示一件事，不允许第四种：
 *
 *   ok    没问题，不用管
 *   warn  值得看一眼，但不挡路
 *   fail  这就是坏了
 */
enum Status {
  ok = 1,
  warn = 2,
  fail = 3,
}

/**
 * 一项检查：查了什么、查出来什么、坏了怎么修。
 *
 * fix 挂在每一项上，并点名能修它的工具（如 jms_asset_update），
 * 这样调用方拿到结论就知道下一步调什么，不必自己猜。
 */
struct Check {
  /** 被检查的维度名，如「资产协议」。 */
  1: required string name,
  /** 这一项的结论。 */
  2: required Status status,
  /** 这一项看到了什么。 */
  3: required string detail,
  /** 坏了怎么修；status=ok 时不出现。 */
  4: optional string fix,
}

/**
 * 诊断报告：五个诊断类工具共用的返回契约。
 *
 *   jms_doctor            接线与堡垒机配置体检
 *   jms_asset_audit       单机全貌（协议/账号/授权/连通性）
 *   jms_command_guard     某条命令会不会被过滤拦下
 *   jms_security_review   安全姿态
 *   jms_login_asset_check 某人此刻能不能登某台机器
 *
 * 统一的是**说法**，不是**判定口径**：每个工具保留自己对「什么算坏」的判断
 * （doctor 把 WARN 算作需要关注、guard 把「没匹配到过滤器」算作没事、
 * 资产审计把「账号全停用」算作坏而「部分停用」只算提醒）。
 */
struct Diagnosis {
  /** 逐项检查结果。 */
  1: required list<Check> checks,
  /** checks 里 status != ok 的那些（同一份数据的子集，方便直接问「哪里不对」）。 */
  2: required list<Check> findings,
  /** 总体评级：由 checks 推导，fail 压过 warn 压过 ok。 */
  3: required Status status,
  /** 一句话结论。 */
  4: optional string verdict,
  /** 一句话怎么修；由 findings 的 fix 拼成。 */
  5: optional string advice,
}

/**
 * 列表类工具的元信息。三个字段一律**无条件存在**，不要靠「有没有被截断」
 * 来猜 total 在不在：
 *
 *   count     本次返回了几条
 *   total     过滤后命中了几条
 *   truncated 返回数是否少于命中数（被截掉了多少 = total - count）
 */
struct ListMeta {
  1: required i32 count,
  2: required i32 total,
  3: required bool truncated,
}

/**
 * 一条 shell 命令的风险级别。
 *
 * 这是**命令**的分类，不是工具的：同一个工具（jmsx_exec）传进来的命令，
 * 风险可以从 READ 一直到 DANGEROUS。分类是保守的 —— 认不出来的一律往上抬，
 * 绝不往下压，所以 UNKNOWN 与 MODIFY 同等对待。
 */
enum CommandClass {
  /** 只读，没有副作用。 */
  READ = 1,
  /** 改配置或包状态（装包、起服务、改文件）。 */
  MODIFY = 2,
  /** 重启 / 删除 / 断网 / 提权。 */
  DANGEROUS = 3,
  /** 分不出来（按 MODIFY 对待）。 */
  UNKNOWN = 4,
}

/**
 * 工具的风险级别。决定它是否需要确认、是否在只读模式下被拦下。
 *
 *   read        只读，没有副作用
 *   write       改变堡垒机状态
 *   destructive 不可逆（删除资产/权限/账号），影响范围写进工具说明里
 */
enum Risk {
  read = 1,
  write = 2,
  destructive = 3,
}

/**
 * 一次动作**有没有真的送到机器上**。
 *
 * 这是失败之后最要紧的一格：「命令超时了」之后，人要问的第一句是
 * 「它还在那台机器上跑着吗」。答不出来就只能重试 —— 而重试一条**可能
 * 还在跑**的命令，就是把 `rm -rf` 跑第二遍的来路。
 *
 *   not_sent    根本没离开这个进程（没发出去）—— 重试是安全的
 *   maybe_sent  可能已经在机器上跑了 —— **永不重放**
 *
 * ⚠️ 没有「肯定送到了」这一档：成功时退出码本身就是证据，不必再写一遍。
 * 缺这一格 = 没人说（不是「肯定没送到」）。
 */
enum Delivery {
  not_sent = 1,
  maybe_sent = 2,
}

/**
 * 工具声明。注册表里的一个条目。
 *
 * name/description 由注册点给出（它们是给模型看的文案，和实现写在一起最不容易过期）；
 * risk 与 confirm 由策略表给出（集中一处，避免 28 处各写一遍「要 confirm=true」而漂移）。
 */
struct ToolSpec {
  1: required string name,
  2: required string description,
  3: required Risk risk,
  /** 需要 confirm=true 时的提示原文；空串表示这个工具不需要确认。 */
  4: optional string confirm,
}

/*
 * 工具调用失败**没有**进这份契约，原因是它兑现不了。
 *
 * 失败分类是真的：pkg/errs 把错误分成「值得重试」与「重发安全」两个维度
 * （timeout 值得重试，但服务端可能已经执行了 —— 原样重发就是重复施加副作用），
 * 那个分类来自 guardx/toolfail，是 HTTP 客户端据此决定重试什么的基础。
 *
 * 但**调用方看到的**失败是一句话：「ERROR: <原因>」。这个前缀是契约的一部分
 * —— 模型与读日志的人都学会了找它。要让失败变成一份结构化的答复，就得改
 * 每一处错误出口（150 多处），还要换掉 agent 已经学会的那句话。
 *
 * 所以失败分类住在代码里（pkg/errs），答复住在文字里，两边各司其职。
 * 这里曾经放过一个 ToolFailure 类型 —— 没有人产出它，于是一段注释变成了
 * 一份没人兑现的承诺。它是被新加的守卫（model/jms/contract_test.go）
 * 逮住的：共享词汇此前没有这道守卫，所以它一直没被看见。
 */

/**
 * 一台资产 —— **两个面共用**的词汇。
 *
 * 为什么在共用的这一层：执行面（jmsx_inventory）与管理面
 * （jms_assets_list）读的是**同一批堡垒机记录**，问的也是同一个问题
 * （「有哪些机器」）。各面各写一份，形状就会漂 —— 同一个 agent 在两个
 * server 上问同一件事，拿到两种字段，那不是两个工具，是一个工具说了两遍。
 *
 * 这个类型是那份「唯一的说法」：两个面的清单工具都按它产出，行字段一致。
 */
struct AssetSummary {
  /** 堡垒机里的 uuid。 */
  1: required string id,
  /** 资产名。 */
  2: required string name,
  /** 地址（IP 或主机名）。 */
  3: required string address,
  /** 这台资产上有几个账号。 */
  4: optional i32 accounts,
  /** 平台，如 Linux / macOS / Gateway。 */
  5: optional string platform,
  /** 平台大类：host / web / cloud —— 决定它是不是走终端接入。 */
  6: optional string category,
  /** 连通性：ok / err / -（没测过）。 */
  7: optional string connectivity,
  /** 是否启用。 */
  8: optional bool is_active,
  /** 声明的协议，形如 "ssh:22"。 */
  9: optional list<string> protocols,
}
