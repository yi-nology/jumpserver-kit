/**
 * jmsrpc —— 两个服务共用的 RPC 面契约（kitex / thrift）。
 *
 * 泛型 Invoke：一次调用 = (工具名 + JSON 入参) → is_error/text/structured。
 * 与 REST 信封同构（pkg/httpapi 的 InvokeResult）——拒绝与失败是**答案**
 * （is_error=true），不是传输错误；门禁、确认、留痕、入参 schema 校验
 * 全部住在 reg.CallTool 下面，RPC 面只是同一扇门上的第三张脸。
 *
 * 生成方式（产物 kitex_gen/jmsrpc/ **入库**）：
 *   ./script/gen-rpc.sh
 */
namespace go jmsrpc

struct ToolCall {
  1: required string tool,
  // args 是 JSON object 字节：与 REST /api/v1/tools/<name> 的 body 同形，
  // 与 stdio MCP 的 params.arguments 同形。工具契约的唯一源是 MCP schema，
  // 这里不复制一份形状。
  2: required binary args,
  // 逐调用凭据：没有「不开认证」模式（服务端 ADDR 配了 TOKEN 缺 ⇒ 启动即拒）。
  3: required string token,
  // 留痕的自报姓名（audit trail 的 caller 列）；缺省记 unnamed。
  4: optional string caller,
}

struct InvokeResult {
  1: required bool is_error,
  // render.ResultText：全部文本块按行拼接（「工具说了什么」的唯一定义）。
  2: required string text,
  // structured content 的 JSON 字节（工具的契约类型序列化产物）。
  3: optional binary structured,
}

struct ToolRow {
  1: required string name,
  2: required string description,
  3: required string risk,
  4: optional string confirm,
  5: optional binary input_schema,
  6: optional binary output_schema,
}

service ExecFace {
  InvokeResult Invoke(1: ToolCall call)
  list<ToolRow> Catalogue(1: string token)
}
