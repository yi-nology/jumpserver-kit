package reg

// 这个文件是注册表对外的**服务面**：给 HTTP 那一层用的三个入口。
//
// ⚠️ 它们都从注册表**里面**出发（srv 仍然不导出）：HTTP 层拿到的是
// 「能列目录、能调工具、能挂 MCP」这三件事，不是「能加工具」——
// 加工具绕过门禁的口子不开。

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// toolSchemas is one tool's argument and answer shapes, as raw JSON Schema.
type toolSchemas struct {
	input  json.RawMessage
	output json.RawMessage
}

// inputSchemaOf reads a tool's argument shape: the one it registered with,
// or the one the SDK derives from the Go type when registration did not
// spell one out.
//
// ⚠️ Why derive here at all: mcp.AddTool derives the schema internally,
// AFTER this package's Add runs — so a catalogue captured at registration
// would show every tool as shapeless, and a REST caller would have to
// guess what to send. This mirrors the SDK's own derivation
// (jsonschema.ForType with default options, "any" means no shape) so the
// catalogue and the wire cannot disagree.
func inputSchemaOf[In any](t *mcp.Tool) any {
	if t.InputSchema != nil {
		return t.InputSchema
	}
	if reflect.TypeFor[In]() == reflect.TypeFor[any]() {
		return &jsonschema.Schema{Type: "object"}
	}
	rt := reflect.TypeFor[In]()
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}
	s, err := jsonschema.ForType(rt, &jsonschema.ForOptions{})
	if err != nil || s == nil {
		return nil
	}
	return s
}

// rawSchemaJSON renders a declared schema as raw JSON.
//
// ⚠️ 缺失或不可渲染都返回 nil：目录里没有这一格，而不是放一个空对象
// ——空对象在 JSON Schema 里意味着「什么都能过」，那是另一个承诺。
func rawSchemaJSON(s any) json.RawMessage {
	if s == nil {
		return nil
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil
	}
	return b
}

// Schema returns the argument and answer shapes a tool declared.
//
// output is nil when the tool did not declare the shape of its answer —
// the same distinction HasOutputSchema makes, in raw form.
func (r *Registry) Schema(name string) (input, output json.RawMessage, ok bool) {
	s, ok := r.schemas[name]
	if !ok {
		return nil, nil, false
	}
	return s.input, s.output, true
}

// StreamableHTTPHandler serves this registry over MCP's streamable HTTP
// transport.
//
// The server stays unexported: the handler can serve calls, it cannot add
// tools. It is fine to serve the same registry from stdio and from HTTP at
// the same time — one gate, one catalogue, one audit trail either way.
func (r *Registry) StreamableHTTPHandler(opts *mcp.StreamableHTTPOptions) *mcp.StreamableHTTPHandler {
	return mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return r.srv }, opts)
}

// CallTool calls one tool by name on behalf of the named caller, without an
// MCP client in the middle.
//
// It exists for the REST surface (pkg/httpapi): a REST call is a tool call
// too, and it must pass the same gate and leave the same kind of line in
// the audit trail. So it goes through the server like any other call — an
// in-memory transport is the shortest way in that does not fork the
// chain. That also means the SDK validates the arguments against the
// tool's schema first, exactly as on the wire.
//
// ⚠️ caller is the audit trail's self-reported client name — the one fact
// that separates two callers sharing one machine. A caller that does not
// name itself is recorded unnamed, never guessed.
//
// ⚠️ The session is per call. Keeping one around would be faster, but a
// long-lived session would keep one caller's identity for the next
// caller's call — and in an audit trail a wrong name is worse than no
// name. These calls are human-frequency (a script driving an API), not
// model-token-frequency.
func (r *Registry) CallTool(ctx context.Context, caller, name string, args json.RawMessage) (*mcp.CallToolResult, error) {
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.srv.Connect(ctx, st, nil)
	if err != nil {
		return nil, err
	}
	defer ss.Close()

	cl := mcp.NewClient(&mcp.Implementation{Name: caller, Version: "1"}, nil)
	cs, err := cl.Connect(ctx, ct, nil)
	if err != nil {
		return nil, err
	}
	defer cs.Close()

	return cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
}
