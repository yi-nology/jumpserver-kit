package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// nestedArgs exercises the shapes INSIDE a struct: a slice of maps and a
// map. (Top-level containers are not legal tool inputs at all — the SDK
// rejects any input schema whose top level is not "object" — so the
// interesting derivation for slices/maps happens as struct fields.)
type nestedArgs struct {
	List []map[string]int  `json:"list,omitempty"`
	Meta map[string]string `json:"meta,omitempty"`
}

// This test pins the MIRROR: the schema the REST catalogue serves must be
// byte-for-byte what the SDK actually sends on the wire (tools/list).
//
// ⚠️ Why it has to be byte-for-byte: reg.Add derives the input schema
// itself (inputSchemaOf) because the SDK derives it AFTER registration.
// A mirror that drifts (SDK upgrade, options change) would leave the REST
// catalogue describing one shape and the wire carrying another — and both
// would look fine in isolation. Comparing against the wire is the only
// comparison that cannot fool itself: it uses the SDK's own output.
//
// ⚠️ The comparison is on RAW BYTES extracted from the SSE payload, with
// no re-marshalling in between — re-marshalling could normalize away the
// very difference this test exists to catch.
func TestTheCatalogueSchemaIsWhatTheWireSends(t *testing.T) {
	r := reg.New(&mcp.Implementation{Name: "mirror-test", Version: "1"}, reg.Options{
		Policy: reg.PolicyTable{
			"m_struct":   {Risk: jms.Risk_read},
			"m_pointer":  {Risk: jms.Risk_read},
			"m_any":      {Risk: jms.Risk_read},
			"m_nested":   {Risk: jms.Risk_read},
			"m_declared": {Risk: jms.Risk_read},
		},
	})
	// One tool per argument shape the derivation has to handle: struct,
	// pointer, any, nested containers (slice of maps / map) in a struct,
	// and a schema declared up front.
	reg.Add(r, &mcp.Tool{Name: "m_struct", Description: "d"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoArgs) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	reg.Add(r, &mcp.Tool{Name: "m_pointer", Description: "d"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ *echoArgs) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	reg.Add[any](r, &mcp.Tool{Name: "m_any", Description: "d"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ any) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	reg.Add(r, &mcp.Tool{Name: "m_nested", Description: "d"},
		func(_ context.Context, _ *mcp.CallToolRequest, _ nestedArgs) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})
	reg.Add(r, &mcp.Tool{Name: "m_declared", Description: "d", InputSchema: render.Schema[echoArgs]()},
		func(_ context.Context, _ *mcp.CallToolRequest, _ echoArgs) (*mcp.CallToolResult, any, error) {
			return nil, nil, nil
		})

	s, err := New(r, Options{Token: "sekrit", Name: "mirror-test", Version: "1"})
	if err != nil {
		t.Fatalf("build the surface: %v", err)
	}

	// The catalogue: what REST promises.
	w := do(t, s, "GET", "/api/v1/tools", "sekrit", "")
	if w.Code != 200 {
		t.Fatalf("tools = %d: %s", w.Code, w.Body.String())
	}
	var cat struct {
		Tools []struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"input_schema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &cat); err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	rest := map[string]json.RawMessage{}
	for _, e := range cat.Tools {
		rest[e.Name] = e.InputSchema
	}

	// The wire: what the SDK actually sends over /mcp tools/list.
	wire := wireInputSchemas(t, s)

	// 防虚绿：两边都必须真的覆盖全部五种形态 —— 空比空不是一面镜子。
	if len(rest) != 5 || len(wire) != 5 {
		t.Fatalf("五种形态没到齐：目录 %d 个、线上 %d 个（空比空不算证据）", len(rest), len(wire))
	}

	for name, want := range rest {
		have, ok := wire[name]
		if !ok {
			t.Errorf("%s: 在 REST 目录里，tools/list 却没发它", name)
			continue
		}
		if !bytes.Equal(want, have) {
			t.Errorf("%s: 目录捕获的 schema 与 SDK 线上下发的不一致：\n  目录: %s\n  线上: %s", name, want, have)
		}
	}
	for name := range wire {
		if _, ok := rest[name]; !ok {
			t.Errorf("%s: tools/list 发了，REST 目录里却没有", name)
		}
	}
}

// wireInputSchemas drives the streamable-HTTP /mcp endpoint through
// initialize + tools/list and returns each tool's inputSchema EXACTLY as
// the SDK serialized it — raw bytes lifted out of the SSE payload, never
// re-marshalled.
func wireInputSchemas(t *testing.T, s *Server) map[string]json.RawMessage {
	t.Helper()
	post := func(body, sid string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer sekrit")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, req)
		return w
	}

	init := post(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"mirror-test","version":"1"}}}`, "")
	if init.Code != 200 {
		t.Fatalf("initialize = %d: %s", init.Code, init.Body.String())
	}
	sid := init.Header().Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize 没回 Mcp-Session-Id —— 会话没建起来，后面的比对是空比对")
	}
	post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, sid)
	list := post(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`, sid)
	if list.Code != 200 {
		t.Fatalf("tools/list = %d: %s", list.Code, list.Body.String())
	}

	out := map[string]json.RawMessage{}
	for _, payload := range sseData(list.Body.String()) {
		var msg struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal([]byte(payload), &msg) != nil || msg.ID != 2 {
			continue
		}
		var res struct {
			Tools []json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(msg.Result, &res); err != nil {
			t.Fatalf("tools/list result: %v", err)
		}
		for _, raw := range res.Tools {
			var obj map[string]json.RawMessage
			if err := json.Unmarshal(raw, &obj); err != nil {
				t.Fatalf("tool entry: %v", err)
			}
			var name string
			_ = json.Unmarshal(obj["name"], &name)
			out[name] = obj["inputSchema"]
		}
	}
	return out
}

// sseData returns the data: payloads of an SSE body.
func sseData(body string) []string {
	var out []string
	for _, line := range strings.Split(body, "\n") {
		if rest, ok := strings.CutPrefix(line, "data:"); ok {
			out = append(out, strings.TrimSpace(rest))
		}
	}
	return out
}
