package reg

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// These tests drive the service face of the registry: the REST loopback
// (CallTool) and the streamable HTTP handler. The rules they hold up are
// the ones a second face could quietly break: the gate still refuses, the
// trail still names the caller, the catalogue still carries shapes.

type surfaceArgs struct {
	Confirm bool   `json:"confirm,omitempty"`
	Message string `json:"message,omitempty"`
}

type surfaceOut struct {
	Echo string `json:"echo"`
}

// surfaceRegistry builds one registry with a confirm-gated tool, and
// captures every trail record into records.
func surfaceRegistry(t *testing.T, records *[]Record) *Registry {
	t.Helper()
	r := New(&mcp.Implementation{Name: "surface-test", Version: "1"}, Options{
		Policy: PolicyTable{
			"surface_echo": {Risk: jms.Risk_write, Confirm: "set confirm=true to echo"},
		},
		OnRecord: func(rec Record) { *records = append(*records, rec) },
	})
	Add(r, &mcp.Tool{
		Name:         "surface_echo",
		Description:  "echo the message",
		OutputSchema: render.Schema[surfaceOut](),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in surfaceArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: in.Message}},
		}, surfaceOut{Echo: in.Message}, nil
	})
	return r
}

func TestCallToolGoesThroughTheGate(t *testing.T) {
	records := []Record{}
	r := surfaceRegistry(t, &records)

	res, err := r.CallTool(context.Background(), "probe", "surface_echo", json.RawMessage(`{"message":"hi"}`))
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !res.IsError {
		t.Fatal("a confirm-gated tool without confirm=true must be refused")
	}
	if !strings.Contains(textOf(res), "set confirm=true") {
		t.Fatalf("the refusal must carry the tool's own sentence, got %q", textOf(res))
	}

	res, err = r.CallTool(context.Background(), "probe", "surface_echo", json.RawMessage(`{"message":"hi","confirm":true}`))
	if err != nil {
		t.Fatalf("confirmed call: %v", err)
	}
	if res.IsError {
		t.Fatalf("the confirmed call must run, got %q", textOf(res))
	}
	if textOf(res) != "hi" {
		t.Fatalf("tool answer = %q, want hi", textOf(res))
	}
	if len(records) != 2 {
		t.Fatalf("trail lines = %d, want 2 (the refusal leaves a line too)", len(records))
	}
	for _, rec := range records {
		if rec.Gate.Call.Caller != "probe" {
			t.Fatalf("trail caller = %q, want probe (the caller the loopback named)", rec.Gate.Call.Caller)
		}
	}
}

// textOf here is the local reader of a result's text; pkg/httpapi has its
// own copy for its envelope. (Both are three lines; a shared one would put
// a wire detail of the REST face into pkg/reg.)
func textOf(res *mcp.CallToolResult) string {
	parts := []string{}
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, t.Text)
		}
	}
	return strings.Join(parts, "\n")
}

func TestSchemaCapturesTheDeclaredShapes(t *testing.T) {
	records := []Record{}
	r := surfaceRegistry(t, &records)

	in, out, ok := r.Schema("surface_echo")
	if !ok {
		t.Fatal("a registered tool must be in the schema catalogue")
	}
	var shape map[string]any
	if err := json.Unmarshal(in, &shape); err != nil {
		t.Fatalf("input schema is not JSON: %v", err)
	}
	props, _ := shape["properties"].(map[string]any)
	if _, ok := props["message"]; !ok {
		t.Fatalf("the captured input shape must mention the message argument, got %v", props)
	}
	if len(out) == 0 {
		t.Fatal("a tool with a declared output shape must capture it")
	}
	if _, _, ok := r.Schema("no_such_tool"); ok {
		t.Fatal("an unregistered name must not be in the catalogue")
	}
}

func TestStreamableHTTPHandlerServesTheRegistry(t *testing.T) {
	records := []Record{}
	r := surfaceRegistry(t, &records)
	h := r.StreamableHTTPHandler(nil)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"http-probe","version":"1"}}}`
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("initialize over streamable HTTP = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "serverInfo") {
		t.Fatalf("the answer must be an initialize result, got %q", w.Body.String())
	}
}
