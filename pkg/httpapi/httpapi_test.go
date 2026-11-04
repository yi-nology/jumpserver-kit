package httpapi

import (
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

// These tests hold up the rules a second face could quietly break: the
// token is the whole access policy, a REST call goes through the same
// gate as a stdio call, and the trail still names who asked.

type echoArgs struct {
	Message string `json:"message,omitempty"`
}

type echoOut struct {
	Echo string `json:"echo"`
}

type dangerArgs struct {
	Confirm bool `json:"confirm,omitempty"`
}

// testServer builds a two-tool registry behind an HTTP surface, and
// captures every trail record into records.
func testServer(t *testing.T, records *[]reg.Record) (*Server, *reg.Registry) {
	t.Helper()
	r := reg.New(&mcp.Implementation{Name: "httpapi-test", Version: "1"}, reg.Options{
		Policy: reg.PolicyTable{
			"echo":   {Risk: jms.Risk_read},
			"danger": {Risk: jms.Risk_write, Confirm: "set confirm=true to run"},
		},
		OnRecord: func(rec reg.Record) { *records = append(*records, rec) },
	})
	reg.Add(r, &mcp.Tool{
		Name:         "echo",
		Description:  "echo the message",
		OutputSchema: render.Schema[echoOut](),
	}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: in.Message}},
		}, echoOut{Echo: in.Message}, nil
	})
	reg.Add(r, &mcp.Tool{
		Name:        "danger",
		Description: "do the dangerous thing",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ dangerArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	})
	s, err := New(r, Options{Token: "sekrit", Name: "httpapi-test", Version: "1"})
	if err != nil {
		t.Fatalf("build the surface: %v", err)
	}
	return s, r
}

func do(t *testing.T, s *Server, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	// The MCP endpoint demands both content types in Accept; REST does
	// not care. One helper header serves both.
	req.Header.Set("Accept", "application/json, text/event-stream")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

func TestEverythingButHealthNeedsTheToken(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	if w := do(t, s, "GET", "/api/v1/health", "", ""); w.Code != 200 {
		t.Fatalf("health without a token = %d, want 200 (the probe cannot hold a secret)", w.Code)
	}
	for _, probe := range []struct{ method, path, body string }{
		{"GET", "/api/v1/tools", ""},
		{"POST", "/api/v1/tools/echo/invoke", `{"message":"hi"}`},
		{"POST", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`},
	} {
		if w := do(t, s, probe.method, probe.path, "", probe.body); w.Code != 401 {
			t.Errorf("%s %s without a token = %d, want 401", probe.method, probe.path, w.Code)
		}
		if w := do(t, s, probe.method, probe.path, "wrong", probe.body); w.Code != 401 {
			t.Errorf("%s %s with a wrong token = %d, want 401", probe.method, probe.path, w.Code)
		}
	}
}

func TestNewRefusesWithoutAToken(t *testing.T) {
	records := []reg.Record{}
	_, r := testServer(t, &records)
	if _, err := New(r, Options{Name: "x", Version: "1"}); err == nil {
		t.Fatal("a surface with no token must not be built")
	}
}

func TestToolsListsTheCatalogue(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	w := do(t, s, "GET", "/api/v1/tools", "sekrit", "")
	if w.Code != 200 {
		t.Fatalf("tools = %d: %s", w.Code, w.Body.String())
	}
	var out struct {
		Tools []reg.CatalogueEntry `json:"tools"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("catalogue is not JSON: %v", err)
	}
	if len(out.Tools) != 2 {
		t.Fatalf("catalogue has %d tools, want 2", len(out.Tools))
	}
	for _, e := range out.Tools {
		if e.Name == "echo" {
			if !strings.Contains(string(e.InputSchema), "message") {
				t.Fatalf("echo's input shape must mention its argument, got %s", e.InputSchema)
			}
			if len(e.OutputSchema) == 0 {
				t.Fatal("echo declared an answer shape; the catalogue must show it")
			}
		}
		if e.Name == "danger" && (e.Confirm == nil || !strings.Contains(*e.Confirm, "confirm=true")) {
			t.Fatalf("danger's confirmation rule must be in the catalogue, got %v", e.Confirm)
		}
	}
}

func TestInvokeCallsTheToolAndRecordsWhoAsked(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	w := do(t, s, "POST", "/api/v1/tools/echo/invoke", "sekrit", `{"message":"hi"}`)
	if w.Code != 200 {
		t.Fatalf("invoke = %d: %s", w.Code, w.Body.String())
	}
	var res InvokeResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	if res.IsError || res.Text != "hi" || res.Tool != "echo" {
		t.Fatalf("answer = %+v", res)
	}
	structured, _ := res.Structured.(map[string]any)
	if structured["echo"] != "hi" {
		t.Fatalf("structured answer must cross the REST face, got %v", res.Structured)
	}
	if len(records) != 1 {
		t.Fatalf("trail lines = %d, want 1", len(records))
	}
	if records[0].Gate.Call.Caller != RestCaller {
		t.Fatalf("trail caller = %q, want %q", records[0].Gate.Call.Caller, RestCaller)
	}
}

func TestARefusalIsAnAnswerNotARequestError(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	w := do(t, s, "POST", "/api/v1/tools/danger/invoke", "sekrit", `{}`)
	if w.Code != 200 {
		t.Fatalf("a refused call = %d, want 200: the call happened, its outcome was a refusal", w.Code)
	}
	var res InvokeResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Text, "confirm=true") {
		t.Fatalf("the refusal must be in the envelope, got %+v", res)
	}
	if len(records) != 1 || records[0].Gate.Allowed {
		t.Fatalf("the refusal must leave one line saying it was stopped, got %+v", records)
	}
	// The same call, confirmed, runs.
	w = do(t, s, "POST", "/api/v1/tools/danger/invoke", "sekrit", `{"confirm":true}`)
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	if res.IsError || res.Text != "ran" {
		t.Fatalf("the confirmed call must run, got %+v", res)
	}
}

func TestInvokeRequestErrors(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	for _, probe := range []struct {
		name, path, body string
		want             int
	}{
		{"unknown tool", "/api/v1/tools/nope/invoke", `{}`, 404},
		{"not JSON", "/api/v1/tools/echo/invoke", `hello`, 400},
		{"not an object", "/api/v1/tools/echo/invoke", `[1]`, 400},
	} {
		w := do(t, s, "POST", probe.path, "sekrit", probe.body)
		if w.Code != probe.want {
			t.Errorf("%s = %d, want %d: %s", probe.name, w.Code, probe.want, w.Body.String())
		}
	}
}

// An argument set that does not match the tool's shape is answered the
// same way over REST as over stdio: a completed call whose result says
// is_error. The two faces must be word-for-word the same — a REST
// caller and an MCP client asking the same question get the same
// answer shape, so no client has to learn two error dialects.
func TestArgumentsThatDoNotFitAreAnAnswerToo(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	w := do(t, s, "POST", "/api/v1/tools/echo/invoke", "sekrit", `{"message":42}`)
	if w.Code != 200 {
		t.Fatalf("bad arguments = %d, want 200 (an answer, like on stdio)", w.Code)
	}
	var res InvokeResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("answer is not JSON: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Text, "want") {
		t.Fatalf("the validation failure must be in the envelope, got %+v", res)
	}
}

func TestTheMCPFaceAnswersOverHTTP(t *testing.T) {
	records := []reg.Record{}
	s, _ := testServer(t, &records)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"http-probe","version":"1"}}}`
	w := do(t, s, "POST", "/mcp", "sekrit", body)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "serverInfo") {
		t.Fatalf("initialize over /mcp = %d: %s", w.Code, w.Body.String())
	}
}
