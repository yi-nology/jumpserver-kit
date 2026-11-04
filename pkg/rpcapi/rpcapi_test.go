package rpcapi

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/kitex/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc"
	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc/execface"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// The RPC face is the registry's third face: what stdio and the REST face
// answer, this face answers the same way. The tests are the parity
// contract: auth is a transport error (no trail line, like a REST 401),
// unknown tool and gate refusals are ANSWERS (is_error), the text is the
// ONE definition (render.ResultText), the catalogue is the registry's own
// assembly, and the gate+trail sit below every call.

// recs collects the trail records safely: OnRecord fires on the kitex
// handler goroutine, the test reads from its own — a plain slice races
// under -race (no happens-before edge through a socket).
type recs struct {
	mu  sync.Mutex
	all []reg.Record
}

func (r *recs) add(rec reg.Record) { r.mu.Lock(); defer r.mu.Unlock(); r.all = append(r.all, rec) }
func (r *recs) got() []reg.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]reg.Record(nil), r.all...)
}

// testRPC brings up the face on a random port and hands back a kitex
// client aimed at it.
func testRPC(t *testing.T, records *recs) (*Server, execface.Client, *reg.Registry) {
	t.Helper()
	return up(t, records)
}

// up builds a registry with two tools (a read and a write-needing-confirm
// one) plus the face, and returns the client aimed at the real port.
func up(t *testing.T, records *recs) (*Server, execface.Client, *reg.Registry) {
	t.Helper()
	r := reg.New(&mcp.Implementation{Name: "rpcapi-test", Version: "1"}, reg.Options{
		Policy: reg.PolicyTable{
			"echo":      {Risk: jms.Risk_read},
			"danger":    {Risk: jms.Risk_write, Confirm: "set confirm=true to run"},
			"twoblocks": {Risk: jms.Risk_read},
		},
		OnRecord: records.add,
	})
	reg.Add(r, &mcp.Tool{
		Name:        "echo",
		Description: "echo the message",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Message}}}, nil, nil
	})
	reg.Add(r, &mcp.Tool{
		Name:        "danger",
		Description: "do the dangerous thing",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ dangerArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	})
	reg.Add(r, &mcp.Tool{
		Name:        "twoblocks",
		Description: "two blocks",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ twoblocksArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{
			&mcp.TextContent{Text: "first"},
			&mcp.TextContent{Text: "second"},
		}}, nil, nil
	})
	s, err := New(r, ServeOptions{
		Options: Options{Token: "sekrit", Name: "rpcapi-test", Version: "1"},
		Addr:    "127.0.0.1:0",
		Stderr:  io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Stop() })
	s.RunBackground()
	cli := execface.MustNewClient("rpcapi-test", client.WithHostPorts(s.Addr()))
	return s, cli, r
}

type echoArgs struct {
	Message string `json:"message" jsonschema:"the message to echo"`
}
type dangerArgs struct {
	Confirm bool `json:"confirm,omitempty"`
}

func TestRPCFaceRefusesWrongToken(t *testing.T) {
	var r recs
	_, cli, _ := testRPC(t, &r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := cli.Invoke(ctx, &jmsrpc.ToolCall{Token: "wrong", Tool: "echo", Args_: []byte(`{}`)}); err == nil {
		t.Fatal("a wrong token must be a transport error")
	}
	if _, err := cli.Catalogue(ctx, "wrong"); err == nil {
		t.Fatal("the catalogue must demand the token too — no anonymous access")
	}
	if len(r.got()) != 0 {
		t.Fatalf("auth failures leave no trail line, got %d", len(r.got()))
	}
}

func TestRPCFaceAnswersUnknownToolWithErrorAnswer(t *testing.T) {
	var r recs
	_, cli, _ := testRPC(t, &r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := cli.Invoke(ctx, &jmsrpc.ToolCall{Token: "sekrit", Tool: "nope", Args_: []byte(`{}`)})
	if err != nil {
		t.Fatalf("unknown tool must be an answer, got transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Text, "no such tool") {
		t.Fatalf("unknown tool answer malformed: %+v", res)
	}
	if len(r.got()) != 0 {
		t.Fatalf("an unknown tool never reaches a tool; no trail line, got %d", len(r.got()))
	}
}

func TestRPCFaceGoesThroughTheGate(t *testing.T) {
	var r recs
	_, cli, _ := testRPC(t, &r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cli.Invoke(ctx, &jmsrpc.ToolCall{Token: "sekrit", Tool: "danger", Args_: []byte(`{}`)})
	if err != nil {
		t.Fatalf("gate refusal is an answer, not a transport error: %v", err)
	}
	if !res.IsError || !strings.Contains(res.Text, "confirm") {
		t.Fatalf("the refusal must carry the gate's sentence: %+v", res)
	}
	if got := r.got(); len(got) != 1 {
		t.Fatalf("the trail must have one line for the refusal, got %d", len(got))
	} else if got[0].Gate.Call.Caller != RPCCaller {
		t.Errorf("trail caller = %q, want %q", got[0].Gate.Call.Caller, RPCCaller)
	}
}

func TestRPCFaceServesTheCatalogue(t *testing.T) {
	var rc recs
	_, cli, r := testRPC(t, &rc)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rows, err := cli.Catalogue(ctx, "sekrit")
	if err != nil {
		t.Fatalf("catalogue: %v", err)
	}
	if len(rows) != len(r.Specs()) {
		t.Fatalf("rows = %d, registry holds %d", len(rows), len(r.Specs()))
	}
	for _, row := range rows {
		if row.Name == "" || row.Description == "" {
			t.Errorf("row has no name or description: %+v", row)
		}
	}
	for _, row := range rows {
		if row.Name == "danger" && (row.Confirm == nil || *row.Confirm == "") {
			t.Errorf("danger's confirm column is empty: %+v", row)
		}
		if row.Name == "echo" && row.Confirm != nil {
			t.Errorf("echo must not carry a confirm column: %+v", row)
		}
	}
}

func TestRPCFaceTextIsTheOneDefinition(t *testing.T) {
	var r recs
	_, cli, _ := testRPC(t, &r)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := cli.Invoke(ctx, &jmsrpc.ToolCall{Token: "sekrit", Tool: "twoblocks", Args_: []byte(`{}`)})
	if err != nil {
		t.Fatalf("invoke: %v", err)
	}
	if res.IsError {
		t.Fatalf("unexpected error answer: %s", res.Text)
	}
	if res.Text != "first\nsecond" {
		t.Fatalf("text = %q, want the joined definition", res.Text)
	}
}

type twoblocksArgs struct{}

func TestRPCFaceStartStopLeavesPortRebindable(t *testing.T) {
	var rc recs
	s, cli, _ := testRPC(t, &rc)
	a := s.Addr()
	// The Stop must not race the server's own bootstrap: wait until the
	// face has answered once (Run completed), then stop.
	deadline := time.Now().Add(3 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err := cli.Invoke(ctx, &jmsrpc.ToolCall{Token: "sekrit", Tool: "echo", Args_: []byte(`{}`)})
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the face never came up: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	ln, err := net.Listen("tcp", a)
	if err != nil {
		t.Fatalf("the port must be rebindable after Stop: %v", err)
	}
	_ = ln.Close()
}
