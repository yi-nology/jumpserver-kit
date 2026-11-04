// Package testsupport drives an MCP server from a test.
//
// It lives in the shared base because both planes need the same three
// things: a server with the tools registered, a session that can call them,
// and the answer read back as JSON. Each plane had grown its own copy of
// the first one — and copies drift, which is how a test ends up exercising
// a path the product does not take.
//
// The tools go on through the registry, exactly as in production: a test
// that registered them directly would not exercise the gate.
package testsupport

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// NewSession starts a server with the given tools registered, over an
// in-memory transport, and returns a client session that can call them.
//
// The policy table is the caller's: it is the plane's own risk side, and
// the gate is only the gate if the catalogue behind it is the real one.
func NewSession(t *testing.T, name string, opts reg.Options, register func(*reg.Registry)) *mcp.ClientSession {
	t.Helper()
	if opts.Policy == nil {
		t.Fatal("a session without a policy table: the gate would let everything through")
	}
	r := reg.New(&mcp.Implementation{Name: name, Version: "1"}, opts)
	register(r)

	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	cl := mcp.NewClient(&mcp.Implementation{Name: name + "-client", Version: "1"}, nil)
	cs, err := cl.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// CallToolJSON calls a tool on a session and returns its answer as JSON.
//
// The tools answer in one JSON block, so the tests read them as JSON: that
// is the wire format, and a test that used the producer's own struct would
// not notice a change in it.
//
// A tool whose answer does not match its own output schema fails the call
// before this returns — so every test that calls a tool is also a test of
// the contract.
func CallToolJSON(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) map[string]any {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	txt := ToolText(t, res)
	if res.IsError {
		t.Fatalf("tool %s failed: %s", name, txt)
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(txt), &out); err != nil {
		t.Fatalf("tool %s returned unparsable text: %v\n%s", name, err, txt)
	}
	return out
}

// ToolText returns the text of a tool result.
func ToolText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatalf("tool result carries no text content")
	return ""
}

// Uniq returns a name that will not collide with another run's.
func Uniq(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1000000)
}

// MustLoad runs a configuration loader and fails the test when it cannot
// read: a test that needs the configuration has no business inventing its
// own failure handling. (Both services' test setups read their
// configuration the same way — a copy of this is a copy that drifts.)
func MustLoad[T any](t *testing.T, load func() (T, error)) T {
	t.Helper()
	v, err := load()
	if err != nil {
		t.Fatalf("read the configuration: %v", err)
	}
	return v
}
