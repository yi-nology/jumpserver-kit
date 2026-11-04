package faces

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudwego/kitex/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/concurrency/async"

	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc"
	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc/execface"
	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/httpapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/rpcapi"
)

// The dispatch table is the launch model: what each subcommand runs and
// what it refuses. The tests pin the matrix and prove the composition
// end-to-end once (RPC mode, served and stopped through the caller's
// context).

func httpOpts(addr string) *httpapi.ServeOptions {
	return &httpapi.ServeOptions{Addr: addr, ExampleAddr: "127.0.0.1:8732"}
}

func rpcOpts(addr string) *rpcapi.ServeOptions {
	return &rpcapi.ServeOptions{
		Options: rpcapi.Options{Token: "sekrit", Name: "faces-test", Version: "1"},
		Addr:    addr,
	}
}

type echoIn struct {
	Message string `json:"message"`
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func TestFacesRPCModeServesUntilContextCancelled(t *testing.T) {
	r := reg.New(&mcp.Implementation{Name: "faces-test", Version: "1"}, reg.Options{
		Policy: reg.PolicyTable{"echo": {Risk: jms.Risk_read}},
	})
	reg.Add(r, &mcp.Tool{Name: "echo", Description: "echo it"},
		func(_ context.Context, _ *mcp.CallToolRequest, in echoIn) (*mcp.CallToolResult, any, error) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: in.Message}}}, nil, nil
		})
	mu := &sync.Mutex{}
	var buf bytes.Buffer
	opts := Options{RPC: rpcOpts("127.0.0.1:0"), Stderr: lockedWriter{mu: mu, b: &buf}}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	async.GoSafe(func() { errCh <- Run(ctx, r, opts, []string{"rpc"}) })
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		s := buf.String()
		mu.Unlock()
		if i := strings.Index(s, "listening on "); i >= 0 {
			if f := strings.Fields(s[i+len("listening on "):]); len(f) > 0 {
				addr = f[0]
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the rpc face never announced an address; stderr so far: %q", s)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cli := execface.MustNewClient("faces-test", client.WithHostPorts(addr))
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	res, err := cli.Invoke(cctx, &jmsrpc.ToolCall{Token: "sekrit", Tool: "echo", Args_: []byte(`{"message":"hi"}`)})
	if err != nil {
		t.Fatalf("invoke through the full stack: %v", err)
	}
	if res.IsError || !strings.Contains(res.Text, "hi") {
		t.Fatalf("echo answer malformed: %+v", res)
	}
	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned an error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on context cancellation")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("the port must be rebindable after the daemon stops: %v", err)
	}
	_ = ln.Close()
}

func TestThePlanRefusesWhatTheConfigCannotServe(t *testing.T) {
	yes, no := true, false
	o := func(http, rpc *bool) Options {
		var opts Options
		if http != nil && *http {
			opts.HTTP = httpOpts("127.0.0.1:8732")
		}
		if rpc != nil && *rpc {
			opts.RPC = rpcOpts("127.0.0.1:8742")
		}
		return opts
	}
	if m, err := plan(o(&yes, &no), nil); err != nil || m != modeStdio {
		t.Fatalf("no args must be stdio, got %v %v", m, err)
	}
	if _, err := plan(o(&no, &no), []string{"http"}); err == nil || !strings.Contains(err.Error(), "JMS_HTTP_ADDR") {
		t.Fatalf("http without an address must be refused: %v", err)
	}
	httpNoAddr := Options{HTTP: &httpapi.ServeOptions{ExampleAddr: "127.0.0.1:8732"}}
	if _, err := plan(httpNoAddr, []string{"http"}); err == nil || !strings.Contains(err.Error(), "127.0.0.1:8732") {
		t.Fatalf("the refusal carries the service's own example port: %v", err)
	}
	if _, err := plan(o(&no, &no), []string{"rpc"}); err == nil || !strings.Contains(err.Error(), "JMS_RPC_ADDR") {
		t.Fatalf("rpc without an address must be refused: %v", err)
	}
	if _, err := plan(o(&no, &no), []string{"all"}); err == nil || !strings.Contains(err.Error(), "JMS_HTTP_ADDR") || !strings.Contains(err.Error(), "JMS_RPC_ADDR") {
		t.Fatalf("all without any face must refuse naming both env vars: %v", err)
	}
	cases := []struct {
		name string
		http bool
		rpc  bool
		want mode
	}{{"http-only", true, false, modeAll}, {"rpc-only", false, true, modeAll}, {"both", true, true, modeAll}}
	for _, tc := range cases {
		h, r2 := tc.http, tc.rpc
		if m, err := plan(o(&h, &r2), []string{"all"}); err != nil || m != tc.want {
			t.Errorf("%s: plan(all) = %v, %v", tc.name, m, err)
		}
	}
	if _, err := plan(Options{}, []string{"bogus"}); err == nil || !strings.Contains(err.Error(), "unknown serve mode") {
		t.Fatalf("unknown mode must be refused: %v", err)
	}
}
