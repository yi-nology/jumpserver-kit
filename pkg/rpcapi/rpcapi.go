// Package rpcapi is the kitex face of the registry: the third face, next
// to stdio MCP and the REST/MCP-HTTP face (pkg/httpapi).
//
// One registry, one gate, one trail — the face only carries the calls
// over thrift. The parity discipline with the other two faces:
//
//   - auth failures are TRANSPORT errors (no trail line, like a REST 401)
//   - unknown tool, gate refusals, schema-invalid arguments are ANSWERS
//     (is_error=true) — the caller's request was well-formed; the answer
//     says what the registry could not do
//   - the text is the ONE definition (render.ResultText, joined blocks)
//   - the catalogue rows are the registry's own assembly (reg.Catalogue)
package rpcapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/cloudwego/kitex/client"
	"github.com/cloudwego/kitex/pkg/serviceinfo"
	kitexserver "github.com/cloudwego/kitex/server"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oekit/concurrency/async"

	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc"
	"github.com/yi-nology/jumpserver-kit/kitex_gen/jmsrpc/execface"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

const RPCCaller = "rpc"

// Options is the RPC face's own configuration: the per-call token every
// method demands (no auth-off mode). ⚠️ Deliberately NO Name/Version:
// the thrift contract carries no self-report method, and dead config is
// drift bait — add them together with the IDL field that would use them.
type Options struct {
	Token string
}

// ServeOptions is Options plus where to listen and where the face writes
// its one line of news.
type ServeOptions struct {
	Options
	// Addr is the TCP address the kitex face listens on. ":0" is legal —
	// read the real port back from Addr().
	Addr string
	// Stderr is where the face writes its news and its failures.
	Stderr io.Writer
}

// Server is the kitex face: the handler behind execface.NewServer plus
// the listener it owns.
type Server struct {
	svr    kitexserver.Server
	ln     net.Listener
	addr   string
	stderr io.Writer
	token  string
	// probedOK flips once a self-call round trip has succeeded: the
	// bootstrap fence below only needs one proof.
	probed sync.Once
}

// New assembles the kitex face and binds it. The bind is SYNCHRONOUS: a
// port conflict fails HERE (the way httpapi.Start's bind does), so a
// half-started face that silently lost its port is impossible.
func New(r *reg.Registry, opts ServeOptions) (*Server, error) {
	if opts.Token == "" {
		return nil, errors.New("rpcapi: a token is required: there is no auth-off mode; " +
			"set JMS_RPC_TOKEN alongside JMS_RPC_ADDR")
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", opts.Addr, err)
	}
	face := &execFace{reg: r, token: opts.Token}
	svr := execface.NewServer(face, kitexserver.WithListener(ln))
	fmt.Fprintf(opts.Stderr, "listening on %s  (kitex, service ExecFace)\n", ln.Addr())
	return &Server{svr: svr, ln: ln, addr: ln.Addr().String(), stderr: opts.Stderr, token: opts.Token}, nil
}

// Addr hands back the real address (for ":0", the resolved port).
func (s *Server) Addr() string { return s.addr }

// Svr hands the server to the composition root (oekit/kitex.RunServer in
// pkg/faces' bootstrap modes). The Stop is FENCED: RunServer registers it
// as the shutdown resource, so the daemon path needs the same
// bootstrap protection the stdio ride gets from Server.Stop.
func (s *Server) Svr() kitexserver.Server { return fencedSvr{s} }

// fencedSvr delegates everything to the inner server except Stop, which
// waits for the face to have answered once (see fenceBootstrap).
type fencedSvr struct{ s *Server }

func (f fencedSvr) Run() error { return f.s.svr.Run() }
func (f fencedSvr) Stop() error {
	return f.s.Stop()
}

func (f fencedSvr) RegisterService(si *serviceinfo.ServiceInfo, h any, opts ...kitexserver.RegisterOption) error {
	return f.s.svr.RegisterService(si, h, opts...)
}

func (f fencedSvr) GetServiceInfos() map[string]*serviceinfo.ServiceInfo {
	return f.s.svr.GetServiceInfos()
}

// RunBackground serves in the background (the stdio-mode ride). The news
// line already went out in New; a Run error after a successful bind is
// exotic and logged, not fatal.
func (s *Server) RunBackground() {
	async.GoSafe(func() {
		if err := s.svr.Run(); err != nil {
			fmt.Fprintf(s.stderr, "rpc: %v\n", err)
		}
	})
}

// Stop shuts the face down — behind the bootstrap fence. kitex's Stop is
// idempotent, and the listener was adopted by the server — its Close is
// the authoritative one, so a defensive Close here fails with "use of
// closed network connection", which IS success, not a second error.
func (s *Server) Stop() error {
	s.probed.Do(s.fenceBootstrap)
	err := s.svr.Stop()
	_ = s.ln.Close()
	return err
}

// fenceBootstrap waits until kitex's Run has passed its bootstrap. kitex
// assigns transServer.ln OUTSIDE its own lock while Shutdown reads it
// under the lock (v0.16.4), so a Stop landing inside the bootstrap window
// is a data race — found by the race detector, reproduced by an audit
// probe, and kitex exposes no after-start hook to close it from the
// outside. The deterministic proof that bootstrap is done: a REAL kitex
// round trip against the face (netpoll only answers once the event loop
// is up). Bounded at 2s — a face that never comes up must not hang the
// caller; the window is better narrowed than the exit path hung.
func (s *Server) fenceBootstrap() {
	cli := execface.MustNewClient("rpcapi-fence", client.WithHostPorts(s.addr))
	deadline := time.Now().Add(2 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		_, err := cli.Catalogue(ctx, s.token)
		cancel()
		if err == nil || time.Now().After(deadline) {
			if err != nil {
				fmt.Fprintf(s.stderr, "rpc: bootstrap fence timed out; stopping anyway\n")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// execFace implements jmsrpc.ExecFace. The registry does the work; the
// face authorizes, names the caller, and shapes the answer.
type execFace struct {
	reg   *reg.Registry
	token string
}

// authorize is the ONE judge: per call, every method, constant-time. The
// length check first is the same shape httpapi's verify uses.
func (e *execFace) authorize(got string) bool {
	want := e.token
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// Invoke runs one tool call through the registry's chain. Auth failures
// are transport errors (no trail line); unknown tools and gate refusals
// are ANSWERS (is_error); a session failure is a transport error.
func (e *execFace) Invoke(ctx context.Context, call *jmsrpc.ToolCall) (*jmsrpc.InvokeResult_, error) {
	if !e.authorize(call.Token) {
		return nil, errors.New("unauthorized: the call must carry the RPC token")
	}
	if !e.reg.Has(call.Tool) {
		return &jmsrpc.InvokeResult_{IsError: true, Text: "no such tool: " + call.Tool}, nil
	}
	caller := RPCCaller
	if call.Caller != nil && *call.Caller != "" {
		caller = RPCCaller + "/" + *call.Caller
	}
	res, err := e.reg.CallTool(ctx, caller, call.Tool, call.Args_)
	if err != nil {
		return nil, err
	}
	return answer(res), nil
}

// Catalogue answers the tool directory. No anonymous access: the token is
// demanded here too — the same invariant as Invoke.
func (e *execFace) Catalogue(_ context.Context, token string) ([]*jmsrpc.ToolRow, error) {
	if !e.authorize(token) {
		return nil, errors.New("unauthorized: the call must carry the RPC token")
	}
	rows := make([]*jmsrpc.ToolRow, 0, len(e.reg.Catalogue()))
	for _, c := range e.reg.Catalogue() {
		row := &jmsrpc.ToolRow{
			Name:         c.Name,
			Description:  c.Description,
			Risk:         c.Risk,
			InputSchema:  c.InputSchema,
			OutputSchema: c.OutputSchema,
		}
		if c.Confirm != nil {
			confirm := *c.Confirm
			row.Confirm = &confirm
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// answer shapes the registry's result into the wire type. The text is
// render.ResultText — the ONE definition of "what did the tool say"; the
// structured content rides as JSON bytes (optional: error answers usually
// have none).
func answer(res *mcp.CallToolResult) *jmsrpc.InvokeResult_ {
	out := &jmsrpc.InvokeResult_{IsError: res.IsError, Text: render.ResultText(res)}
	if res.StructuredContent != nil {
		b, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return &jmsrpc.InvokeResult_{
				IsError: true,
				Text:    fmt.Sprintf("the answer could not be serialised: %v", err),
			}
		}
		out.Structured = b
	}
	return out
}
