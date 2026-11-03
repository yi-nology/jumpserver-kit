package reg

// The calls the SDK refuses before the tool ever runs.
//
// The SDK checks the INPUT against the tool's input schema BEFORE it calls
// the tool — so a management-plane write without `confirm` is refused there,
// and the gate never runs, and the trail had no line for it at all. The
// agent sees the error; the audit trail saw nothing.
//
// This is the one place where the trail and the agent disagree about what
// happened, and the trail is the one that has to be right: "who tried to
// write the config" is an audit question, and the answer cannot be "nobody
// tried".
//
// ⚠️ The row it writes says: the call was STOPPED (allowed=false), it FAILED
// (failed=true), and the gate never ran — so `stages[]` is EMPTY, which is
// how a reader tells it apart from a call the gate stopped (whose stages
// name the gate step that stopped it).

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oagentkit/guardx/invoke"
)

// methodCallTool is the JSON-RPC method of a tool call.
const methodCallTool = "tools/call"

// callMark is the per-call scratch the middleware and the registry share.
//
// It answers one question: did the tool body run? The SDK refuses some
// calls before the tool is called, and those refusals have to be told
// apart from the tool's own "no" — the first one never reached the tool,
// the second one did.
type callMark struct {
	reached atomic.Bool
}

// markKey is the context key the mark travels under.
type markKey struct{}

// markOf reads the call's mark out of the context, if there is one.
func markOf(ctx context.Context) *callMark {
	m, _ := ctx.Value(markKey{}).(*callMark)
	return m
}

// watchRejectedCalls records the calls the SDK refuses before the tool runs.
//
// It records ONLY the calls the tool never saw: a call the tool saw is the
// trail's business, and the gate's own refusals are already in it.
func (r *Registry) watchRejectedCalls(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != methodCallTool {
			// Only a tool call can be refused before the tool ran, and
			// only a tool call needs the mark.
			return next(ctx, method, req)
		}
		mark := &callMark{}
		ctx = context.WithValue(ctx, markKey{}, mark)
		res, err := next(ctx, method, req)
		if err != nil || mark.reached.Load() {
			return res, err
		}
		result, ok := res.(*mcp.CallToolResult)
		if !ok || !result.IsError {
			return res, err
		}
		r.recordRejectedCall(req, result)
		return res, err
	}
}

// recordRejectedCall writes the line for a call the SDK refused.
//
// It goes through the same recorder as every other call, so the arguments
// are scrubbed the same way ✓ — a refused call can carry a password just as
// easily as a successful one.
func (r *Registry) recordRejectedCall(req mcp.Request, res *mcp.CallToolResult) {
	if r.audit == nil {
		return
	}
	// ⚠️ The params here are the RAW ones — the SDK hands the middleware
	// the arguments as they came over the wire, before it validated them.
	// That is exactly what this needs: the name of the tool that was
	// called, and the arguments it was called with.
	params, _ := req.GetParams().(*mcp.CallToolParamsRaw)
	if params == nil {
		return
	}
	args := ""
	if len(params.Arguments) > 0 {
		args = string(params.Arguments)
	}
	// The reason the trail records: OUR words, not the SDK's.
	//
	// ⚠️ The SDK's validation message quotes the offending VALUE ("type:
	// [hunter2] has type \"string\", want \"integer\""), so copying it into
	// the trail would write down a credential the arguments column refuses
	// to write. The agent still gets the SDK's full message — it sent those
	// values — but the trail gets the FIELD PATH and nothing else.
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text = tc.Text
			break
		}
	}
	reason := "the arguments did not match the tool's declared shape"
	if fields := fieldPaths(text, params.Arguments); len(fields) > 0 {
		reason += " (" + strings.Join(fields, ", ") + ")"
	}
	r.record(invoke.Record{
		Call: invoke.Call{
			Name:   params.Name,
			Server: r.serverName,
			Args:   args,
			Caller: callerOfSession(req.GetSession()),
		},
		Err: errors.New(reason),
	}, nil, "", "", true)
}

// fieldPaths pulls the property paths out of the SDK's validation message.
//
// A path is a name ("/properties/password"), never a value — that is the
// whole point of taking the path instead of the sentence.
//
// ⚠️ And a path is only kept when it names a field the call ACTUALLY
// passed: otherwise a value that happens to contain "/properties/…" would
// be taken for a path and written down. The raw arguments are the ground
// truth for what the fields are called.
//
// If the SDK's wording changes, this finds nothing and the trail says
// less, which is the harmless direction.
func fieldPaths(text string, rawArgs json.RawMessage) []string {
	var keys map[string]bool
	if len(rawArgs) > 0 {
		keys = map[string]bool{}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(rawArgs, &decoded); err == nil {
			for k := range decoded {
				keys[k] = true
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range fieldPathRE.FindAllStringSubmatch(text, -1) {
		path := m[1]
		if path == "" || seen[path] {
			continue
		}
		// The path is "/properties/foo/properties/bar" ⇒ the field it
		// starts at is "foo", and that must be one of the fields the
		// call really passed.
		//
		// ⚠️ When the field names could not be established at all, NO
		// path is kept. A check that quietly stops checking is worse
		// than no check: it would let a value that merely LOOKS like a
		// path back into the trail.
		first := strings.Split(path, "/")[0]
		if !keys[first] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	return out
}

// fieldPathRE matches a property path in the SDK's validation message.
var fieldPathRE = regexp.MustCompile(`/properties/([A-Za-z0-9_.\-]+)`)
