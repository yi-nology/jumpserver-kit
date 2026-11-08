// Package reg is the only door into the MCP server.
//
// Everything a tool can do to the bastion goes through one registry, and
// that registry decides two things before the tool body runs:
//
//   - whether the call is allowed at all (read-only mode, deny rules)
//   - whether the caller has confirmed the consequences
//
// The reason this is a package with an unexported server, rather than a
// helper the handlers may call or skip, is the whole point: the previous
// shape had 28 handlers each repeating "if !args.Confirm { refuse }", and
// the only thing keeping that honest was discipline. A handler added later
// would simply forget. Here, a tool cannot be registered outside this
// package, so it cannot skip the gate — the guarantee is structural, not
// conventional.
//
// The gate itself is guardx/invoke (a chain you cannot route around) plus
// guardx/permgate (who may do what, in which mode).
package reg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/oagentkit/guardx/invoke"
	"github.com/oagentkit/guardx/permgate"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/errs"
	"github.com/yi-nology/jumpserver-kit/pkg/redact"
	"github.com/yi-nology/jumpserver-kit/pkg/render"
)

// Policy is what the gate knows about one tool.
//
// The tool's own name and description live with its implementation; its
// risk and its confirmation requirement live here, in one table. They used
// to live in the handler, which is why 28 places had to be kept in step.
type Policy struct {
	// Risk grades the tool: read has no side effects, write changes the
	// bastion, destructive cannot be undone.
	Risk jms.Risk

	// Confirm is the sentence the caller sees when the tool is invoked
	// without an explicit confirmation. Empty means the tool needs none.
	//
	// The wording is the tool's own, because it is what the model reads:
	// "set confirm=true to delete the asset" says more than "confirmation
	// required" does.
	Confirm string

	// Hint is the catalogue text of a conditional confirmation: it says
	// when the flag is needed, without demanding it every time.
	//
	// It is not enforced (that is what Conditional is for) — it is what the
	// `tools` command prints, so an operator can see the rule without
	// reading the tool's schema.
	Hint string

	// Conditional marks a tool whose confirmation requirement depends on its
	// input: jms_job_run only needs confirm=true when the command it was
	// given classifies as DANGEROUS.
	//
	// Such a tool is not gated here. A refusal from the gate would be the
	// wrong answer — the tool's answer to "run this dangerous command
	// without confirmation" is a plan that says it was blocked, not an
	// error — so the decision stays where the classification is.
	Conditional bool
}

// PolicyTable is the risk side of the tool catalogue, keyed by tool name.
type PolicyTable map[string]Policy

// Lookup returns the policy of a tool.
//
// A tool that is not in the table is treated as a write that needs an
// explicit confirmation. The catalogue is supposed to be complete — a test
// enforces that — but if it ever is not, an unknown tool must not be able
// to change anything.
func (t PolicyTable) Lookup(name string) Policy {
	if p, ok := t[name]; ok {
		return p
	}
	return Policy{
		Risk:    jms.Risk_write,
		Confirm: "set confirm=true: this tool is not classified in the server's policy table",
	}
}

// Options configures a Registry.
type Options struct {
	// Policy is the tool catalogue's risk side.
	Policy PolicyTable

	// ReadOnly refuses every write tool. The bastion-wide "look, do not
	// touch" switch for an agent that should only look.
	ReadOnly bool

	// ServerName identifies this server in the audit trail.
	ServerName string

	// OnRecord receives one audit record per tool call: what was called,
	// which gate said what, how long it took, and whether the tool itself
	// refused to act. Credentials are scrubbed HERE, before the record is
	// handed over.
	OnRecord func(Record)
}

// Record is one tool call, as the trail sees it.
//
// The gate's verdict and the tool's verdict are two different things, and the
// difference is not academic. A tool can be let through by the gate and still
// refuse to act: a dangerous command without a confirmation reaches the tool,
// not the gate, because only the tool knows what the command is. The gate
// says "allowed", the tool says "refused", and the answer is that nothing
// ran.
//
// The trail has to say so, because a refusal leaves no trace on the bastion
// either — the command never got there.
type Record struct {
	// Gate is what the chain recorded: the gate's own verdict (Allowed,
	// Err, the stages) AND the action-layer conclusion the tool declared
	// (Outcome). Both layers live in one place because the upstream record
	// is where they live — a second copy of the conclusion is a second
	// thing to keep in step, and the one that drifts decides what the
	// trail records.
	Gate invoke.Record
	// WouldExecute says a rehearsal would have run the command had it been
	// confirmed. It is nil when the answer did not say — "unknown" and
	// "it would not have run" are different facts.
	//
	// It is the one field of the conclusion that upstream's Outcome does
	// not carry (the issue is filed against oagentkit/guardx), so it
	// travels beside the record until upstream grows that field.
	WouldExecute *bool
	// ToolError is the tool's own failure text, when the tool answered
	// with an error result.
	//
	// It is here because an MCP error result is still a SUCCESSFUL
	// protocol call: the chain sees no error, so `gate.Err` stays nil
	// and nothing else would record that the call failed. Without this,
	// a command that died half way through reads in the trail exactly
	// like one that ran fine — and "the trail says it ran" is the one
	// answer the trail must never give wrongly.
	ToolError string
	// Failure is the answer's own account of what went wrong, when the
	// tool reported it INSIDE the answer.
	//
	// Some tools answer with the results of the commands that worked and
	// say what broke the rest. That is a successful call — the chain sees
	// no error — so without this the trail would record a failed call as
	// a clean success.
	Failure string
	// StoppedEarly says the call was stopped BEFORE the tool ran — the
	// SDK refused it on its input contract (a management-plane write
	// without `confirm`, for instance).
	//
	// It is a fact of its own because it changes what `allowed` means for
	// that line: the call was STOPPED, not "it ran and broke".
	StoppedEarly bool
	// Delivery says how far the action got, when the error knew.
	//
	// It is the answer to "did it reach the machine": a command that was
	// delivered may still be running there, and running it again is how
	// `rm -rf` happens twice. The empty string means nobody said — which
	// is NOT the same as "it did not get there".
	//
	// It is a string because that is the shape the trail writes and the
	// contract carries; the typed vocabulary behind it lives in model/jms.
	Delivery string
}

// DeliveryAware is an error that knows whether the action reached the
// machine it was aimed at.
//
// It is how the delivery state travels out of the layer that knows it (the
// execution plane's session) and into the trail. The base declares the
// shape and the service fills it in, so neither side has to know the
// other's types — and the trail can answer "did it get there?" without
// parsing prose.
type DeliveryAware interface {
	error
	Delivery() jms.Delivery
}

// DeliveryOf says how far an action got, when the error knows.
//
// The zero value means "nobody said" — which is NOT the same as "it did
// not get there".
//
// It lives HERE, in the base, because reading the state is one thing with
// one answer: the service's errors carry it, the base reads it, and there
// is no second implementation to drift.
func DeliveryOf(err error) jms.Delivery {
	if err == nil {
		return jms.Delivery(0)
	}
	var aware DeliveryAware
	if errors.As(err, &aware) {
		return aware.Delivery()
	}
	return jms.Delivery(0)
}

// Registry owns the MCP server and the gate in front of it.
//
// The server is deliberately not exported: handing it out would hand out
// the ability to add a tool without the gate.
type Registry struct {
	srv    *mcp.Server
	policy PolicyTable
	mode   permgate.Mode
	audit  func(Record)

	// serverName identifies this server in the audit trail.
	serverName string

	gate permgate.Service

	specs []jms.ToolSpec
	// registered holds the names already on the server, so a second
	// registration of the same name is reported rather than absorbed.
	registered map[string]bool

	// schemas holds the argument and answer shapes each tool declared,
	// captured at registration. They are published by the REST catalogue
	// (pkg/httpapi): a client that cannot read the MCP tool list still has
	// to know what to send. The shapes are captured here rather than
	// derived later so the catalogue and the server can never disagree
	// about a tool's shape.
	schemas map[string]toolSchemas

	// declared records the tools that declared the shape of their output.
	// A tool that declares one has its answer checked against that shape
	// before the model sees it; a tool that does not is still callable, but
	// nothing holds its answer to a promise.
	declared map[string]bool
}

// New creates a registry around a fresh MCP server.
func New(impl *mcp.Implementation, opts Options) *Registry {
	mode := permgate.ModeDefault
	if opts.ReadOnly {
		mode = permgate.ModeReadOnly
	}
	r := &Registry{
		srv:        mcp.NewServer(impl, nil),
		policy:     opts.Policy,
		mode:       mode,
		audit:      opts.OnRecord,
		serverName: opts.ServerName,
		gate: permgate.Service{
			// Every tool the server exposes is on the whitelist by
			// default; the deny list is what an operator fills in.
			AllowedTools: map[string]bool{},
		},
		registered: map[string]bool{},
		schemas:    map[string]toolSchemas{},
		declared:   map[string]bool{},
	}
	// The middleware watches for the calls the SDK refuses before the tool
	// runs — see rejected.go.
	r.srv.AddReceivingMiddleware(r.watchRejectedCalls)
	return r
}

// Add puts one tool on the server.
//
// The signature is the SDK's, deliberately: the input schema is derived from
// the Go type of the arguments, so the schema the model sees and the schema
// the server validates can never drift apart.
//
// Add is a package-level function rather than a method because Go has no
// generic methods, and the input type has to be generic for the SDK to
// derive the schema.
//
// The tool body is called from inside the guard chain, which means a denied
// call never reaches it.
func Add[In any](r *Registry, t *mcp.Tool, fn mcp.ToolHandlerFor[In, any]) {
	// A tool name may be registered once. The SDK would silently let the
	// second registration win, which hides the mistake instead of reporting
	// it — and a catalogue that lists a tool twice is a catalogue nobody can
	// read. Failing here is failing at start-up, where it is cheap.
	if r.registered[t.Name] {
		panic(fmt.Sprintf("reg: tool %s is registered twice", t.Name))
	}
	r.registered[t.Name] = true

	policy := r.policy.Lookup(t.Name)
	spec := jms.ToolSpec{
		Name:        t.Name,
		Description: t.Description,
		Risk:        policy.Risk,
	}
	if policy.Confirm != "" {
		confirm := policy.Confirm
		spec.Confirm = &confirm
	}
	r.specs = append(r.specs, spec)
	r.schemas[t.Name] = toolSchemas{
		input:  rawSchemaJSON(inputSchemaOf[In](t)),
		output: rawSchemaJSON(t.OutputSchema),
	}
	r.gate.AllowedTools[t.Name] = true
	// The answer's shape, resolved ONCE so the call can check itself
	// against it.
	var resolved *jsonschema.Resolved
	if t.OutputSchema != nil {
		r.declared[t.Name] = true
		if s, ok := t.OutputSchema.(*jsonschema.Schema); ok {
			// The same options the SDK uses, so the two checks agree.
			r2, err := s.Resolve(&jsonschema.ResolveOptions{ValidateDefaults: true})
			if err != nil {
				// A schema that does not resolve can never validate — and
				// "declared but never checked" is the worst of both. Add is
				// the start-up entry, so this fails loudly and at boot, the
				// same as a duplicate registration.
				panic(fmt.Sprintf("reg.Add(%s): output schema does not resolve: %v", t.Name, err))
			}
			resolved = r2
		}
	}

	mcp.AddTool(r.srv, t, func(ctx context.Context, req *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
		res, out, err := call(r, ctx, t.Name, req, in, fn, resolved)
		if err != nil {
			return render.Err(err)
		}
		// The structured value is handed on, not dropped: the SDK checks it
		// against the tool's declared output schema and then serves it as
		// structuredContent, so the model receives data it can read as data
		// rather than only as text.
		return res, out, nil
	})
}

// callFacts is what the execution body tells the rest of the call about
// what happened. The closures below fill it in across the chain's
// boundary; it used to be three free variables crossing that boundary
// silently, and a reader had to hunt each write to know what the trail
// would end up saying.
type callFacts struct {
	// outcome is what the answer says happened. It is declared by the
	// execution body, and the chain copies it into the record, so the
	// trail reads the conclusion from one place instead of the registry
	// stitching it back together afterwards.
	outcome *render.Outcome
	// toolErr is the tool's own failure text, when it answered with an
	// error result. An MCP error result is still a successful protocol
	// call, so the chain sees no error — without this the trail would
	// have nothing to say about a call that failed.
	toolErr string
	// delivery is how far the action got, when the error knew. It is the
	// answer to "did it reach the machine", and the trail needs it
	// because a delivered command may still be running there.
	delivery string
}

// call runs one tool through the gate.
//
// The chain is built per call rather than per tool so the handler can close
// over the already-decoded arguments: the SDK has validated them against the
// schema by then, and decoding them a second time would throw away the
// defaults the schema applied.
func call[In any](
	r *Registry,
	ctx context.Context,
	name string,
	req *mcp.CallToolRequest,
	in In,
	fn mcp.ToolHandlerFor[In, any],
	resolved *jsonschema.Resolved,
) (*mcp.CallToolResult, any, error) {
	var out *mcp.CallToolResult
	var structured any
	facts := callFacts{}
	chain, err := invoke.NewChain(
		func(ctx context.Context, c invoke.Call) (invoke.Result, error) {
			res, value, err := fn(ctx, req, in)
			if err != nil {
				// ⚠️ The outcome is DROPPED here. Upstream v0.16.0 does
				// keep the body's own conclusion on the error path — it
				// copies `res.Outcome` into the record BEFORE it looks at
				// the error — but this handler returns a ZERO Result on
				// that path, so there is no outcome to copy.
				//
				// Nothing in this repository refuses that way today (every
				// refusal answers with a `blocked` field), so nothing is
				// broken by it — but a tool that starts refusing with an
				// error will be missing from `refused=` in the trail, and
				// the capability upstream offers would have to be used
				// (return a Result that carries the Outcome alongside the
				// error) for it to be recorded at all.
				//
				// The DELIVERY state, on the other hand, does come through
				// here: the error may know how far the action got, and
				// that is the one fact the trail cannot work out for
				// itself.
				if d := DeliveryOf(err); d != jms.Delivery(0) {
					facts.delivery = d.String()
				}
				// guardx v0.16+ supports carrying the conclusion alongside
				// the error (Result.Outcome survives the error path into
				// the record). The answer value may still declare a verdict
				// even though the call failed — a tool that refuses WITH an
				// error must reach the trail's `refused=` column, so the
				// outcome is read here too, exactly as on the success path.
				if res != nil {
					if oc := render.OutcomeOf(value); oc != nil {
						facts.outcome = oc
						result := invoke.Result{Text: render.ResultText(res)}
						result.Outcome = &oc.Outcome
						return result, err
					}
				}
				return invoke.Result{}, err
			}
			if res == nil {
				return invoke.Result{}, fmt.Errorf("tool %s produced no result", name)
			}
			out = res
			facts.outcome = render.OutcomeOf(value)
			result := invoke.Result{Text: render.ResultText(res)}
			// The answer is serialised ONCE, here, and the bytes are what
			// the trail measures.
			//
			// ⚠️ Without this the trail's `out_bytes` was 0 for every
			// structured answer: the chain measures the size of the TEXT,
			// and a structured answer has no text — the answer is in
			// structuredContent. So "how big was the answer" read as
			// "empty" for every tool that answers with data.
			//
			// The bytes are also what the SDK gets, so nothing is
			// serialised twice: the SDK copies them verbatim.
			if value != nil {
				if raw, mErr := json.Marshal(value); mErr == nil {
					structured = json.RawMessage(raw)
					result.Structured = raw
					// ⚠️ The answer is checked against the shape the
					// tool declared, HERE — before it leaves.
					//
					// The SDK checks it too, but that check happens
					// AFTER this chain has closed and the trail has
					// been written: an answer that violates its own
					// contract would reach the agent as a transport
					// error while the trail said "allowed, nothing
					// wrong". Checking here means the failure is a
					// failed CALL: the trail records it, and the agent
					// gets a tool error it can read.
					//
					// The cost is one validation per call (~60µs for a
					// 32KB answer) — noise next to a bastion session.
					if resolved != nil {
						var instance any
						if uErr := json.Unmarshal(raw, &instance); uErr == nil {
							if vErr := resolved.Validate(instance); vErr != nil {
								return invoke.Result{}, fmt.Errorf(
									"the answer of %s does not match the shape it declares: %w",
									name, vErr)
							}
						}
					}
				} else {
					// The answer could not be serialised. The SDK will
					// say so to the agent; the trail says it here too,
					// because "the answer was broken" is exactly what
					// the trail is for.
					structured = value
					facts.toolErr = fmt.Sprintf("the answer could not be serialised: %v", mErr)
				}
			} else {
				structured = value
			}
			if res.IsError {
				facts.toolErr = render.ResultText(res)
			}
			if facts.outcome != nil {
				// A nil Outcome means "the tool declared nothing", and
				// the chain settles that by its own result. Declaring
				// it here is what puts the conclusion into the trail.
				result.Outcome = &facts.outcome.Outcome
			}
			return result, nil
		},
		r.stages(name),
		invoke.WithRecorder(func(rec invoke.Record) {
			// The call reached the chain, so the tool was reached too:
			// the trail has this one, and the middleware must not write a
			// second line for it.
			if m := markOf(ctx); m != nil {
				m.reached.Store(true)
			}
			// The answer is read here, not inside the chain: the recorder
			// runs after the handler, so the answer is the one this call
			// produced — and it is what says whether the tool refused to
			// act.
			r.record(rec, facts.outcome, facts.toolErr, facts.delivery, false)
		}),
	)
	if err != nil {
		return nil, nil, err
	}

	call := invoke.Call{
		Name:   name,
		Server: r.serverName,
		Args:   string(rawArgs(req)),
		// The caller is the MCP client that asked. The trail says what
		// was attempted and why it was stopped; this says WHICH client
		// asked — the one thing that separates two agents sharing one
		// machine.
		Caller: callerOf(req),
	}
	if _, err := chain.Do(ctx, call); err != nil {
		return nil, nil, refusal(err)
	}
	if out == nil {
		return nil, nil, fmt.Errorf("tool %s produced no result", name)
	}
	return out, structured, nil
}

// callerOf names the MCP client that made the call.
//
// It is best-effort: a client that did not say who it is is recorded as
// unknown rather than guessed, because a wrong name in an audit trail is
// worse than no name.
// callerOf reads the MCP client's self-reported name from a tool call.
func callerOf(req *mcp.CallToolRequest) string {
	if req == nil || req.Session == nil {
		return ""
	}
	return callerOfSession(req.Session)
}

// callerOfSession reads the MCP client's self-reported name from a session.
//
// It is the same fact as callerOf, read from the session instead of from the
// typed request — the middleware only has the session.
func callerOfSession(sess mcp.Session) string {
	s, ok := sess.(*mcp.ServerSession)
	if !ok || s == nil {
		return ""
	}
	params := s.InitializeParams()
	if params == nil || params.ClientInfo == nil {
		return ""
	}
	return params.ClientInfo.Name
}

// stages are the gates every call passes through, in order.
//
// A stage that returns an error is treated as a refusal, never as "this
// stage does not apply" — a broken gate has to fail closed.
func (r *Registry) stages(name string) []invoke.Stage {
	return []invoke.Stage{
		invoke.StageFunc{StageName: "capability", Fn: func(ctx context.Context, c invoke.Call) (invoke.Verdict, error) {
			policy := r.policy.Lookup(name)
			cap := permgate.Capability{
				ReadOnly:  policy.Risk == jms.Risk_read,
				AlwaysAsk: policy.Confirm != "",
			}
			d := r.gate.Check(ctx, name, argsFor(c.Args), r.mode, cap)
			if d.Behavior == permgate.Deny {
				return invoke.Verdict{Allow: false, Reason: d.Reason}, nil
			}
			return invoke.Verdict{Allow: true, Reason: d.Reason}, nil
		}},
		invoke.StageFunc{StageName: "confirm", Fn: func(ctx context.Context, c invoke.Call) (invoke.Verdict, error) {
			policy := r.policy.Lookup(name)
			if policy.Confirm == "" {
				return invoke.Verdict{Allow: true}, nil
			}
			if confirmed(c.Args) {
				return invoke.Verdict{Allow: true}, nil
			}
			return invoke.Verdict{Allow: false, Reason: policy.Confirm}, nil
		}},
	}
}

// record hands one audit record to the caller.
//
// ⚠️ The arguments are scrubbed HERE, before the record is handed over —
// so a callback of any kind receives them already masked (Options.OnRecord
// is PUBLIC) — and the trail scrubs them again for its two exits
// (pkg/audit.Trail). Two passes are safe only because the COMBINED
// scrubber is idempotent: that invariant, and why it needs BOTH halves of
// the scrubber, is stated in ONE place — pkg/redact.Scrub. This comment
// only points at it.
//
// The raw arguments can carry a password (jms_user_password_set,
// jms_account_update) or a private key (jms_user_sshkey_add), and the
// record is written to a log.
//
// The conclusion comes along because the gate's verdict is not the whole
// story: a tool that refuses a dangerous command has already PASSED the gate,
// and the refusal is the part an audit has to remember. It rides in the
// chain's own record (upstream copies the execution body's declaration into
// it), so the trail reads one copy of it.
func (r *Registry) record(rec invoke.Record, outcome *render.Outcome, toolErr string, delivery string, stoppedEarly bool) {
	if r.audit == nil {
		return
	}
	// The combined scrubber (pkg/redact.Scrub) — the one place that
	// documents what it masks and why a second pass is safe.
	rec.Call.Args = redact.Scrub(rec.Call.Args)
	var wouldExecute *bool
	var failure string
	if outcome != nil {
		wouldExecute = outcome.WouldExecute
		// The answer may know how far the action got, even when the
		// failure came back as a normal answer (the multi-command tools
		// report a broken command INSIDE the answer).
		if delivery == "" {
			delivery = outcome.Delivery
		}
		failure = outcome.Failure
	}
	r.audit(Record{
		Gate:         rec,
		WouldExecute: wouldExecute,
		ToolError:    toolErr,
		Failure:      failure,
		Delivery:     delivery,
		StoppedEarly: stoppedEarly,
	})
}

// HasOutputSchema reports whether a tool declared the shape of its output.
//
// It exists so a test can hold the whole catalogue to the same standard: a
// tool that says nothing about its answer is a tool whose answer nobody can
// check.
func (r *Registry) HasOutputSchema(name string) bool {
	return r.declared[name]
}

// Specs returns the catalogue of registered tools.
func (r *Registry) Specs() []jms.ToolSpec {
	out := make([]jms.ToolSpec, len(r.specs))
	copy(out, r.specs)
	return out
}

// Serve runs the server on stdio until the transport closes.
func (r *Registry) Serve(ctx context.Context) error {
	return r.srv.Run(ctx, &mcp.StdioTransport{})
}

// Connect starts a session on this server over the given transport.
//
// Serve is the normal entry point; Connect is how a test drives the server
// in memory, against a fake bastion. It opens a session, it does not open a
// way to add a tool: the server stays unexported either way.
func (r *Registry) Connect(ctx context.Context, tr mcp.Transport, opts *mcp.ServerSessionOptions) (*mcp.ServerSession, error) {
	return r.srv.Connect(ctx, tr, opts)
}

// refusal turns a gate rejection into the error the caller sees.
//
// The wording matters: for a missing confirmation it is the tool's own
// sentence ("set confirm=true to delete the asset"), byte for byte what the
// tool used to answer when it checked the flag itself. The chain's own
// envelope ("invoke: 拒绝调用 ...") is for the audit trail, not for the
// model — the model needs the instruction, not the framework's grammar.
//
// ⚠️ Whether err IS the gate's denial is judged in one place
// (errs.GateDenial — it spells out the exact-match rule and why). The
// audit trail asks the same question for its own purposes.
func refusal(err error) error {
	if deny, ok := errs.GateDenial(err); ok && deny.Reason != "" {
		return errors.New(deny.Reason)
	}
	return err
}

// confirmed reports whether the caller passed confirm=true.
//
// The flag is read from the raw arguments rather than from the decoded
// struct: the gate has to work for every tool, and the tools that need a
// confirmation all declare a boolean named "confirm".
func confirmed(args string) bool {
	if args == "" {
		return false
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(args), &fields); err != nil {
		return false
	}
	v, ok := fields["confirm"].(bool)
	return ok && v
}

// argsFor hands the arguments to permgate in the shape it reads them in.
func argsFor(args string) any {
	if args == "" {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(args), &fields); err != nil {
		return nil
	}
	return fields
}

// rawArgs reads the arguments off a tool call.
func rawArgs(req *mcp.CallToolRequest) []byte {
	if req == nil || req.Params == nil {
		return nil
	}
	return req.Params.Arguments
}

// summary used to render a result for the audit trail by taking the FIRST
// text block — one of two definitions of "what did the tool say" in this
// repository (pkg/httpapi joined them all). There is one now:
// render.ResultText.
