package reg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-mcp-kit/model/jms"
	"github.com/yi-nology/jumpserver-mcp-kit/pkg/render"
)

// The gate is the mechanism behind every refusal. These tests drive it
// directly, with a synthetic tool, because the interesting cases are the
// ones the production tools do not have: a tool whose schema does NOT make
// "confirm" required.
//
// In production the SDK's own schema validation catches a missing
// "confirm" first (the field is required in the input schema), so the gate's
// confirmation stage is the second line of defence there. It is the first
// line for a tool whose confirmation is optional — jms_job_run, whose
// requirement depends on the command it was given — and it is the only line
// if a schema is ever loosened.

type echoArgs struct {
	Confirm bool   `json:"confirm,omitempty"`
	Message string `json:"message,omitempty"`
}

func newTestRegistry(t *testing.T, opts Options) *Registry {
	t.Helper()
	if opts.Policy == nil {
		opts.Policy = PolicyTable{}
	}
	return New(&mcp.Implementation{Name: "reg-test", Version: "1"}, opts)
}

// callTool drives one tool of the registry.
//
// This one builds its session by hand instead of using pkg/testsupport: that
// package imports the registry, so importing it back here would be a cycle.
// It is the only place in the repository where the session setup is written
// out, and that is not an accident.
func callTool(t *testing.T, r *Registry, name string, args map[string]any) (string, bool) {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer ss.Close()

	cl := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil)
	cs, err := cl.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	return text, res.IsError
}

func TestConfirmationGateRefusesWithoutTheFlag(t *testing.T) {
	const sentence = "set confirm=true to do the thing"
	r := newTestRegistry(t, Options{Policy: PolicyTable{
		"jms_thing": {Risk: jms.Risk_write, Confirm: sentence},
	}})
	Add(r, &mcp.Tool{Name: "jms_thing", Description: "a thing"}, func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		b, _ := json.Marshal(in)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	})

	text, isErr := callTool(t, r, "jms_thing", map[string]any{"message": "ran"})
	if !isErr {
		t.Fatalf("the call went through without a confirmation: %s", text)
	}
	if !strings.Contains(text, sentence) {
		t.Errorf("refusal does not carry the policy's sentence %q:\n%s", sentence, text)
	}
}

func TestConfirmationGateLetsTheConfirmedCallThrough(t *testing.T) {
	r := newTestRegistry(t, Options{Policy: PolicyTable{
		"jms_thing": {Risk: jms.Risk_write, Confirm: "set confirm=true to do the thing"},
	}})
	Add(r, &mcp.Tool{Name: "jms_thing", Description: "a thing"}, func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		b, _ := json.Marshal(in)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}, nil, nil
	})

	text, isErr := callTool(t, r, "jms_thing", map[string]any{"confirm": true, "message": "ran"})
	if isErr {
		t.Fatalf("the confirmed call was refused: %s", text)
	}
	if !strings.Contains(text, "ran") {
		t.Errorf("the confirmed call did not reach the tool: %s", text)
	}
}

func TestReadOnlyModeRefusesWritesAndKeepsReads(t *testing.T) {
	r := newTestRegistry(t, Options{
		ReadOnly: true,
		Policy: PolicyTable{
			"jms_write": {Risk: jms.Risk_write, Confirm: "set confirm=true to do the thing"},
			"jms_read":  {Risk: jms.Risk_read},
		},
	})
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	}
	Add(r, &mcp.Tool{Name: "jms_write", Description: "a write"}, handler)
	Add(r, &mcp.Tool{Name: "jms_read", Description: "a read"}, handler)

	// The write is refused even with the confirmation.
	if _, isErr := callTool(t, r, "jms_write", map[string]any{"confirm": true}); !isErr {
		t.Error("the read-only mode let a write through")
	}
	// The read still runs.
	if _, isErr := callTool(t, r, "jms_read", map[string]any{}); isErr {
		t.Error("the read-only mode refused a read")
	}
}

// A tool that is not classified must not be able to change anything.
func TestUnclassifiedToolIsTreatedAsAWrite(t *testing.T) {
	r := newTestRegistry(t, Options{})
	Add(r, &mcp.Tool{Name: "jms_mystery", Description: "not classified"}, func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	})

	if _, isErr := callTool(t, r, "jms_mystery", map[string]any{}); !isErr {
		t.Error("an unclassified tool was allowed to run")
	}
}

// The catalogue is what the CLI prints and what the tests check against.
func TestSpecsCarryNameDescriptionAndRisk(t *testing.T) {
	r := newTestRegistry(t, Options{Policy: PolicyTable{
		"jms_thing": {Risk: jms.Risk_destructive, Confirm: "set confirm=true"},
	}})
	Add(r, &mcp.Tool{Name: "jms_thing", Description: "a thing"}, func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	})

	specs := r.Specs()
	if len(specs) != 1 {
		t.Fatalf("specs = %d, want 1", len(specs))
	}
	s := specs[0]
	if s.Name != "jms_thing" || s.Description != "a thing" {
		t.Errorf("spec = %+v", s)
	}
	if s.Risk != jms.Risk_destructive {
		t.Errorf("risk = %s, want destructive", s.Risk)
	}
	if s.Confirm == nil || *s.Confirm != "set confirm=true" {
		t.Errorf("confirm = %v", s.Confirm)
	}
}

// A name may be registered once. The SDK would let the second registration
// win silently; a catalogue that lists a tool twice is worse than a refusal
// to start.
func TestDuplicateRegistrationIsRefused(t *testing.T) {
	r := newTestRegistry(t, Options{})
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ran"}}}, nil, nil
	}
	Add(r, &mcp.Tool{Name: "jms_thing", Description: "a thing"}, handler)

	defer func() {
		if recover() == nil {
			t.Error("the second registration of the same name was accepted")
		}
	}()
	Add(r, &mcp.Tool{Name: "jms_thing", Description: "a thing"}, handler)
}

// A tool that answers with an ERROR RESULT still made a successful protocol
// call — the chain sees no error, so nothing else would say the call failed.
//
// Without this, a command that died half way through reads in the trail
// exactly like one that ran fine: same `allowed`, no error, no trace of the
// failure. The trail exists to answer "what happened here", and "it ran" is
// the answer that must never be given wrongly.
func TestAFailedCallIsRecordedAsFailed(t *testing.T) {
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{"jmsx_exec": {Risk: jms.Risk_read}},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	Add(r, &mcp.Tool{
		Name:        "jmsx_exec",
		Description: "a tool whose work fails",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		res, _, err := render.Failf("the command died half way through")
		return res, nil, err
	})

	callTool(t, r, "jmsx_exec", map[string]any{})
	if len(got) != 1 {
		t.Fatalf("the gate recorded %d calls, want 1", len(got))
	}
	if got[0].ToolError == "" {
		t.Fatal("the record does not say the call failed")
	}
	if !strings.Contains(got[0].ToolError, "died half way") {
		t.Errorf("the record does not carry the failure text: %q", got[0].ToolError)
	}
}

// callToolFull drives one tool and hands back the whole result.
//
// callTool answers "what did the agent read", which is the question most of
// these tests ask. This one answers "what came back" — the structured
// content included — for the tests that care about the wire shape.
func callToolFull(t *testing.T, r *Registry, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	ct, st := mcp.NewInMemoryTransports()
	ss, err := r.Connect(context.Background(), st, nil)
	if err != nil {
		t.Fatalf("connect server: %v", err)
	}
	defer ss.Close()

	cl := mcp.NewClient(&mcp.Implementation{Name: "probe", Version: "1"}, nil)
	cs, err := cl.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	defer cs.Close()

	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	return res
}

// deliveryAwareError is an error that knows how far the action got.
//
// It is what the execution plane's session produces: the layer that sent
// the command is the layer that knows whether the send went through.
type deliveryAwareError struct {
	text     string
	delivery jms.Delivery
}

func (e *deliveryAwareError) Error() string          { return e.text }
func (e *deliveryAwareError) Delivery() jms.Delivery { return e.delivery }

// The delivery state has to survive the whole way from the layer that
// knows it to the trail.
//
// It is the answer to "is it still running on that machine?" — the one a
// caller cannot work out for itself after a failure, and the one that
// decides whether running the command again is allowed.
func TestTheDeliveryStateReachesTheRecord(t *testing.T) {
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{"jmsx_exec": {Risk: jms.Risk_read}},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	type shape struct {
		Rows int `json:"rows,omitempty"`
	}
	Add(r, &mcp.Tool{
		Name:         "jmsx_exec",
		Description:  "a tool whose command may already be running",
		OutputSchema: render.Schema[shape](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return nil, nil, &deliveryAwareError{
			text:     "the command may already be running on the machine",
			delivery: jms.Delivery_maybe_sent,
		}
	})

	res := callToolFull(t, r, "jmsx_exec", map[string]any{})
	if !res.IsError {
		t.Fatal("the agent got no error for a failed call")
	}
	if len(got) != 1 {
		t.Fatalf("the gate recorded %d calls, want 1", len(got))
	}
	if got[0].Delivery != jms.Delivery_maybe_sent.String() {
		t.Errorf("the record says the delivery state is %q, want %q",
			got[0].Delivery, jms.Delivery_maybe_sent.String())
	}
	// The agent still gets a readable error — the state travels beside the
	// text, not instead of it.
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "may already be running") {
		t.Errorf("the agent got %q; the reason is missing", text)
	}
}

// An answer that violates its own contract must be a FAILED CALL, not a
// surprise the agent gets after the trail has already said "fine".
//
// The SDK checks the answer's shape too — but it checks it AFTER this chain
// has closed and the trail has been written. So a contract violation used to
// reach the agent as a transport error while the trail said "allowed,
// nothing wrong". The registry checks the answer itself, so the failure is
// a failed call: the trail records it, and the agent gets an error it can
// read.
func TestAnAnswerThatBreaksItsContractIsAFailedCall(t *testing.T) {
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{"jmsx_inventory": {Risk: jms.Risk_read}},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	type shape struct {
		Rows int `json:"rows,omitempty"`
	}
	type broken struct {
		Rows string `json:"rows,omitempty"`
	}
	Add(r, &mcp.Tool{
		Name:         "jmsx_inventory",
		Description:  "a tool whose answer breaks its own shape",
		OutputSchema: render.Schema[shape](),
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		// rows is a string; the declared shape says an integer.
		return &mcp.CallToolResult{}, broken{Rows: "not a number"}, nil
	})

	res := callToolFull(t, r, "jmsx_inventory", map[string]any{})
	if !res.IsError {
		t.Fatal("the agent got a normal answer for a broken one")
	}
	if len(got) != 1 {
		t.Fatalf("the gate recorded %d calls, want 1", len(got))
	}
	// The failure closes the call, so it arrives as the call's error — and
	// that is the channel the trail's `error` column reads.
	if got[0].Gate.Err == nil {
		t.Error("the record does not carry the failure")
	}
	if got[0].Gate.Allowed {
		t.Error("the record says the call was allowed; it failed")
	}
}

// A structured answer must reach the agent as structured content — AND the
// trail must say how big it was.
//
// ⚠️ The second half used to be a lie: the chain measures the size of the
// answer's TEXT, and a structured answer has no text (the answer is in
// structuredContent). So `out_bytes` was 0 for every tool that answers with
// data — "how big was the answer" read as "empty".
func TestAStructuredAnswerReachesTheAgentAndIsMeasured(t *testing.T) {
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{"jmsx_inventory": {Risk: jms.Risk_read}},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	type answer struct {
		Asset string `json:"asset,omitempty"`
		Rows  int    `json:"rows,omitempty"`
	}
	Add(r, &mcp.Tool{
		Name:        "jmsx_inventory",
		Description: "a tool that answers with data",
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"asset": map[string]any{"type": "string"},
				"rows":  map[string]any{"type": "integer"},
			},
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, answer{Asset: "node-071", Rows: 42}, nil
	})

	res := callToolFull(t, r, "jmsx_inventory", map[string]any{})
	if res.StructuredContent == nil {
		t.Fatal("the agent got no structured content")
	}
	var got2 answer
	switch raw := res.StructuredContent.(type) {
	case []byte:
		if err := json.Unmarshal(raw, &got2); err != nil {
			t.Fatalf("the structured content is not the answer: %v (%s)", err, raw)
		}
	case map[string]any:
		b, err := json.Marshal(raw)
		if err != nil {
			t.Fatalf("marshal the structured content: %v", err)
		}
		if err := json.Unmarshal(b, &got2); err != nil {
			t.Fatalf("the structured content is not the answer: %v (%s)", err, b)
		}
	default:
		t.Fatalf("the structured content is %T, want bytes or an object", res.StructuredContent)
	}
	if got2.Asset != "node-071" || got2.Rows != 42 {
		t.Errorf("the agent got %+v, want the answer", got2)
	}

	if len(got) != 1 {
		t.Fatalf("the gate recorded %d calls, want 1", len(got))
	}
	if got[0].Gate.OutBytes <= 0 {
		t.Errorf("the trail says the answer was %d bytes; a structured answer is not empty",
			got[0].Gate.OutBytes)
	}
}

// The arguments that reach the trail are scrubbed — and the payload fields
// are cut down BEFORE the shape rules, so the size that is reported is the
// size of what was passed.
//
// The order matters: a PEM private key is recognised by logredact and
// replaced by a remnant, so scrubbing the shapes first would leave the
// payload field holding a 21-byte remnant and the trail would report
// "21 bytes" for a 135-byte key.
func TestTheRegistryScrubsTheArgumentsBeforeTheCallback(t *testing.T) {
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	type payloadArgs struct {
		Confirm      bool   `json:"confirm,omitempty"`
		Message      string `json:"message,omitempty"`
		ContentBase6 string `json:"content_base64,omitempty"`
	}
	Add(r, &mcp.Tool{
		Name:        "jmsx_put_file",
		Description: "a tool that carries a payload",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args payloadArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})

	callTool(t, r, "jmsx_put_file", map[string]any{
		"message":        "hi",
		"content_base64": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",
	})
	if len(got) != 1 {
		t.Fatalf("the gate recorded %d calls, want 1", len(got))
	}
	args := got[0].Gate.Call.Args
	// ⚠️ The callback must NOT see the credential: the registry scrubs
	// before handing the record over, and that promise is the whole point
	// of the public API.
	if strings.Contains(args, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo") {
		t.Errorf("the callback saw the payload: %s", args)
	}
	// ⚠️ The registry DOES scrub, with the COMBINED scrubber: the shape
	// rules alone are not idempotent, but the combination is — so the
	// trail may scrub them again for its two exits without changing
	// them. ⇒ a callback of any kind receives them already masked.

	if !strings.Contains(args, "hi") {
		t.Errorf("the record threw away the useful part too: %s", args)
	}
}

// A call the SDK refuses BEFORE the tool runs must still leave a line.
//
// The SDK checks the input against the tool's input schema before it calls
// the tool — so a management-plane write without `confirm` is refused there,
// and the gate never runs. Without this the trail would have no line for it
// at all: the agent saw an error, the audit trail saw nothing.
//
// The line says: the call was STOPPED, it FAILED, and the gate never ran —
// so its stages are empty, which is how a reader tells it apart from a call
// the gate stopped (whose stages name the gate step that stopped it).
func TestACallRefusedBeforeTheToolStillLeavesALine(t *testing.T) {
	type strictArgs struct {
		// No omitempty: the SDK's schema makes it REQUIRED, so a call
		// without it is refused before the tool is called.
		Confirm bool   `json:"confirm"`
		Target  string `json:"target"`
	}
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	Add(r, &mcp.Tool{
		Name:        "jms_write",
		Description: "a tool that requires a confirmation",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args strictArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})

	res := callToolFull(t, r, "jms_write", map[string]any{"target": "x"})
	if !res.IsError {
		t.Fatal("the call was not refused")
	}
	if len(got) != 1 {
		t.Fatalf("the trail recorded %d lines, want 1", len(got))
	}
	rec := got[0]
	if rec.Gate.Call.Name != "jms_write" {
		t.Errorf("the line names %q, want jms_write", rec.Gate.Call.Name)
	}
	if rec.Gate.Allowed {
		t.Error("the line says the call was allowed; it was refused")
	}
	if rec.Gate.Err == nil {
		t.Error("the line does not say why the call was refused")
	}
	if len(rec.Gate.Stages) != 0 {
		t.Errorf("the line has gate stages (%d); the gate never ran", len(rec.Gate.Stages))
	}
	if rec.Gate.Call.Args == "" {
		t.Error("the line does not say what was attempted")
	}
}

// A call the tool DID see must leave exactly one line — the middleware must
// not add a second one.
func TestACallTheToolSawLeavesOneLine(t *testing.T) {
	type strictArgs struct {
		Confirm bool   `json:"confirm"`
		Target  string `json:"target"`
	}
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	Add(r, &mcp.Tool{
		Name:        "jms_write",
		Description: "a tool that requires a confirmation",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, args strictArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})

	res := callToolFull(t, r, "jms_write", map[string]any{
		"confirm": true,
		"target":  "x",
	})
	if res.IsError {
		t.Fatal("the call failed although the tool was reached")
	}
	if len(got) != 1 {
		t.Fatalf("the trail recorded %d lines, want 1", len(got))
	}
}

// The trail must not write down a value the arguments column refuses to.
//
// The SDK's validation message quotes the offending VALUE ("type:
// [hunter2] has type \"string\", want \"integer\""), so the reason a call was
// refused can carry a credential.
//
// The agent still gets that message — it sent those values. The trail gets
// the field path and nothing else.
func TestTheRefusalReasonCarriesNoValue(t *testing.T) {
	const secret = "hunter2-plaintext"
	type args struct {
		Target string `json:"target"`
		// A string, and the call passes an array: the SDK refuses it on
		// the input contract, before the tool is called.
		Password string `json:"password"`
	}
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	Add(r, &mcp.Tool{
		Name:        "jms_probe",
		Description: "a tool with a field that will not validate",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})

	res := callToolFull(t, r, "jms_probe", map[string]any{
		"target":   "x",
		"password": []string{secret},
	})
	if !res.IsError {
		t.Fatal("the call was not refused")
	}
	if len(got) != 1 {
		t.Fatalf("the trail recorded %d lines, want 1", len(got))
	}
	rec := got[0]
	if rec.Gate.Err == nil {
		t.Fatal("the line does not say why the call was refused")
	}
	if strings.Contains(rec.Gate.Err.Error(), secret) {
		t.Errorf("the line writes down the value it refused to write in the arguments: %q",
			rec.Gate.Err.Error())
	}
	if !strings.Contains(rec.Gate.Err.Error(), "password") {
		t.Errorf("the line does not say which field was wrong: %q", rec.Gate.Err.Error())
	}
}

// A value that LOOKS like a field path must not be taken for one.
//
// The paths are pulled out of the SDK's message, and the message quotes
// values — so a value containing "/properties/…" could be mistaken for a
// path and written down. Only a path that names a field the call really
// passed is kept.
func TestAValueThatLooksLikeAPathIsNotTakenForOne(t *testing.T) {
	const crafted = "/properties/secret"
	type args struct {
		Target string `json:"target"`
		// A string, and the call passes an array: the SDK refuses it on
		// the input contract, and the message quotes the array.
		Password string `json:"password"`
	}
	var got []Record
	r := newTestRegistry(t, Options{
		Policy: PolicyTable{},
		OnRecord: func(rec Record) {
			got = append(got, rec)
		},
	})
	Add(r, &mcp.Tool{
		Name:        "jms_probe",
		Description: "a tool with a field that will not validate",
	}, func(ctx context.Context, _ *mcp.CallToolRequest, a args) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{}, nil, nil
	})

	res := callToolFull(t, r, "jms_probe", map[string]any{
		"target":   "x",
		"password": []string{crafted},
	})
	if !res.IsError {
		t.Fatal("the call was not refused")
	}
	if len(got) != 1 {
		t.Fatalf("the trail recorded %d lines, want 1", len(got))
	}
	reason := got[0].Gate.Err.Error()
	if strings.Contains(reason, crafted) {
		t.Errorf("the line writes down a value that looked like a path: %q", reason)
	}
	if strings.Contains(reason, "secret") {
		t.Errorf("the line writes down a fragment of the value: %q", reason)
	}
}
