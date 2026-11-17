package reg

import (
	"context"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// TestReadOnlyRefusesEveryWriteEvenConfirmed is the kit#38 regression matrix.
//
// Read-only mode is documented as "refuse every write tool". The gate used to
// break that promise for every tool registered through Add: Add put each tool
// on guardx's AllowedTools whitelist, and the whitelist is a break-glass that
// is checked BEFORE the read-only interception. Conditional tools — the ones
// whose confirmation depends on the input, so policy.Confirm is empty — then
// took the checkStandard path, hit the whitelist, and ran even with
// JMS_READ_ONLY=1. Unconditional tools rode checkAlwaysAsk, which has no
// whitelist branch, and were refused correctly — which is why the hole went
// unnoticed.
//
// The matrix mirrors the execution plane's catalogue: the six conditional
// tools the issue names, plus the five unconditional ones as regression
// controls. Every one of them is called WITH confirm=true, because that is
// the invocation that used to reach the handler.
func TestReadOnlyRefusesEveryWriteEvenConfirmed(t *testing.T) {
	conditional := []string{
		"jmsx_exec",
		"jmsx_run",
		"jmsx_collect",
		"jmsx_collect_multi",
		"jmsx_exec_multi",
		"jmsx_bg_start",
	}
	unconditional := []string{
		"jmsx_put_file",
		"jmsx_put_dir",
		"jmsx_relay",
		"jmsx_relay_dir",
		"jmsx_bg_cancel",
	}

	table := PolicyTable{}
	for _, name := range conditional {
		table[name] = Policy{
			Risk:        jms.Risk_write,
			Conditional: true,
			Hint:        "confirm=true only when the input is classified DANGEROUS",
		}
	}
	for _, name := range unconditional {
		table[name] = Policy{
			Risk:    jms.Risk_destructive,
			Confirm: "set confirm=true to write",
		}
	}

	for _, tc := range []struct {
		mode    string
		opts    Options
		refused bool
	}{
		{"read-only", Options{ReadOnly: true, Policy: table}, true},
		// The control: outside read-only mode the confirmed calls must still
		// reach the handler, or the fix would be a blanket denial wearing a
		// read-only costume.
		{"default", Options{Policy: table}, false},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			r := newTestRegistry(t, tc.opts)
			ran := 0
			handler := func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
				ran++
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "HANDLER-RAN"}}}, nil, nil
			}
			for _, name := range append(append([]string{}, conditional...), unconditional...) {
				Add(r, &mcp.Tool{Name: name, Description: "write " + name}, handler)
			}

			// The root cause in one assertion: registration must not invent
			// operator trust. The whitelist is a break-glass an operator fills
			// in explicitly; a registry that populates it for every tool turns
			// the read-only switch into decoration.
			if len(r.gate.AllowedTools) != 0 {
				t.Errorf("registration put %d tools on the break-glass whitelist: %v",
					len(r.gate.AllowedTools), r.gate.AllowedTools)
			}

			for _, name := range append(append([]string{}, conditional...), unconditional...) {
				text, isErr := callTool(t, r, name, map[string]any{"confirm": true})
				if tc.refused {
					if !isErr {
						t.Errorf("%s: read-only mode let a confirmed write reach the handler: %s", name, text)
					}
					if strings.Contains(text, "HANDLER-RAN") {
						t.Errorf("%s: read-only mode ran the handler: %s", name, text)
					}
					if !strings.Contains(text, "read-only") && !strings.Contains(text, "只读") {
						t.Errorf("%s: refusal does not name read-only mode: %s", name, text)
					}
				} else {
					if isErr {
						t.Errorf("%s: default mode refused a confirmed write: %s", name, text)
					}
					if !strings.Contains(text, "HANDLER-RAN") {
						t.Errorf("%s: default mode did not reach the handler: %s", name, text)
					}
				}
			}

			wantRan := 0
			if !tc.refused {
				wantRan = len(conditional) + len(unconditional)
			}
			if ran != wantRan {
				t.Errorf("handler ran %d times, want %d", ran, wantRan)
			}
		})
	}
}

// TestReadOnlyStillAllowsReadsAfterWhitelistRemoval guards the other half of
// the contract: removing the implicit whitelist must not drag the read tools
// down with it.
func TestReadOnlyStillAllowsReadsAfterWhitelistRemoval(t *testing.T) {
	r := newTestRegistry(t, Options{
		ReadOnly: true,
		Policy: PolicyTable{
			"jmsx_inventory": {Risk: jms.Risk_read},
			"jmsx_get_file":  {Risk: jms.Risk_read},
		},
	})
	handler := func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "READ-RAN"}}}, nil, nil
	}
	for _, name := range []string{"jmsx_inventory", "jmsx_get_file"} {
		Add(r, &mcp.Tool{Name: name, Description: "read " + name}, handler)
	}

	for _, name := range []string{"jmsx_inventory", "jmsx_get_file"} {
		text, isErr := callTool(t, r, name, map[string]any{})
		if isErr {
			t.Errorf("%s: read-only mode refused a read: %s", name, text)
		}
		if !strings.Contains(text, "READ-RAN") {
			t.Errorf("%s: read did not reach the handler: %s", name, text)
		}
	}
}

// TestReadOnlyDenialOutranksAWhitelistedTool pins the ordering the issue is
// about: even if a future caller puts a write tool on the break-glass
// whitelist (operator configuration, not registration), read-only mode must
// still refuse it. The kit states the guarantee, so the kit enforces it
// before handing the verdict to a gate whose whitelist branch sits first.
func TestReadOnlyDenialOutranksAWhitelistedTool(t *testing.T) {
	r := newTestRegistry(t, Options{
		ReadOnly: true,
		Policy: PolicyTable{
			"jmsx_exec": {Risk: jms.Risk_write, Conditional: true},
		},
	})
	// Simulate the operator break-glass that guardx#58 keeps: the whitelist
	// is stronger than the mode *in guardx*, but not stronger than the kit's
	// read-only contract.
	r.gate.AllowedTools["jmsx_exec"] = true

	ran := false
	Add(r, &mcp.Tool{Name: "jmsx_exec", Description: "a conditional write"}, func(ctx context.Context, _ *mcp.CallToolRequest, in echoArgs) (*mcp.CallToolResult, any, error) {
		ran = true
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "HANDLER-RAN"}}}, nil, nil
	})

	text, isErr := callTool(t, r, "jmsx_exec", map[string]any{"confirm": true})
	if !isErr {
		t.Fatalf("read-only mode let a whitelisted write through: %s", text)
	}
	if ran {
		t.Fatalf("read-only mode ran a whitelisted write handler: %s", text)
	}
	if !strings.Contains(text, "read-only") && !strings.Contains(text, "只读") {
		t.Errorf("refusal does not name read-only mode: %s", text)
	}
}
