package render

import "testing"

// The lookup for the verdict must not be able to panic.
//
// The answers are the tools' own contract types — shapes nobody here
// controls — and reflect's own FieldByName PANICS when the field it is
// asked for is promoted through a NIL embedded pointer ("indirection through
// nil pointer to embedded struct").
//
// ⚠️ Where that panic lands matters: the lookup used to run in the audit
// callback, where it escaped into the trail; it now runs in the chain's
// handler, where the upstream recovers it — so a mis-shaped answer would
// become a FAILED TOOL CALL instead of a bad trail line. Either way the
// answer is "no verdict", not "the process is in trouble".
func TestTheVerdictLookupCannotPanicOnANilEmbeddedPointer(t *testing.T) {
	type inner struct {
		Blocked *string
	}
	type answer struct {
		*inner
		DryRun *bool
	}

	// The embedded pointer is nil: there is no Blocked field to read.
	got := OutcomeOf(&answer{})
	if got == nil {
		// No verdict at all — DryRun is there, but a nil one says nothing.
		return
	}
	if got.Refused != "" {
		t.Errorf("a nil embedded pointer produced a refusal: %q", got.Refused)
	}
	if got.DryRun {
		t.Error("a nil pointer produced a rehearsal")
	}
}

// A verdict that is there has to be found, and the shapes that carry it are
// the ones the contract generates: a string pointer, a bool pointer, and
// their value forms.
func TestTheVerdictIsFoundInEveryShapeTheContractsUse(t *testing.T) {
	reason := "classified DANGEROUS"
	yes := true
	cases := []struct {
		name   string
		answer any
	}{
		{"string pointer", &struct{ Blocked *string }{Blocked: &reason}},
		{"string value", &struct{ Blocked string }{Blocked: reason}},
		{"bool pointer", &struct{ DryRun *bool }{DryRun: &yes}},
		{"bool value", &struct{ DryRun bool }{DryRun: true}},
	}
	for _, c := range cases {
		got := OutcomeOf(c.answer)
		if got == nil {
			t.Errorf("%s: no verdict was found", c.name)
			continue
		}
		if c.name == "bool pointer" || c.name == "bool value" {
			if !got.DryRun {
				t.Errorf("%s: the rehearsal was not found", c.name)
			}
			continue
		}
		if got.Refused != reason {
			t.Errorf("%s: the refusal was not found: %q", c.name, got.Refused)
		}
	}
}

// An answer that declares nothing is not a verdict.
func TestAnAnswerWithoutAVerdictDeclaresNone(t *testing.T) {
	got := OutcomeOf(&struct {
		Asset string
	}{Asset: "10.0.0.1"})
	if got != nil {
		t.Errorf("an answer with no verdict field produced one: %+v", got)
	}
	if OutcomeOf(nil) != nil {
		t.Error("a nil answer produced a verdict")
	}
}

// The upstream收编 (guardx v0.17.0+, issue #39 in oagentkit/guardx): an
// answer that declares a rehearsal's would-execute MUST propagate it into
// the EMBEDDED invoke.Outcome — the chain's record is what the trail reads,
// and a verdict that lives only in kit's parallel *bool never reaches the
// upstream layer at all.
func TestWouldExecutePropagatesIntoTheUpstreamOutcome(t *testing.T) {
	yes := true
	cases := []struct {
		name string
		in   any
		want bool
	}{
		{"a rehearsal that would run", &struct {
			DryRun       bool
			WouldExecute bool
		}{DryRun: true, WouldExecute: true}, true},
		{"a rehearsal one confirm short", &struct {
			DryRun       bool
			WouldExecute bool
		}{DryRun: true, WouldExecute: false}, false},
		{"not a rehearsal", &struct {
			WouldExecute bool
		}{WouldExecute: true}, false}, // upstream: 非演练恒 false
		{"unsaid stays unsaid", &struct {
			DryRun bool
		}{DryRun: true}, false},
	}
	for _, c := range cases {
		got := OutcomeOf(c.in)
		if got == nil {
			t.Fatalf("%s: no verdict was found", c.name)
		}
		if got.Outcome.WouldExecute != c.want {
			t.Errorf("%s: upstream WouldExecute = %v, want %v (local *bool = %v)",
				c.name, got.Outcome.WouldExecute, c.want, got.WouldExecute)
		}
	}
	// 指针形态也要走到上游。
	got := OutcomeOf(&struct {
		DryRun       *bool
		WouldExecute *bool
	}{DryRun: &yes, WouldExecute: &yes})
	if got == nil || !got.Outcome.WouldExecute {
		t.Errorf("pointer shape: upstream WouldExecute = %v, want true", got.Outcome.WouldExecute)
	}
}
