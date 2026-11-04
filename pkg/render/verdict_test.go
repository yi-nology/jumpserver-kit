package render

import (
	"testing"
)

// The two shapes the answers actually come in: a contract with the full
// verdict vocabulary (thrift optional fields, so pointers), and a leaner
// one that carries only part of it — the writer fills what is there and
// skips what is not, without an error either way.
type verdictFull struct {
	Risk         *string
	DryRun       *bool
	WouldExecute *bool
	Executed     *bool
	Blocked      *string
	Note         *string
}

type verdictLean struct {
	Risk    *string
	Blocked *string
	Note    *string
}

// A rehearsal fills the whole vocabulary it finds, and the blocked hint
// only when there is one.
func TestFillRehearsalFillsWhatTheAnswerCarries(t *testing.T) {
	a := &verdictFull{}
	FillRehearsal(a, "DANGEROUS", true, "set confirm=true", RehearsalNote)
	if a.Risk == nil || *a.Risk != "DANGEROUS" {
		t.Errorf("Risk = %v, want DANGEROUS", a.Risk)
	}
	if a.DryRun == nil || !*a.DryRun {
		t.Errorf("DryRun = %v, want true", a.DryRun)
	}
	if a.WouldExecute == nil || !*a.WouldExecute {
		t.Errorf("WouldExecute = %v, want true", a.WouldExecute)
	}
	if a.Executed == nil || *a.Executed {
		t.Errorf("Executed = %v, want false: a rehearsal executes nothing", a.Executed)
	}
	if a.Blocked == nil || *a.Blocked != "set confirm=true" {
		t.Errorf("Blocked = %v, want the hint", a.Blocked)
	}
	if a.Note == nil || *a.Note != RehearsalNote {
		t.Errorf("Note = %v, want the rehearsal note", a.Note)
	}

	// A rehearsal that needs no confirmation carries no hint — an empty
	// "blocked" would read as a refusal the caller never got.
	b := &verdictFull{}
	FillRehearsal(b, "READ", true, "", "")
	if b.Blocked != nil {
		t.Errorf("Blocked = %v, want unset: no hint, no field", *b.Blocked)
	}
	if b.Note != nil {
		t.Errorf("Note = %v, want unset: no note, no field", *b.Note)
	}

	// A type without the rehearsal vocabulary keeps what it has.
	c := &verdictLean{}
	FillRehearsal(c, "READ", true, "", "a note")
	if c.Risk == nil || *c.Risk != "READ" {
		t.Errorf("Risk = %v, want READ", c.Risk)
	}
	if c.Note == nil || *c.Note != "a note" {
		t.Errorf("Note = %v, want the note", c.Note)
	}
}

// A refusal is NOT a rehearsal and must not borrow its fields: no DryRun,
// no WouldExecute (absent is "not asked"), no Note — the blocked sentence
// is the answer.
func TestFillRefusalSaysRefusedAndOnlyThat(t *testing.T) {
	a := &verdictFull{}
	FillRefusal(a, "DANGEROUS", "set confirm=true to run it")
	if a.Risk == nil || *a.Risk != "DANGEROUS" {
		t.Errorf("Risk = %v, want DANGEROUS", a.Risk)
	}
	if a.Blocked == nil || *a.Blocked != "set confirm=true to run it" {
		t.Errorf("Blocked = %v, want the refusal sentence", a.Blocked)
	}
	if a.Executed == nil || *a.Executed {
		t.Errorf("Executed = %v, want false", a.Executed)
	}
	if a.DryRun != nil {
		t.Errorf("DryRun = %v, want unset: a refusal is not a rehearsal", *a.DryRun)
	}
	if a.WouldExecute != nil {
		t.Errorf("WouldExecute = %v, want unset: not asked", *a.WouldExecute)
	}
	if a.Note != nil {
		t.Errorf("Note = %v, want unset: the blocked sentence is the answer", *a.Note)
	}
}

// What the writer writes, the reader reads back: FillRehearsal and
// FillRefusal produce answers whose OutcomeOf is the verdict that was
// filled — the two ends of the convention cannot drift apart if the round
// trip is pinned.
func TestTheFilledVerdictRoundTripsThroughOutcomeOf(t *testing.T) {
	a := &verdictFull{}
	FillRehearsal(a, "DANGEROUS", false, "set confirm=true", RehearsalNote)
	o := OutcomeOf(a)
	if o == nil {
		t.Fatal("OutcomeOf found no verdict in a filled rehearsal")
	}
	if o.Refused != "set confirm=true" {
		t.Errorf("Refused = %q, want the hint", o.Refused)
	}
	if !o.DryRun {
		t.Error("DryRun = false, want true: the trail would read this rehearsal as a refusal")
	}
	if o.WouldExecute == nil || *o.WouldExecute {
		t.Errorf("WouldExecute = %v, want false", o.WouldExecute)
	}

	b := &verdictFull{}
	FillRefusal(b, "DANGEROUS", "set confirm=true to run it")
	o = OutcomeOf(b)
	if o == nil {
		t.Fatal("OutcomeOf found no verdict in a filled refusal")
	}
	if o.Refused != "set confirm=true to run it" {
		t.Errorf("Refused = %q, want the sentence", o.Refused)
	}
	if o.DryRun {
		t.Error("DryRun = true, want false: a refusal must not read as a rehearsal")
	}
}
