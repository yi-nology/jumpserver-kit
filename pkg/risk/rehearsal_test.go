package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// The rehearsal's judgement and its sentence are a cross-server contract:
// both planes answer "would this run?" through THIS function, so the words
// cannot drift between them (one plane used to hard-code "DANGEROUS" into a
// sentence that was supposed to name the class it actually found).
func TestRehearsal(t *testing.T) {
	// A command that needs no confirmation runs, and says nothing about
	// confirmation.
	would, blocked := Rehearsal(jms.CommandClass_READ, false)
	if !would || blocked != "" {
		t.Errorf("READ without confirm = (%v, %q), want (true, \"\")", would, blocked)
	}
	// A DANGEROUS command without the confirmation does not run, and the
	// sentence names the class it found and what to do about it.
	would, blocked = Rehearsal(jms.CommandClass_DANGEROUS, false)
	if would {
		t.Error("DANGEROUS without confirm must not run")
	}
	if want := "classified DANGEROUS; re-call with confirm=true to execute"; blocked != want {
		t.Errorf("blocked = %q, want %q", blocked, want)
	}
	// With the confirmation it runs, and the hint is gone.
	would, blocked = Rehearsal(jms.CommandClass_DANGEROUS, true)
	if !would || blocked != "" {
		t.Errorf("DANGEROUS with confirm = (%v, %q), want (true, \"\")", would, blocked)
	}
	// The sentence names the class it was given, whatever that class is:
	// the words come from the class, not from a constant.
	_, blocked = Rehearsal(jms.CommandClass_MODIFY, false)
	if blocked != "" {
		t.Errorf("MODIFY must need no confirmation, got %q", blocked)
	}
}
