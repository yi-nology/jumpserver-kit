package render

import (
	"reflect"

	"github.com/oagentkit/guardx/invoke"
)

// Outcome is what an answer says about what ACTUALLY happened.
//
// The distinction it draws is the one a gate cannot draw for itself. The gate
// knows whether the call was allowed in; only the tool knows whether the
// command ran. A dangerous command without a confirmation reaches the tool —
// the gate cannot see what the command is — and the tool refuses it. So
// "the gate said yes" and "something ran" are two different facts, and an
// audit that only records the first one records a lie.
//
// The three cases it tells apart:
//
//   - the tool REFUSED: nothing ran, and the answer says why;
//   - it was a REHEARSAL: nothing ran, but that was what the caller asked
//     for — a rehearsal is not an attempt that was stopped, and recording it
//     as one is a false alarm on the very question the audit exists for;
//   - it RAN: the command went through.
//
// ⚠️ The VERDICT TABLE is upstream's (invoke.Outcome): `Refused` says the
// tool declined, `DryRun` says it rehearsed, and `Acted()` settles whether
// anything happened. This package keeps no second copy of that table — a
// second copy is a second thing to keep in step, and the one that drifts
// decides what the audit records.
//
// WouldExecute 上游的判定表自 guardx v0.17.0 起自己带这一格（#39/#41），答案
// 说了的会同步进嵌入的 invoke.Outcome——链上那份记录就是审计读的那份。
// 仍然留在本地的是 *bool 的「没说/说了不会跑」之分：留痕的 omitempty 靠它
// 区分，上游的裸 bool 表达不了「没说」。
//
// It is found by reflection rather than by a type switch because the answer's
// type is the tool's own contract type, and the caller must not have to know
// which one it is. The question is "what did this answer say happened", not
// "what shape does this tool answer with".
//
// The management plane's refusals never reach an answer at all: the gate
// stops them before the tool runs, so they are recorded as the gate's own
// verdict instead.
type Outcome struct {
	// Outcome is the upstream action-layer verdict, carried through as it
	// is so that the trail reads one copy of it (the one inside the
	// chain's own record) and not two.
	invoke.Outcome
	// WouldExecute says a rehearsal would have run the command had it been
	// confirmed.
	//
	// It is a POINTER because "the answer does not say" and "it would not
	// have run" are two different facts, and the trail must not report the
	// second one when it only knows the first: a contract type with no
	// would_execute field would otherwise claim "it would not have run" for
	// every rehearsal it describes.
	WouldExecute *bool
	// Failure is the answer's own account of what went wrong, when it has
	// one.
	//
	// Some tools report a failure INSIDE the answer (the multi-command ones
	// answer with the results of the commands that worked and say what
	// broke the rest). That answer is a successful call — the chain sees
	// no error — so without this the trail would record a failed call as a
	// clean success, which is the one answer the trail must never give
	// wrongly.
	Failure string
	// Delivery says how far the action got, when the answer says.
	//
	// It is the same wording as the trail's own column: "not_sent" (it
	// never left this process) or "maybe_sent" (it may already be running
	// on the machine). It is empty when the answer does not say — which
	// is NOT the same as "it did not get there".
	Delivery string
}

// OutcomeOf reads the outcome out of an answer.
//
// It returns nil when the answer says nothing about what happened: the tool
// declared no verdict, and upstream reads that as "undeclared" and settles it
// by the chain's own result (a call that closed cleanly acted, one that
// closed with an error did not).
func OutcomeOf(answer any) *Outcome {
	if answer == nil {
		return nil
	}
	v := reflect.ValueOf(answer)
	for v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	// A verdict needs somewhere to live: an answer with none of the three
	// fields is not declaring one.
	//
	// ⚠️ The names are GO field names, and that is what the reflection
	// matches. Thriftgo derives the Go name from the IDL name, so
	// renaming `dry_run` in the IDL moves the Go field too — and the
	// trail would stop reading it, silently. The mechanical guard in
	// internal/arch pins the names for that reason.
	blocked, hasBlocked := fieldByName(v, "Blocked")
	dryRun, hasDryRun := fieldByName(v, "DryRun")
	would, hasWould := fieldByName(v, "WouldExecute")
	failure, hasFailure := fieldByName(v, "Error")
	delivery, hasDelivery := fieldByName(v, "Delivery")
	// An answer that declares NONE of these is not declaring a verdict.
	//
	// The third one counts on its own: an answer that says only "this
	// would have run" is still telling the trail something. (No contract
	// type is shaped like that today — every one that carries
	// would_execute also carries dry_run — so this is the shape the rule
	// is written for, not one that currently occurs.)
	if !hasBlocked && !hasDryRun && !hasWould && !hasFailure && !hasDelivery {
		return nil
	}
	o := &Outcome{}
	o.Refused = stringField(blocked)
	o.DryRun = verdictFlag(dryRun)
	o.WouldExecute = optBoolField(would)
	o.Failure = stringField(failure)
	o.Delivery = stringField(delivery)
	// 上游的判定表（guardx v0.17.0 起，#39/#41）自己带这一格：凡答案说了的，同步进
	// 嵌入的 invoke.Outcome，让链上那份记录——而不是 kit 平行携带的副本——
	// 成为审计读的那一份。上游语义「只在演练时有意义」，所以非演练恒 false。
	// 本地 *bool 仍然保留：「答案没说」（nil）与「说了不会跑」（false）是
	// 两个事实，留痕的 omitempty 靠它区分——上游的裸 bool 表达不了。
	o.Outcome.WouldExecute = o.DryRun && o.WouldExecute != nil && *o.WouldExecute
	return o
}

// fieldByName finds a field by name, including one promoted from an embedded
// struct.
//
// It exists because reflect's own FieldByName PANICS when the name is
// promoted through a nil embedded pointer ("indirection through nil pointer
// to embedded struct"). The answers are the tools' own contract types —
// shapes nobody here controls — so a panic there must not be possible.
//
// ⚠️ Where the panic lands matters: this lookup used to run in the audit
// callback, where it escaped into the trail; it now runs in the chain's
// handler, where the upstream recovers it — so a mis-shaped answer would
// become a FAILED TOOL CALL rather than a bad trail line. A lookup that
// cannot panic is the right shape for both.
func fieldByName(v reflect.Value, name string) (reflect.Value, bool) {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == name {
			return v.Field(i), true
		}
		if !f.Anonymous {
			continue
		}
		// The field is embedded: look inside it — but only when it is
		// there. A nil embedded pointer has no fields to look at.
		inner := v.Field(i)
		if inner.Kind() == reflect.Pointer {
			if inner.IsNil() {
				continue
			}
			inner = inner.Elem()
		}
		if inner.Kind() != reflect.Struct {
			continue
		}
		if got, ok := fieldByName(inner, name); ok {
			return got, true
		}
	}
	return reflect.Value{}, false
}

// stringField reads a string field, whether it is a string or a pointer to
// one.
//
// Only strings count. A field called "Blocked" that holds something else —
// the management plane's OffendingIP.blocked is a bool meaning "this address
// is blacklisted" — is not a refusal, and reading it as one would put a
// false alarm in the trail.
func stringField(f reflect.Value) string {
	if !f.IsValid() {
		return ""
	}
	switch f.Kind() {
	case reflect.String:
		return f.String()
	case reflect.Pointer:
		if f.IsNil() {
			return ""
		}
		if f.Elem().Kind() == reflect.String {
			return f.Elem().String()
		}
	}
	return ""
}

// optBoolField reads a bool field into a pointer, keeping "absent" apart
// from "false".
//
// A contract type with no such field yields nil — the trail then says
// nothing, rather than claiming the command would not have run.
//
// ⚠️ A PLAIN bool is read too, and that is the hole the guard closes: a
// plain bool cannot say "not answered", so reading one here would give
// the trail a verdict the tool never gave. The mechanical guard in
// internal/arch requires the field to be a *bool in every contract type
// — the leniency here is covered there, not here.
func optBoolField(f reflect.Value) *bool {
	if !f.IsValid() {
		return nil
	}
	switch f.Kind() {
	case reflect.Bool:
		b := f.Bool()
		return &b
	case reflect.Pointer:
		if f.IsNil() {
			return nil
		}
		if f.Elem().Kind() == reflect.Bool {
			b := f.Elem().Bool()
			return &b
		}
	}
	return nil
}

// verdictFlag reads a bool verdict field, whether it is a bool or a pointer to one.
func verdictFlag(f reflect.Value) bool {
	if !f.IsValid() {
		return false
	}
	switch f.Kind() {
	case reflect.Bool:
		return f.Bool()
	case reflect.Pointer:
		if f.IsNil() {
			return false
		}
		if f.Elem().Kind() == reflect.Bool {
			return f.Elem().Bool()
		}
	}
	return false
}
