package render

import (
	"fmt"
	"reflect"
)

// The verdict writers — the filling counterpart of OutcomeOf's reading.
//
// The two planes spell a rehearsal ("classified, and here is whether it
// would run") and a refusal ("it did not run, and here is what to do about
// it") the same way at seven call sites between them, and the contract
// types carrying those fields are thrift-generated: no methods can hang
// off them, and a per-type setter table would reintroduce the very drift
// (a field name typed as a string) that contract types exist to prevent.
//
// So the filling is done by reflection over the SAME Go field names
// OutcomeOf reads — Blocked, DryRun, WouldExecute, Risk, Executed, Note —
// with one spelling of each verdict, once, for both planes. A field the
// answer's type does not carry is skipped: the verdict conventions (and
// the guard that pins them, CheckVerdictConvention) decide which fields a
// contract must carry, not this writer.

// RehearsalNote is the one sentence that says what a rehearsal is.
//
// Both planes used to spell it each; two spellings of "nothing was
// executed" is one spelling too many.
const RehearsalNote = "dry run: nothing was executed"

// FillRehearsal fills a DRY-RUN answer: the command was classified and
// answered, nothing was executed.
//
// It sets Risk, DryRun, WouldExecute and Executed (each when the answer's
// type carries it), the note verbatim, and the blocked hint only when
// there is one — a rehearsal that needs no confirmation carries no hint,
// and an empty "blocked" would read as a refusal the caller never got.
func FillRehearsal(answer any, riskClass string, would bool, blocked, note string) {
	setString(answer, "Risk", riskClass)
	setBool(answer, "DryRun", true)
	setBool(answer, "WouldExecute", would)
	setBool(answer, "Executed", false)
	if blocked != "" {
		setString(answer, "Blocked", blocked)
	}
	if note != "" {
		setString(answer, "Note", note)
	}
}

// FillRefusal fills a REFUSED answer: the command needed a confirmation
// the caller did not give, so nothing ran.
//
// It sets Risk, Executed (when the type carries them) and the blocked
// sentence. It deliberately sets NOTHING ELSE: no DryRun (this was not a
// rehearsal), no WouldExecute (an absent answer is "not asked", and a
// refusal is not the place to say "it would have run if asked" — the
// rehearsal is), no Note.
func FillRefusal(answer any, riskClass, blocked string) {
	setString(answer, "Risk", riskClass)
	setBool(answer, "Executed", false)
	setString(answer, "Blocked", blocked)
}

// setString writes a string verdict field by its Go name, when the answer
// carries it.
//
// The field may be a plain string or a pointer to one: thrift optional
// fields are pointers ("not answered" is a state worth keeping), and a
// plain field cannot say it — both spellings are filled the same way.
func setString(answer any, name, val string) {
	f, ok := verdictField(answer, name)
	if !ok {
		return
	}
	if f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.String {
		if f.IsNil() {
			f.Set(reflect.New(f.Type().Elem()))
		}
		f.Elem().SetString(val)
		return
	}
	if f.Kind() == reflect.String {
		f.SetString(val)
	}
}

// setBool writes a boolean verdict field by its Go name, when the answer
// carries it. See setString for the pointer/plain distinction.
func setBool(answer any, name string, val bool) {
	f, ok := verdictField(answer, name)
	if !ok {
		return
	}
	if f.Kind() == reflect.Pointer && f.Type().Elem().Kind() == reflect.Bool {
		if f.IsNil() {
			f.Set(reflect.New(f.Type().Elem()))
		}
		f.Elem().SetBool(val)
		return
	}
	if f.Kind() == reflect.Bool {
		f.SetBool(val)
	}
}

// verdictField finds a verdict field by its Go name on the answer's
// struct. It demands a struct (or a pointer to one): a verdict on anything
// else is a caller bug, and the one thing this writer must not do is fail
// silently about it.
func verdictField(answer any, name string) (reflect.Value, bool) {
	if answer == nil {
		panic(fmt.Sprintf("render.FillVerdict: nil answer (setting %s)", name))
	}
	v := reflect.ValueOf(answer)
	if v.Kind() != reflect.Pointer {
		panic(fmt.Sprintf("render.FillVerdict: answer must be a pointer, got %s (setting %s)", v.Kind(), name))
	}
	v = v.Elem()
	if v.Kind() != reflect.Struct {
		panic(fmt.Sprintf("render.FillVerdict: answer must point at a struct, got %s (setting %s)", v.Kind(), name))
	}
	// The safe lookup, not reflect's own FieldByName: that one panics on a
	// name promoted through a nil embedded pointer, and the answers are
	// shapes nobody here controls (see outcome.go's fieldByName).
	f, ok := fieldByName(v, name)
	if !ok || !f.CanSet() {
		return reflect.Value{}, false
	}
	return f, true
}
