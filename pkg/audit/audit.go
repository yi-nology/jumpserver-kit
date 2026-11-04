package audit

// audit.go is the trail both servers keep.
//
// One line per tool call: what was called, what the gate decided, what the
// tool's own answer says happened, how long it took, and what came back.
//
// It lives in the shared base because it is the SAME trail for both servers:
// the gate is shared, so the gate's voice should be too. Two copies of this
// function would drift, and the one that drifts is the one that decides what
// gets recorded — which is the last place a difference should hide.
//
// Why the execution plane needs it as much as the management plane: a
// DANGEROUS command refused for want of a confirmation never reaches the
// bastion, so the bastion has no session to show for it. Without a local
// trail, "who tried to run rm -rf on that box and was stopped" is
// unanswerable — the refusal leaves no trace anywhere.

import (
	"strings"

	"github.com/oagentkit/guardx/invoke"
	"github.com/oekit/logx"

	"github.com/yi-nology/jumpserver-kit/pkg/fspath"
	"github.com/yi-nology/jumpserver-kit/pkg/redact"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/textx"
)

// Settings is where the trail goes.
//
// It is configured by the server's own configuration package (conf/<服务>/),
// because that is where configuration lives in this repository — and the
// trail is configured the same way for both servers, so the two cannot drift.
type Settings struct {
	// Mode is "file" or "off".
	Mode string
	// Dir is where the trail files are written.
	Dir string
	// RetentionDays is how many days of trail files are kept.
	//
	// Zero means "keep them": the trail is one file per process, so the
	// directory grows with the number of restarts, and every query that
	// scans it pays for the whole history.
	//
	// ⚠️ Empty files are always pruned (once they are quiet for an hour),
	// whatever this says: an empty file is a fact about nothing.
	RetentionDays int
}

// TrailDir is where the trail files are, or "" when the file trail is off.
//
// The mode "off" means no file trail at all: an empty directory is how the
// sink is told to write to the log only.
//
// The home directory is expanded HERE, so that everyone who asks where the
// trail is gets the same answer — the doctor included, which would
// otherwise stat a literal "~" and report a directory that does not exist.
func (s Settings) TrailDir() string {
	if s.Mode != "file" {
		return ""
	}
	return fspath.ExpandHome(strings.TrimSpace(s.Dir))
}

// Options turns the settings into the trail's options.
func (s Settings) Options(service string) Options {
	return Options{Service: service, Dir: s.TrailDir(), RetentionDays: s.RetentionDays}
}

// Options configure the trail.
type Options struct {
	// Service is the name the server registers under, so the lines from
	// the two servers can be told apart in one log.
	Service string
	// Dir is where the trail file is written. An empty Dir means the trail
	// goes to the log only — that is what "the file trail is off" means.
	Dir string
	// RetentionDays is how many days of trail files are kept. Zero keeps
	// them all.
	RetentionDays int
}

// Trail returns the sink that writes one line per tool call.
//
// The line goes to the log AND to the trail file: the log is where an
// operator reads it while the server runs, and the file is where it can be
// found afterwards — which is the half that matters for a call that did NOT
// run, because such a call never reached the bastion and left no trace
// there. See file.go.
//
// The verdict written down is the one an operator cares about: did the call
// DO something? A call the gate stopped and a call the tool refused are both
// "did not happen", and the second one is invisible in the gate's own stages
// — the gate let it through, the tool did not.
func Trail(opts Options) func(reg.Record) {
	log := logx.WithService(opts.Service)
	file := openTrail(opts)
	return func(rec reg.Record) {
		gate := rec.Gate
		// ⚠️ The arguments are scrubbed HERE, at the sink, and not only
		// by the registry that hands them over.
		//
		// The trail's guarantee is "what is written down is scrubbed",
		// and a guarantee that lives in the CALLER is not the trail's
		// guarantee: a second caller (or a test) would write the raw
		// arguments, and the line would carry a password while every
		// other column of it was scrubbed — the reader has no way to
		// tell which is which.
		//
		// ⚠️ The registry scrubs them too, before handing the record
		// over. That is safe because the COMBINED scrubber is idempotent
		// (on valid JSON) — the shape rules alone are not.
		gate.Call.Args = scrubArgs(gate.Call.Args)
		rec.Gate = gate
		fields := []any{
			"tool", gate.Call.Name,
			// WHO asked. The trail says what was attempted and why it
			// was stopped; without this it cannot say which client did
			// it, and two agents on one machine are indistinguishable.
			//
			// The key is "client" and not "caller" because logx already
			// writes a "caller" of its own — the source location of the
			// log line — and two keys with the same name in one JSON
			// object are read differently by different parsers.
			"client", clientName(gate.Call.Caller),
			// WHAT was attempted, not just which tool: on the execution
			// plane the tool is "jmsx_exec" and the attempt is the command.
			// Without the arguments the trail says a command ran and not
			// which one — and a command refused for want of a confirmation
			// never reaches the bastion, so there is nowhere else to look.
			//
			// The arguments are scrubbed right here (a tool
			// call can carry a password or a private key) and the heavy
			// payloads are cut down to their size by the same scrubber.
			"args", truncate(gate.Call.Args, 500),
			// Two layers, one field: the gate's verdict (did the call get
			// through) AND the action-layer verdict (did anything
			// actually happen). A call the gate stopped never reaches
			// the tool, and a call the tool refused reached it and did
			// nothing — both are "did not happen", and the second one is
			// invisible in the gate's own stages.
			//
			// ⚠️ Read it as "was NOT refused", NOT as "it ran fine":
			//   - false ⇒ nothing ran (the gate stopped it, the tool
			//     refused it, or it was a rehearsal);
			//   - true ⇒ it was not refused — but it may still have
			//     FAILED (see the `failed` and `error` fields), and
			//     whether the command reached the machine is the
			//     `delivery` field's business.
			"allowed", allowed(rec),
			"duration_ms", gate.Duration.Milliseconds(),
			"out_bytes", gate.OutBytes,
		}
		// The refusal and the rehearsal are told apart, because they are
		// not the same event: one was stopped, the other was asked for. A
		// rehearsal recorded as a refusal is a false alarm on the very
		// question this trail exists to answer.
		if refused(gate) {
			fields = append(fields, "refused", refusedText(gate.Outcome.RefusalReason()))
		}
		if gate.DryRun() {
			fields = append(fields, "dry_run", true)
			// Only when the answer actually said: a contract type with
			// no would_execute field must not make the log claim the
			// rehearsal would not have run.
			if rec.WouldExecute != nil {
				fields = append(fields, "would_execute", *rec.WouldExecute)
			}
		}
		for _, st := range gate.Stages {
			fields = append(fields,
				"stage."+st.Stage, st.Allow,
				"stage."+st.Stage+".reason", reasonText(st.Reason))
		}
		switch {
		case gate.Err != nil:
			fields = append(fields, "error", failureText(gate.Err.Error()))
		case rec.ToolError != "":
			// The tool answered with an error result. That is still a
			// successful PROTOCOL call, so the chain saw no error and
			// nothing else would say the call failed — without this, a
			// command that died half way through reads exactly like one
			// that ran fine.
			fields = append(fields, "error", failureText(rec.ToolError))
		case rec.Failure != "":
			// The tool reported the failure INSIDE the answer (the
			// multi-command ones answer with the results that worked and
			// say what broke the rest). The call itself succeeded, so
			// without this a broken command reads as a clean success.
			fields = append(fields, "error", failureText(rec.Failure))
		}
		// The failure is told apart from the gate's stop: the first is a
		// broken call, the second is the gate working.
		if toolFailed(rec) {
			fields = append(fields, "failed", true)
		}
		// How far the action got, when the error knew. This is the answer
		// to "is it still running on that machine?" — the one a caller
		// cannot work out for itself after a failure.
		if rec.Delivery != "" {
			fields = append(fields, "delivery", rec.Delivery)
		}
		log.Info("tool call", fields...)
		file.write(rec)
	}
}

// allowed says whether the call was STOPPED.
//
// It is "not stopped", not "did what was asked": a call that BROKE is not a
// stopped call — it went through and failed. The gate's own verdict is in
// stages[] (a stage with allow=false is what stopped it), and the failure
// is in the `failed` and `error` columns.
//
// ⚠️ A REFUSAL comes first: a call the tool refused was stopped, whatever
// else the answer says. The two cannot happen together today (a refusal and
// a failure are different branches), but the answer types have room for
// both, and "not stopped" and "the tool refused it" must never share a
// line.
func allowed(rec reg.Record) bool {
	if refused(rec.Gate) {
		return false
	}
	if rec.StoppedEarly {
		// The call was stopped before the tool ran — the SDK refused it
		// on its input contract. Nothing ran, and the agent got an
		// error: it was stopped, not "it ran and broke".
		return false
	}
	if toolFailed(rec) {
		return true
	}
	return rec.Gate.Allowed && rec.Gate.Acted()
}

// toolFailed says whether the TOOL's work failed.
//
// It answers "what broke here", and the gate stopping a call is NOT part of
// it: the gate stopping something is the gate working, and nothing ran in
// either case — but only one of them is a broken call.
//
// ⚠️ How the gate's stop is recognised — by TWO independent signs, so that
// neither can be faked by a tool:
//
//   - the STAGE TRAIL: a stage that says "no" is the gate's own product
//     (the tool cannot produce one);
//   - the error's EXACT type: the chain returns the gate's denial as
//     `*invoke.DenyError` and nothing else, while a tool error that
//     happens to WRAP one is a different type — so it is not read as the
//     gate's wording ("the gate stopped it" when it did not).
//
// Either sign alone would do; both together mean neither can be faked.
func toolFailed(rec reg.Record) bool {
	// The tool said so — either with an error result or inside its
	// answer.
	if rec.ToolError != "" || rec.Failure != "" {
		return true
	}
	gate := rec.Gate
	if gate.Err == nil {
		return false
	}
	for _, st := range gate.Stages {
		if !st.Allow {
			// The gate stopped it.
			return false
		}
	}
	if _, isDeny := gate.Err.(*invoke.DenyError); isDeny {
		// The gate stopped it, and the trail says so in the stages.
		return false
	}
	return true
}

// maxColumn is how long a free-text column may be in the trail.
//
// The lines have to stay small. Two reasons: a reader that meets a huge
// line must be able to skip it and carry on (a huge line is not worth
// losing the rest of the file over), and a trail that holds megabytes of
// prose is not evidence — it is noise.
const maxColumn = 4096

// clip cuts a free-text column to a length the trail can carry.
//
// It cuts on a RUNE boundary (the same reason the arguments do — the cut
// is made in pkg/textx, the one place it lives): a byte cut that lands
// inside a multi-byte character would put invalid UTF-8 into the file, and
// the JSON encoder turns that into U+FFFD — so the column would not be
// the text that was said.
func clip(s string, n int) string {
	return textx.Trunc(s, n, "…(clipped)")
}

// refusedText is the refusal reason as the trail writes it.
//
// ⚠️ The LOG side and the FILE side call THIS function, not their own
// copy of the expression: two copies of "clip then scrub" are two water
// levels waiting to happen — and once they differ, the same fact is
// written at two lengths in two places, and nobody can tell which is
// which.
func refusedText(reason string) string {
	return clip(scrub(reason), maxColumn)
}

// reasonText is one gate stage's reason as the trail writes it.
//
// Same one-definition rule as refusedText.
func reasonText(reason string) string {
	return clip(scrub(reason), maxColumn)
}

// failureText is the failure's text without the protocol decoration.
//
// The tool's error result carries an "ERROR: " prefix — that prefix is
// for the model, and writing it into the audit column would make every
// failure read like a protocol artefact instead of a sentence.
// failureText is the failure's text as the trail writes it.
//
// Two things happen here, and the second one matters more than it looks:
//
//   - the "ERROR: " prefix is dropped: it is the protocol's decoration for
//     the model, not a sentence an operator reads;
//   - ⚠️ the text goes through the SAME redaction as the arguments. The
//     SDK's input validation quotes the offending VALUE ("type: [hunter2]
//     has type \"string\", want \"integer\""), so a rejected call's reason
//     can carry a secret — and the arguments column is scrubbed for
//     exactly that reason. The error column must be on the same water
//     line, or the trail would write down a credential the arguments
//     column refused to write.
func failureText(text string) string {
	return clip(scrub(strings.TrimPrefix(text, "ERROR: ")), maxColumn)
}

// scrub scrubs the credentials out of a piece of free text.
//
// EVERY free-text column goes through it: the arguments, the error, the
// refusal reason, the gate's own reasons. A column that skipped it would
// be the one place a credential survives — and a reader who sees the
// arguments column scrubbed has every reason to believe the whole line is.
//
// ⚠️ The refusal reason and the gate's reasons come from the SAME answer
// and the SAME gate as the error, and the error IS scrubbed. A tool whose
// answer carries both `error` and `blocked` therefore had one of them
// scrubbed and the other written down in full — two columns of one line,
// two water levels, and no way for the reader to tell which is which.
//
// The rules are shape-based (a `password: …` pair, a PEM block, a bearer
// token), so an ordinary sentence comes through untouched.
func scrub(text string) string {
	// ⚠️ The credential-key backstop runs on EVERY free-text column, not
	// only on the arguments: the upstream scrubber leaves the same holes
	// everywhere, and a column that was masked while its neighbour was not
	// is two water levels in one line.
	return redact.Scrub(text)
}

// scrubArgs scrubs the ARGUMENTS, and is safe to run twice.
//
// ⚠️ The scrubber is NOT idempotent on its own: logredact rewrites
// `"password":"x"` into `"password=****` — it eats the closing quote,
// so the result is no longer valid JSON, and a SECOND pass eats the
// separator after the marker too (`{"password=****,"tool":…` becomes
// `{"password=****"tool":…`).
//
// ⚠️ The arguments are scrubbed here, and the two exits read the same
// value — so the log line and the file line are byte-identical.
//
// ⚠️ The registry scrubs them as well, and that is safe because the
// COMBINED scrubber is idempotent on valid JSON: the shape rules alone
// are not (they eat the closing quote of the value they mask, and a
// second pass eats the separator after that).
//
// ⚠️ ⚠️ The guarantee is about credentials in QUOTED KEY-VALUE PAIRS whose
// KEY is in the backstop's word list: a credential the upstream rules
// cannot match at all — one containing `&`, or one in prose, or one in an
// escaped JSON string — is outside it, and the prose shape is outside it
// in EVERY column.
func scrubArgs(text string) string {
	return scrub(text)
}

// truncate keeps a trail line readable.
//
// The arguments are the interesting part, but a tool call can carry a long
// command or a long list; the tail of it is not what an operator is looking
// for when they read the line.
//
// ⚠️ The cut is on a RUNE boundary, not a byte boundary. A byte slice that
// lands inside a multi-byte character leaves invalid UTF-8 behind, and the
// JSON encoder turns those bytes into U+FFFD — so the trail would store a
// DIFFERENT string from the one that was called, and the operator reading
// the evidence would see a replacement character where the command had one.
// The repository has fixed this exact bug three times (the answers, the
// client name, this copy) — which is why the cut now lives in pkg/textx,
// the one place it is made.
func truncate(s string, n int) string {
	return textx.Trunc(s, n, "…(truncated)")
}

// refused reports whether the tool REFUSED the action — as opposed to
// rehearsing it.
//
// The two are told apart on purpose. A rehearsal carries the hint of what a
// confirmation would do, and upstream's Record.Refused() answers "did the
// tool decline" — true for that rehearsal too. The trail's question is
// narrower: was this an attempt that was STOPPED? A rehearsal recorded as a
// refusal is a false alarm on the very question the trail exists to answer.
//
// The verdict itself is upstream's (invoke.Record.Refused / DryRun); only
// this policy — how the trail reads the two — is local, and it is written
// here once because two copies of it would drift, and the drifted one is the
// one that decides what gets recorded.
func refused(gate invoke.Record) bool {
	return gate.Refused() && !gate.DryRun()
}
