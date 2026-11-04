package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/oagentkit/guardx/invoke"
	"github.com/oekit/logx"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// The trail is the only record of a call that did NOT run: such a call never
// reaches the bastion, so the bastion has no session and no log line for it.
// That is why the trail has to land in a FILE and not only in the log.
//
// The test therefore does the whole round trip: a record goes in through the
// same sink the servers use, and comes back out through the same reader.

func TestTheTrailLandsInAFile(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	trail(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{
				Name:   "jmsx_exec",
				Server: "jumpserver-exec",
				Args:   `{"asset":"node-071","command":"rm -rf /var/lib/x"}`,
			},
			Allowed:  true,
			Duration: 12 * time.Millisecond,
			OutBytes: 0,
			Stages: []invoke.StageResult{
				{Stage: "capability", Allow: true, Reason: "白名单放行: jmsx_exec"},
			},
			Outcome: &invoke.Outcome{Refused: "classified DANGEROUS; re-call with confirm=true to execute"},
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if total != 1 {
		t.Fatalf("read %d lines, want 1", total)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1: %+v", len(entries), entries)
	}
	e := entries[0]
	if e.Tool != "jmsx_exec" {
		t.Errorf("the line says the tool is %q", e.Tool)
	}
	if e.Service != "jumpserver-exec" {
		t.Errorf("the line says the service is %q", e.Service)
	}
	if e.Allowed {
		t.Error("the line says the call was allowed; it was refused")
	}
	if e.Refused == "" {
		t.Error("the line does not say that the tool refused")
	}
	if e.DryRun {
		t.Error("the line says the call was a rehearsal; it was a refusal")
	}
	if e.DurationMs != 12 {
		t.Errorf("the line says %dms, want 12ms", e.DurationMs)
	}
	if e.Error != "" {
		t.Error("the line reports an error; the tool refused, it did not fail")
	}
	if len(e.Stages) != 1 {
		t.Fatalf("the line has %d stages, want 1", len(e.Stages))
	}
	if e.Stages[0].Stage != "capability" || !e.Stages[0].Allow {
		t.Errorf("the stage says %+v", e.Stages[0])
	}
	if e.Ts == "" {
		t.Error("the line has no timestamp")
	}
	if _, err := time.Parse(time.RFC3339Nano, e.Ts); err != nil {
		t.Errorf("the timestamp %q is not a timestamp: %v", e.Ts, err)
	}
}

// A rehearsal is NOT a refusal.
//
// This is the false alarm that matters: the trail exists to answer "who
// tried to run rm -rf and was stopped", and a rehearsal recorded as a
// refusal answers that question with a lie. The two have to be tellable
// apart, or the trail is worse than no trail.
func TestARehearsalIsNotARefusal(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
			Outcome: &invoke.Outcome{
				// The rehearsal's answer carries a blocked field too — the
				// hint of what would happen with a confirmation — and the
				// trail must not read that as a refusal.
				Refused: "classified DANGEROUS; re-call with confirm=true to execute",
				DryRun:  true,
			},
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	e := entries[0]
	if e.Refused != "" {
		t.Errorf("the line calls a rehearsal a refusal: %q", e.Refused)
	}
	if !e.DryRun {
		t.Error("the line does not say the call was a rehearsal")
	}
	if e.Allowed {
		t.Error("the line says the call was allowed; a rehearsal ran nothing")
	}

	// And the refusals filter must not pick it up.
	refused := true
	res, err = Read(ReadOptions{Dir: dir, Refused: &refused})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the refusals filter picked up a rehearsal: %+v", entries)
	}
}

// A failed call must not read in the trail like one that ran fine.
//
// The tool answered with an error result, which is still a successful
// PROTOCOL call — so the chain saw no error and the gate's own record has
// nothing to say about it. Without this column the line would read
// "allowed=true, no error", and a command that died half way through would
// look exactly like one that ran.
func TestAFailedCallCarriesItsFailure(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		},
		ToolError: "ERROR: the command died half way through",
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	if entries[0].Error == "" {
		t.Error("the line does not say the call failed")
	}
	if !strings.Contains(entries[0].Error, "died half way") {
		t.Errorf("the line does not carry the failure text: %q", entries[0].Error)
	}
}

// A rehearsal that did not say whether it would have run must NOT have the
// column filled in for it.
//
// "Not said" and "it would not have run" are two different facts, and the
// second one is a claim about the tool's behaviour — a claim the trail would
// be making up on the tool's behalf. A contract type with no would_execute
// field (the answer simply does not carry one) would otherwise make every
// rehearsal it describes look like "this one would not have run".
//
// The other half of the rule: when the answer DID say, the line must carry
// it — including `false`, which is a fact of its own.
func TestOnlyARehearsalThatSaidCarriesWouldExecute(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})

	// The answer did not say: the record carries no verdict on it.
	trail(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
			Outcome: &invoke.Outcome{DryRun: true},
		},
	})

	// The answer said "it would not have run".
	said := false
	trail(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
			Outcome: &invoke.Outcome{DryRun: true},
		},
		WouldExecute: &said,
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines, want 2", len(entries))
	}
	// Newest first.
	saidEntry, silentEntry := entries[0], entries[1]
	if saidEntry.WouldExecute == nil {
		t.Error("the line dropped the answer's own verdict (it said it would not run)")
	} else if *saidEntry.WouldExecute {
		t.Error("the line says it would have run; the answer said the opposite")
	}
	if silentEntry.WouldExecute != nil {
		t.Errorf("the line invented a verdict for a rehearsal that did not say one: %v",
			*silentEntry.WouldExecute)
	}
}

// The "who" of the question "who tried to run rm -rf": the MCP client that
// asked. Two agents on one machine are otherwise indistinguishable.
func TestTheTrailRecordsWhoCalled(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{Gate: invoke.Record{
		Call: invoke.Call{
			Name:   "jmsx_exec",
			Server: "jumpserver-exec",
			Caller: "minimax-code",
		},
		Allowed: true,
	}})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	if entries[0].Client != "minimax-code" {
		t.Errorf("the line says the client is %q, want %q", entries[0].Client, "minimax-code")
	}

	// And it can be filtered on.
	res, err = Read(ReadOptions{Dir: dir, Client: "minimax-code"})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("the caller filter returned %d lines, want 1", len(entries))
	}
	res, err = Read(ReadOptions{Dir: dir, Client: "somebody-else"})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("the caller filter returned %d lines, want 0", len(entries))
	}
}

// The file must not be readable by anyone else: it holds the arguments of
// every call, and an argument can carry a name, a path or a secret.
func TestTheTrailFileIsNotWorldReadable(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{Gate: invoke.Record{
		Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
	}})

	paths, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) != 1 {
		t.Fatalf("the trail wrote %d files, want 1: %v", len(paths), paths)
	}
	info, err := os.Stat(paths[0])
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("the trail file is %o, want 600", perm)
	}
}

// The delivery state is the answer to "is it still running on that
// machine?" — the trail has to carry it as a column, not as prose, so it
// can be asked for.
//
// And the `allowed` column has to stay honest about it: a call that BROKE
// was not stopped. It went through and failed.
func TestTheTrailCarriesTheDeliveryState(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	// A command that may already be running on the machine.
	trail(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			// The tool's own failure: the chain closed with an error
			// that is not a gate denial.
			Err: errors.New("the command may already be running on the machine"),
		},
		Delivery: jms.Delivery_maybe_sent.String(),
	})
	// A command that never left this process.
	trail(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Err:  errors.New("the command was not delivered"),
		},
		Delivery: jms.Delivery_not_sent.String(),
	})
	// A call nobody classified.
	trail(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d lines, want 3", len(entries))
	}
	// Newest first: the unclassified call was written last.
	unclassified, notSent, maybeSent := entries[0], entries[1], entries[2]
	if unclassified.Delivery != "" {
		t.Errorf("the line invented a delivery state: %q", unclassified.Delivery)
	}
	if notSent.Delivery != "not_sent" {
		t.Errorf("the line says the delivery state is %q, want not_sent", notSent.Delivery)
	}
	if maybeSent.Delivery != "maybe_sent" {
		t.Errorf("the line says the delivery state is %q, want maybe_sent", maybeSent.Delivery)
	}
	// A call that broke was not stopped.
	if !maybeSent.Allowed {
		t.Error("the line says the call was stopped; it broke, it was not stopped")
	}
	if !maybeSent.Failed {
		t.Error("the line does not say the call failed")
	}

	// And it can be asked for.
	res, err = Read(ReadOptions{Dir: dir, Delivery: "maybe_sent"})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines that may still be running, want 1", len(entries))
	}
}

// A tool error that happens to WRAP the gate's own error type must not be
// read as the gate stopping the call.
//
// The gate's denial and a tool's failure are told apart by the stage trail
// (the gate's own product) and by the error's EXACT type. A tool error
// that wraps one is neither: the gate let it through, and the tool broke.
//
// Getting this backwards would make a broken call read as a refusal — and
// the agent would then "fix" it by adding confirm=true, which is exactly
// the wrong move for a call that already ran.
func TestAToolErrorWrappingTheGateErrorIsNotAGateStop(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			// Every stage allowed: the gate let it through.
			Stages: []invoke.StageResult{{Stage: "capability", Allow: true}},
			Err: fmt.Errorf("the tool blew up: %w", &invoke.DenyError{
				Stage: "confirm", Tool: "jmsx_exec", Reason: "set confirm=true",
			}),
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	e := entries[0]
	if !e.Failed {
		t.Error("the line does not say the call failed")
	}
	if !e.Allowed {
		t.Error("the line says the call was stopped; the gate let it through")
	}
	if e.Refused != "" {
		t.Errorf("the line calls it a refusal: %q", e.Refused)
	}
}

// A failure is not a refusal, and it is not the gate stopping the call
// either — the three have to be askable for apart.
//
// A tool that answers with an error result still made a successful protocol
// call, so the failure is a column of the line — and "what went wrong here"
// is a question the trail has to answer on its own. A call the GATE stopped
// is not in that answer: the gate working is not something broken.
func TestTheFailuresCanBeFiltered(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	// A call whose work failed.
	trail(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		},
		ToolError: "ERROR: no such asset",
	})
	// A call the GATE stopped: nothing ran, and nothing is broken.
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: false,
		Err:     &invoke.DenyError{Stage: "confirm", Tool: "jmsx_exec", Reason: "set confirm=true"},
	}})
	// A call the TOOL refused: also nothing ran, and also not a failure.
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
		Outcome: &invoke.Outcome{Refused: "classified DANGEROUS"},
	}})
	// A call that worked.
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
	}})

	failed := true
	res, err := Read(ReadOptions{Dir: dir, Failed: &failed})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d failed lines, want 1", len(entries))
	}
	if entries[0].Error == "" {
		t.Error("the failed line does not carry the failure")
	}
	// The protocol decoration is for the model, not for the audit.
	if strings.HasPrefix(entries[0].Error, "ERROR: ") {
		t.Errorf("the audit column carries the protocol prefix: %q", entries[0].Error)
	}

	notFailed := false
	res, err = Read(ReadOptions{Dir: dir, Failed: &notFailed})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("read %d lines that did not fail, want 3", len(entries))
	}
	for _, e := range entries {
		if e.Failed {
			t.Errorf("a line that did not fail came back under \"failed\": %+v", e)
		}
	}
}

// The filters are the point of the query: a refusal and an allowance have to
// be tellable apart, and so do the two servers.
func TestTheTrailCanBeFiltered(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
		Outcome: &invoke.Outcome{Refused: "classified DANGEROUS"},
	}})
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_get_file", Server: "jumpserver-exec"},
		Allowed: true,
	}})
	trail(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jms_asset_create", Server: "jumpserver-mgmt"},
		Allowed: false,
	}})

	res, err := Read(ReadOptions{Dir: dir})

	all := res.Entries

	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 3 {
		t.Fatalf("read %d lines, want 3", total)
	}
	if len(all) != 3 {
		t.Fatalf("read %d lines, want 3", len(all))
	}

	notAllowed := false
	res, err = Read(ReadOptions{Dir: dir, Allowed: &notAllowed})
	entries := res.Entries
	total = res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines that did nothing, want 2", len(entries))
	}

	refused := true
	res, err = Read(ReadOptions{Dir: dir, Refused: &refused})
	entries = res.Entries
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 || entries[0].Tool != "jmsx_exec" {
		t.Fatalf("the refusals filter returned %+v", entries)
	}

	res, err = Read(ReadOptions{Dir: dir, Service: "jumpserver-mgmt"})

	entries = res.Entries

	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 || entries[0].Tool != "jms_asset_create" {
		t.Fatalf("the service filter returned %+v", entries)
	}

	res, err = Read(ReadOptions{Dir: dir, Tool: "jmsx_get_file"})

	entries = res.Entries

	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 || !entries[0].Allowed {
		t.Fatalf("the tool filter returned %+v", entries)
	}
}

// The count of what matched is the count of EVERYTHING that matched, even
// when the answer carries only the newest few. A caller that says "50 of
// 300" has to mean it.
func TestTheCountIsOfEverythingThatMatched(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	for i := 0; i < 5; i++ {
		trail(reg.Record{Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		}})
	}

	res, err := Read(ReadOptions{Dir: dir, Limit: 2})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines, want 2", len(entries))
	}
	if total != 5 {
		t.Errorf("the count says %d matched, want 5", total)
	}
}

// A file that is being written while it is read has a half-written last
// line from time to time. That must not take the whole answer down.
func TestAHalfWrittenLineIsSkipped(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	good := `{"ts":"2026-10-28T09:00:00+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	half := `{"ts":"2026-10-28T09:00:01+08:00","service":"jumpserver-exec","tool":"jmsx_`
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	if err := os.WriteFile(path, []byte(good+half), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1 (the half-written one is skipped)", len(entries))
	}
	// ⚠️ It is NOT counted as unreadable: a half-written LAST line is a
	// line being written RIGHT NOW — not broken, unfinished — and the next
	// read sees it whole. Counting it would cry wolf on every read of a
	// live trail.
	if res.Skipped != 0 {
		t.Errorf("a half-written last line was counted as unreadable (%d): it is still being written", res.Skipped)
	}
}

// quiet keeps the trail's log line out of the test output.
func quiet(t *testing.T) {
	t.Helper()
	logx.SetDefault(logx.NewSlogLogger("audit-test",
		logx.WithHandler(slog.NewJSONHandler(io.Discard, nil))))
}

// useTempTrail points the trail at a temporary directory and restores the
// old settings afterwards.
func useTempTrail(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return dir
}

// A client name that is long and non-ASCII must still be findable.
//
// The name comes from the client, so its length is the client's choice, and
// it may be in any script. Cutting it on a BYTE boundary lands inside a
// multi-byte character; the invalid bytes behind it become U+FFFD in the
// JSON, so the name written down is not the name that was sent — and a
// filter carrying the original name matches nothing.
//
// The filter is normalized the same way the stored name is, so the two sides
// of the comparison are cut by the same rule.
func TestALongMultiByteClientNameIsFoundByItsFilter(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// 80 CJK characters: 240 bytes, well over the cap, and every cut
	// point that is not on a character boundary breaks the name.
	name := strings.Repeat("审", 80)

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec", Caller: name},
			Allowed: true,
		},
	})

	res, err := Read(ReadOptions{Dir: dir, Client: name})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("the line was not found by its own client name: %d lines", len(entries))
	}
	if !utf8.ValidString(entries[0].Client) {
		t.Errorf("the stored client name is not valid UTF-8: %q", entries[0].Client)
	}
}

// A call the SDK refused BEFORE the tool ran was STOPPED — not "it ran and
// broke".
//
// The SDK checks the input against the tool's input schema before it calls
// the tool, so a management-plane write without `confirm` never reaches the
// gate. The line says so: allowed=false (it was stopped), failed=true (the
// call failed), and no gate stages at all (the gate never ran).
func TestACallStoppedBeforeTheToolWasStopped(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	Trail(Options{Service: "jumpserver-mgmt", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{Name: "jms_user_set_active", Server: "jumpserver-mgmt"},
			Err:  errors.New(`validating "arguments": required: missing properties: ["confirm"]`),
		},
		StoppedEarly: true,
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	e := entries[0]
	if e.Allowed {
		t.Error("the line says the call was allowed; it was stopped before the tool ran")
	}
	if !e.Failed {
		t.Error("the line does not say the call failed")
	}
	if len(e.Stages) != 0 {
		t.Errorf("the line has %d gate stages; the gate never ran", len(e.Stages))
	}
	if e.Error == "" {
		t.Error("the line does not say why the call was refused")
	}
}

// A rotated trail must still be READABLE.
//
// Rotation moves the current file aside to "<name>.jsonl.1" and starts a
// fresh one. A reader whose pattern only matched "*.jsonl" therefore stopped
// seeing HALF the trail the moment the file rotated — while still answering
// "nothing matched". On a long-lived server that is exactly where the
// interesting history is, and a true-looking silence over it is the worst
// answer an audit can give.
//
// ⚠️ The rotation is done by the WRITER here, not by hand: the reader and
// the writer have to agree on the name of the rotated file, and a test that
// made the name up on its own would keep passing after the writer changed
// it — which is a reader that has quietly gone blind.
func TestTheRotatedTrailIsStillReadable(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail file did not open")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()
	trail.write(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
	}})
	if !trail.rotate() {
		t.Fatal("the rotation failed")
	}
	// A line in the fresh file, after the rotation.
	trail.write(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
	}})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 2 {
		t.Fatalf("read %d lines, want 2: the rotated half of the trail is invisible", total)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines, want 2", len(entries))
	}
}

// A file next to the trail that is NOT the trail must not be read as one.
//
// The trail directory holds whatever the operator put next to it. A copy
// called "audit-….jsonl.bak" is not a trail file, and reading it would put
// a duplicate of the trail into the answer — and into "everything that
// matched", which is a number an operator takes as a fact.
func TestAFileThatIsNotTheTrailIsNotReadAsOne(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	real := `{"ts":"2026-10-28T09:00:00Z","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl"), []byte(real), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A backup of the same file, and the operator's own notes.
	if err := os.WriteFile(filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl.bak"), []byte(real), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	notes := `{"note":"my own notes, not a call"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "notes.json"), []byte(notes), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 1 {
		t.Fatalf("the count says %d matched, want 1: something that is not the trail was read as one", total)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
}

// A line that is not one of ours is not a fact about a call.
//
// A neighbouring file may hold a JSON object that happens to parse. It is
// not a call, so it must not be counted — and it must not land in the
// "allowed=false" filter, where it would read as "a call that was stopped".
func TestALineThatIsNotACallIsNotAFact(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// A well-formed JSON object that is not a trail line.
	foreign := `{"ts":"2026-10-28T09:00:00Z","note":"not a call"}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl"), []byte(foreign), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 0 {
		t.Fatalf("the count says %d matched, want 0: a line that is not a call was counted", total)
	}
	if len(entries) != 0 {
		t.Fatalf("read %d lines, want 0", len(entries))
	}
}

// The arguments must be cut on a CHARACTER boundary.
//
// A byte cut that lands inside a multi-byte character leaves invalid UTF-8
// behind, and the JSON encoder turns those bytes into U+FFFD — so the trail
// stores a DIFFERENT string from the one that was called, and the operator
// reading the evidence sees a replacement character where the command had
// one. The evidence must be what was called.
func TestTheArgumentsAreCutOnACharacterBoundary(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// Long enough to be cut, and Chinese so that every cut point that is
	// not on a character boundary breaks a character.
	args := `{"command":"` + strings.Repeat("审", 300) + `"}`

	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec", Args: args},
			Allowed: true,
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	got := entries[0].Args
	if !utf8.ValidString(got) {
		t.Fatalf("the stored arguments are not valid UTF-8: %q", got)
	}
	if strings.ContainsRune(got, utf8.RuneError) {
		t.Fatalf("the stored arguments carry a replacement character: the cut split a character")
	}
	if !strings.HasPrefix(got, `{"command":"审`) {
		t.Errorf("the stored arguments do not start with what was called: %q", got)
	}
	// ⚠️ The cut has to HAPPEN and it has to SAY so: an argument column
	// that quietly stopped being cut would grow without bound, and one
	// that was cut without a marker would leave the reader guessing
	// whether it is looking at the whole command.
	if !strings.Contains(got, "…(truncated)") {
		t.Errorf("the stored arguments do not say they were truncated: %q", got)
	}
	if len(got) >= len(args) {
		t.Errorf("the stored arguments are %d bytes, not shorter than the %d that were passed",
			len(got), len(args))
	}
}

// A rotation that FAILS must not throw the size accounting away.
//
// When the rename fails the old file is still there, still holding its
// bytes, and is reopened in append mode. Assuming it was empty takes the
// cap off that file for good — and a trail that grows without end is
// exactly what the cap exists to prevent.
func TestAFailedRotationKeepsTheSizeAccounting(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail file did not open")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()
	trail.write(reg.Record{Gate: invoke.Record{
		Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec", Args: "{}"},
	}})
	before := trail.size
	if before == 0 {
		t.Fatal("nothing was written")
	}

	// Make the rotation fail: the target of the rename is a NON-EMPTY
	// directory, so it can neither be removed nor be replaced by a file.
	poison := trail.path + ".1"
	if err := os.Mkdir(poison, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(poison, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	trail.rotate()
	if trail.size != before {
		t.Fatalf("the size accounting is %d after a failed rotation, want %d: "+
			"the cap is off that file for good", trail.size, before)
	}
}

// The newest line must come FIRST.
//
// The stamp is RFC3339Nano, which drops the trailing zeros of the fraction:
// the exact second ("…:00Z") sorts AFTER the half second ("…:00.5Z") as
// text, while being the EARLIER of the two. Comparing the strings therefore
// put the older line first in a list that is supposed to be newest-first —
// and the newest line is the one an operator is looking for.
func TestTheNewestLineComesFirst(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	const older = "2026-10-28T09:00:00Z"
	const newer = "2026-10-28T09:00:00.5Z"
	line := func(ts string) string {
		return `{"ts":"` + ts + `","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	}
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	if err := os.WriteFile(path, []byte(line(older)+line(newer)), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines, want 2", len(entries))
	}
	if entries[0].Ts != newer {
		t.Fatalf("the first line is %q, want the newer one %q: the newest line must come first",
			entries[0].Ts, newer)
	}
}

// The DROPPING path sorts by time too — and it is a different path.
//
// ⚠️ `add` sorts and truncates once the queue holds 2*limit lines, and
// that is where it decides WHICH lines are dropped. The test above never
// reaches it: two lines and the default limit of 50 ⇒ the incremental
// path is not taken at all ⇒ a mutation that broke the incremental sort
// left the test green.
//
// ⚠️ And the moments have to DISAGREE between text order and time order,
// or the two sorts agree by accident: RFC3339Nano drops the trailing
// zeros of the fraction, so "…:00Z" sorts AFTER "…:00.5Z" as text while
// being the EARLIER of the two.
//
// ⚠️ The drop boundary has to fall BETWEEN that pair, or the wrong sort
// keeps the same set and the difference is invisible.
func TestTheDroppingPathKeepsTheNewestLines(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	const exact = "2026-10-28T09:00:00Z"  // earlier, but LATER as text
	const half = "2026-10-28T09:00:00.5Z" // later,  but EARLIER as text
	const s1 = "2026-10-28T09:00:01Z"
	const h1 = "2026-10-28T09:00:01.5Z"
	const s2 = "2026-10-28T09:00:02Z"
	const s3 = "2026-10-28T09:00:03Z"
	line := func(ts string) string {
		return `{"ts":"` + ts + `","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	}
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	// arrival order: s3, s2, h1, s1, half, exact
	body := line(s3) + line(s2) + line(h1) + line(s1) + line(half) + line(exact)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// limit 3 ⇒ the queue holds 6 lines before `add` sorts and drops.
	res, err := Read(ReadOptions{Dir: dir, Limit: 3})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	got := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		got = append(got, e.Ts)
	}
	// The three newest BY TIME: s3, s2, h1.
	want := []string{s3, s2, h1}
	if len(got) != len(want) {
		t.Fatalf("read %d lines (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("read %v, want %v: the newest lines by TIME must survive the drop",
				got, want)
		}
	}
	// ⚠️ And the line that must NOT be there is the one the text order
	// would have kept: the exact second sorts after the half second as
	// text, so a text-ordered drop keeps the OLDER line and drops the
	// newer one.
	for _, e := range got {
		if e == exact {
			t.Fatalf("read %v: the older line survived the drop (%q)", got, exact)
		}
	}
}

// Every free-text column of a trail line sits on the SAME water line.
//
// The arguments, the error, the refusal reason and the gate's own reasons
// are all free text that the tool or the gate wrote — and a column that
// skipped the scrubber is the one place a credential survives. The refusal
// reason and the error come from the SAME answer, so a tool whose answer
// carries both `error` and `blocked` had one of them scrubbed and the
// other written down in full: two columns of one line, two water levels,
// and no way for the reader to tell which is which.
//
// Both exits of the line are checked: the file (what survives the process)
// and the log line (what an operator reads while it runs).
func TestEveryFreeTextColumnIsScrubbed(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// The log line goes to a buffer this time: the trail writes to BOTH
	// the log and the file, and the two are separate exits.
	var logBuf bytes.Buffer
	logx.SetDefault(logx.NewSlogLogger("audit-test",
		logx.WithHandler(slog.NewJSONHandler(&logBuf, nil))))

	const secret = "hunter2-plaintext"
	Trail(Options{Service: "jumpserver-exec", Dir: dir})(reg.Record{
		Gate: invoke.Record{
			Call: invoke.Call{
				Name:   "jmsx_exec",
				Server: "jumpserver-exec",
				Args:   `{"password":"` + secret + `"}`,
			},
			Outcome: &invoke.Outcome{Refused: "the password: " + secret + " was refused"},
			Stages: []invoke.StageResult{
				{Stage: "capability", Allow: true, Reason: "白名单放行: jmsx_exec"},
				{Stage: "confirm", Allow: false, Reason: "password: " + secret},
			},
		},
	})

	paths, err := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("the trail file is not there: %v (%v)", paths, err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read the trail file: %v", err)
	}
	if bytes.Contains(raw, []byte(secret)) {
		t.Errorf("the trail FILE carries the secret: %s", raw)
	}
	if strings.Contains(logBuf.String(), secret) {
		t.Errorf("the trail LOG LINE carries the secret: %s", logBuf.String())
	}

	// The reasons themselves must survive the scrubber — a reason that was
	// emptied by it would vanish from the `refused` filter, and "who was
	// stopped?" would silently lose an answer.
	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	_ = total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(entries))
	}
	e := entries[0]
	if e.Refused == "" {
		t.Error("the refusal reason was emptied by the scrubber: it would vanish from the refused filter")
	}
	if len(e.Stages) != 2 {
		t.Fatalf("the line has %d stages, want 2", len(e.Stages))
	}
	if e.Stages[0].Reason != "白名单放行: jmsx_exec" {
		t.Errorf("an ordinary reason was changed by the scrubber: %q", e.Stages[0].Reason)
	}
}

// A rotation that FAILS must not destroy the archived generation.
//
// The old code removed the previous ".1" BEFORE the rename — so a rename
// that then failed took the archived generation with it, and the trail
// answered "nothing matched" over a generation that was there a moment
// ago. The rename replaces its destination atomically, so there is no
// reason to remove it first.
func TestAFailedRotationKeepsTheArchivedGeneration(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail file did not open")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()
	call := func() {
		trail.write(reg.Record{Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		}})
	}

	// The first generation, and the rotation that archives it.
	call()
	call()
	if !trail.rotate() {
		t.Fatal("the first rotation failed")
	}
	// The second generation.
	call()

	// Now the next rotation fails: the current file is gone (an external
	// process moved it away), so the rename has nothing to move.
	if err := os.Remove(trail.path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if trail.rotate() {
		t.Fatal("the rotation was supposed to fail")
	}

	// The archived generation must still be there, with its content.
	//
	// ⚠️ Two lines, not three: the third was in the CURRENT file, and
	// that file is the one the operator's own process moved away — it is
	// legitimately gone. What must NOT be gone is the ARCHIVED
	// generation, which the old code deleted before the rename.
	res, err := Read(ReadOptions{Dir: dir})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 2 {
		t.Fatalf("the count says %d matched, want 2: a failed rotation took the archived generation with it", total)
	}
	if len(entries) != 2 {
		t.Fatalf("read %d lines, want 2", len(entries))
	}
}

// The cap is a bound, and a bound a broken filesystem can lift is not a
// bound.
//
// When the rotation fails the file trail STOPS: the file keeps what it
// had, it does not grow past the cap, and it is not written to again.
func TestTheCapHoldsEvenWhenTheRotationFails(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail file did not open")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()
	// A small cap, so the test does not have to write 32 MiB to reach it.
	trail.max = 512

	// Make the rotation fail: the destination is a non-empty directory, so
	// it can neither be replaced by a file nor be renamed onto.
	poison := trail.path + ".1"
	if err := os.Mkdir(poison, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(poison, "keep"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	for i := 0; i < 20; i++ {
		trail.write(reg.Record{Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		}})
	}

	info, err := os.Stat(trail.path)
	if err != nil {
		t.Fatalf("the trail file is gone: %v", err)
	}
	if info.Size() > trail.max {
		t.Errorf("the trail file is %d bytes, over the %d cap: a failed rotation lifted the bound",
			info.Size(), trail.max)
	}
	if trail.f != nil {
		t.Error("the file trail kept writing after a failed rotation")
	}
}

// The limit has a ceiling.
//
// "How many lines to return at most" promised a bound that did not exist:
// a caller could ask for a million lines and the server would build the
// answer. The bound exists now, and the count of everything that matched
// is still reported so the caller can narrow the question down.
func TestTheLimitHasACeiling(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	for i := 0; i < MaxReadLimit+10; i++ {
		trail(reg.Record{Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Allowed: true,
		}})
	}

	res, err := Read(ReadOptions{Dir: dir, Limit: 1_000_000})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != MaxReadLimit+10 {
		t.Errorf("the count says %d matched, want %d", total, MaxReadLimit+10)
	}
	if len(entries) != MaxReadLimit {
		t.Fatalf("read %d lines, want %d: the limit has no ceiling", len(entries), MaxReadLimit)
	}
}

// The answer must be the NEWEST lines, not the oldest.
//
// The files are read newest-first, but that is the order of their
// MODIFICATION TIMES, not of their lines: an older process's file can
// hold many more lines than a newer one's. So the lines arrive newest-first
// and then OLD ones — and a queue that dropped by ARRIVAL would end up
// keeping the oldest lines, the opposite of what the trail promises.
//
// The fixture is built to make the two orders disagree: the newer file
// (read first) has few lines, the older file (read last) has many.
func TestTheAnswerIsTheNewestLines(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// The newer file: read FIRST, few lines, the newest timestamps.
	newer := filepath.Join(dir, "audit-20261029-2-bbbbbbbb.jsonl")
	now := time.Now()
	for i := 0; i < 8; i++ {
		ts := now.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		line := `{"ts":"` + ts + `","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
		f, err := os.OpenFile(newer, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		f.WriteString(line)
		f.Close()
	}
	// The older file: read LAST, many lines, the oldest timestamps.
	older := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	past := now.Add(-2 * time.Hour)
	for i := 0; i < 20; i++ {
		ts := past.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)
		line := `{"ts":"` + ts + `","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
		f, err := os.OpenFile(older, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		f.WriteString(line)
		f.Close()
	}
	// The newer file is the one read first.
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if err := os.Chtimes(newer, now, now); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir, Limit: 8})
	entries := res.Entries
	total := res.Total
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if total != 28 {
		t.Fatalf("the count says %d matched, want 28", total)
	}
	if len(entries) != 8 {
		t.Fatalf("read %d lines, want 8", len(entries))
	}
	// Every returned line must be one of the NEW ones. The cut is in the
	// MIDDLE: the old lines are two hours old, the new ones are now.
	cut := now.Add(-time.Hour)
	for i, e := range entries {
		ts, ok := parseTs(e.Ts)
		if !ok {
			t.Fatalf("the stamp of line %d cannot be read: %q", i, e.Ts)
		}
		if ts.Before(cut) {
			t.Errorf("line %d is one of the OLD lines (%s): the answer kept the oldest lines",
				i, e.Ts)
		}
	}
}

// The `Since` filter must actually filter.
//
// It had NO coverage at all: deleting the check left the whole suite
// green, so "the ordering and the period filter share one time
// semantics" was something the code said, not something the tests knew.
func TestTheSinceFilterKeepsOnlyWhatIsAfterIt(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// ⚠️ The lines are written by hand: the trail stamps a line with the
	// moment it was WRITTEN, so a line written now is always "now".
	cut := time.Now().Add(-time.Hour)
	line := func(at time.Time) string {
		return `{"ts":"` + at.Format(time.RFC3339Nano) + `","service":"jumpserver-exec",` +
			`"tool":"jmsx_exec","allowed":true}` + "\n"
	}
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	if err := os.WriteFile(path, []byte(line(cut.Add(-time.Hour))+line(cut.Add(time.Hour))), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir, Since: cut})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Total != 1 {
		t.Fatalf("the count says %d matched, want 1: the period filter did not filter", res.Total)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(res.Entries))
	}
	if res.Entries[0].Ts == line(cut.Add(-time.Hour)) {
		t.Error("the line before the cut was returned")
	}
}

// A line that cannot be placed in time is not a fact.
//
// Two of the three checks that make a row a fact — the tool name and the
// stamp — have to hold on their own, not only in combination.
func TestWhatMakesALineAFact(t *testing.T) {
	quiet(t)

	cases := []struct {
		name string
		line string
		want bool
	}{
		{"a call", `{"ts":"2026-10-28T09:00:00Z","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}`, true},
		{"no tool", `{"ts":"2026-10-28T09:00:00Z","service":"jumpserver-exec","allowed":true}`, false},
		{"no stamp", `{"service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}`, false},
		{"an unreadable stamp", `{"ts":"not a moment","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}`, false},
		// ⚠️ No service is NOT a reason to drop the row: the service
		// filter copes with an empty one, and making it a requirement
		// would let one missing field blind a whole process's trail.
		{"no service", `{"ts":"2026-10-28T09:00:00Z","tool":"jmsx_exec","allowed":true}`, true},
	}
	for _, c := range cases {
		d := t.TempDir()
		path := filepath.Join(d, "audit-20261028-1-aaaaaaaa.jsonl")
		if err := os.WriteFile(path, []byte(c.line+"\n"), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		res, err := Read(ReadOptions{Dir: d})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got := res.Total == 1
		if got != c.want {
			t.Errorf("%s: counted=%v, want %v", c.name, got, c.want)
		}
	}
}

// A line that is too long must not cost the REST of the file.
//
// The reader used to stop at such a line (`bufio.Scanner` gives up on the
// whole file), so one huge line made everything after it unreadable —
// silently. Now the long line is skipped, the rest is read, and the answer
// says how many were skipped.
func TestALineThatIsTooLongDoesNotCostTheRestOfTheFile(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// A small limit, so the test does not have to write a megabyte.
	old := maxTrailLine
	maxTrailLine = 512
	defer func() { maxTrailLine = old }()

	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	good := `{"ts":"2026-10-28T09:00:00Z","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	huge := `{"ts":"2026-10-28T09:00:01Z","service":"jumpserver-exec","tool":"jmsx_exec","args":"` +
		strings.Repeat("x", 2000) + `"}` + "\n"
	if err := os.WriteFile(path, []byte(good+huge+good+good), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines were skipped, want 1", res.Skipped)
	}
	if res.Total != 3 {
		t.Errorf("the count says %d matched, want 3: the long line cost the file its other lines", res.Total)
	}
}

// The queue must stay bounded.
//
// The memory a read holds is supposed to be O(limit) and not O(the size
// of the trail) — and nothing tested that: dropping the trimming entirely
// left the whole suite green.
func TestTheQueueStaysBounded(t *testing.T) {
	q := &newest{limit: 4}
	base := time.Now()
	for i := 0; i < 100; i++ {
		q.add(Entry{Ts: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)},
			base.Add(time.Duration(i)*time.Second))
	}
	if len(q.items) > 2*q.limit {
		t.Fatalf("the queue holds %d items, want at most %d", len(q.items), 2*q.limit)
	}
	lines := q.sorted()
	if len(lines) != q.limit {
		t.Fatalf("the answer holds %d lines, want %d", len(lines), q.limit)
	}
	// The newest must be the first one, and the oldest of the kept ones
	// the last.
	if lines[0].Ts != base.Add(99*time.Second).Format(time.RFC3339Nano) {
		t.Errorf("the first line is %s, want the newest", lines[0].Ts)
	}
}

// The files the writer opens must carry the cap.
//
// Nothing tested that the wiring between the constant and the file
// object exists: a writer with a cap of zero would rotate on every line
// and the suite stayed green.
func TestTheTrailFileCarriesTheCap(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)
	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail file did not open")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()
	if trail.max != MaxTrailBytes {
		t.Errorf("the trail file's cap is %d, want %d", trail.max, MaxTrailBytes)
	}
}

// The files that are over the cap must be found.
//
// The doctor's warning depends on this, and nothing tested it: making
// `OverCap` always answer "none" left the suite green.
func TestTheFilesOverTheCapAreFound(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	over, err := OverCap(dir)
	if err != nil {
		t.Fatalf("OverCap: %v", err)
	}
	if len(over) != 0 {
		t.Fatalf("an empty directory reported %d files over the cap", len(over))
	}

	// A file over the cap: the cap is 32 MiB, so the file is written with
	// a hole in it (a sparse file) rather than 32 MiB of zeros.
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := f.Truncate(MaxTrailBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	over, err = OverCap(dir)
	if err != nil {
		t.Fatalf("OverCap: %v", err)
	}
	if len(over) != 1 {
		t.Fatalf("OverCap found %d files over the cap, want 1", len(over))
	}
	// A file that is NOT over the cap must not be reported, and neither
	// must a neighbour that is not a trail file.
	if err := os.WriteFile(filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl.bak"),
		[]byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	over, err = OverCap(dir)
	if err != nil {
		t.Fatalf("OverCap: %v", err)
	}
	if len(over) != 1 {
		t.Errorf("OverCap found %d files over the cap, want 1", len(over))
	}
}

// Every free-text column must have a ceiling — IN THE FILE, not only in
// the log.
//
// The log side and the file side write the same fact; if only one of them
// caps it, the same refusal is written at two lengths in two places, and
// nobody can tell which is which. That is exactly what happened once: the
// file side did not cap at all.
func TestEveryFreeTextColumnHasACeiling(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	// The log line goes to a buffer: the trail writes to BOTH the log and
	// the file, and they are two separate exits.
	//
	// ⚠️ The ceiling has to hold on the log side too. The file side had
	// one and the log side did not, and the mutation that reintroduced a
	// second copy of the shaping on the log side survived the whole suite:
	// a second copy of "clip then scrub" is a second waterline waiting to
	// happen, and nobody would notice until the two told the same fact at
	// two lengths.
	var logBuf bytes.Buffer
	logx.SetDefault(logx.NewSlogLogger("audit-test",
		logx.WithHandler(slog.NewJSONHandler(&logBuf, nil))))

	// Longer than the ceiling, in Chinese so that a byte-boundary cut
	// would break a character.
	huge := strings.Repeat("审", maxColumn)
	trail := Trail(Options{Service: "jumpserver-exec", Dir: dir})
	trail(reg.Record{
		Gate: invoke.Record{
			Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
			Outcome: &invoke.Outcome{Refused: huge},
			Stages: []invoke.StageResult{
				{Stage: "confirm", Allow: false, Reason: huge},
			},
			Err: errors.New(huge),
		},
	})

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(res.Entries) != 1 {
		t.Fatalf("read %d lines, want 1", len(res.Entries))
	}
	e := res.Entries[0]
	// The ceiling is in BYTES (the cut is a byte budget on a rune
	// boundary), and the marker "…(clipped)" is twelve more.
	limit := maxColumn + len("…(clipped)")
	for _, col := range []struct {
		name string
		text string
	}{
		{"refused", e.Refused},
		{"stage reason", e.Stages[0].Reason},
		{"error", e.Error},
	} {
		if len(col.text) > limit {
			t.Errorf("the %s column is %d bytes, over the %d ceiling", col.name, len(col.text), limit)
		}
		if !utf8.ValidString(col.text) {
			t.Errorf("the %s column is not valid UTF-8: %q", col.name, col.text[:40])
		}
		if strings.ContainsRune(col.text, utf8.RuneError) {
			t.Errorf("the %s column carries a replacement character: the cut split a character", col.name)
		}
		// The cut has to SAY it happened: a column that was cut without a
		// marker leaves the reader guessing whether it is looking at the
		// whole thing.
		if !strings.Contains(col.text, "…(clipped)") {
			t.Errorf("the %s column does not say it was clipped", col.name)
		}
	}

	// ⚠️ And the same on the LOG side: the file and the log are two exits,
	// and a fact told at two lengths is two waterlines.
	var logged map[string]any
	line := strings.TrimSpace(logBuf.String())
	if line == "" {
		t.Fatal("the trail wrote no log line")
	}
	if err := json.Unmarshal([]byte(line), &logged); err != nil {
		t.Fatalf("the log line is not JSON: %v (%s)", err, line)
	}
	for _, col := range []struct {
		name string
		key  string
	}{
		{"refused", "refused"},
		{"stage reason", "stage.confirm.reason"},
		{"error", "error"},
	} {
		text, _ := logged[col.key].(string)
		if text == "" {
			t.Errorf("the log line has no %s field", col.key)
			continue
		}
		if len(text) > limit {
			t.Errorf("the LOG's %s column is %d bytes, over the %d ceiling", col.name, len(text), limit)
		}
		if !strings.Contains(text, "…(clipped)") {
			t.Errorf("the LOG's %s column does not say it was clipped", col.name)
		}
	}
}

// The ceiling's VALUE is part of what the documentation promises.
//
// ⚠️ The other ceiling test computed its expectation FROM the constant, so
// it stayed green when the constant moved: the documentation says 4KB per
// column, and the code could say 64KB without a single test turning red.
// A number that the documentation pins has to be pinned in code too.
func TestTheColumnCeilingIsTheOneTheDocumentationPromises(t *testing.T) {
	const want = 4096
	if maxColumn != want {
		t.Errorf("the column ceiling is %d bytes, want %d (the documentation says 4KB per column)", maxColumn, want)
	}
}

// The random suffix has to have the shape the reader recognises.
//
// The reader recognises trail files by their name, so a suffix that does
// not fit the shape makes that process's whole trail invisible — silently.
func TestTheRandomSuffixFitsTheShapeTheReaderRecognises(t *testing.T) {
	suffix := randomSuffix()
	if len(suffix) != 8 {
		t.Errorf("the random suffix is %q (%d characters), want 8", suffix, len(suffix))
	}
	if !trailFileName.MatchString("audit-20261028-1-" + suffix + ".jsonl") {
		t.Errorf("the reader would not recognise a file named with the suffix %q", suffix)
	}
	// The FALLBACK has the same shape — and it is a constant, so it can
	// be checked. (The branch that uses it is unreachable in practice:
	// crypto/rand.Read never returns an error. That is exactly why its
	// shape needs pinning — nobody will ever run it.)
	if len(randomSuffixFallback) != 8 {
		t.Errorf("the fallback suffix is %q (%d characters), want 8",
			randomSuffixFallback, len(randomSuffixFallback))
	}
	if !trailFileName.MatchString("audit-20261028-1-" + randomSuffixFallback + ".jsonl") {
		t.Errorf("the reader would not recognise a file named with the fallback suffix %q",
			randomSuffixFallback)
	}
}

// A file that is exactly AT the cap is not over it.
//
// The cap is a ceiling, not a threshold: a file of exactly the cap is
// still a healthy file, and reporting it as broken would send an operator
// after a problem that is not there.
func TestAFileExactlyAtTheCapIsNotOverIt(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := f.Truncate(MaxTrailBytes); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	over, err := OverCap(dir)
	if err != nil {
		t.Fatalf("OverCap: %v", err)
	}
	if len(over) != 0 {
		t.Fatalf("a file of exactly the cap was reported as over it: %v", over)
	}
}

// A neighbouring file that is over the cap is not a trail file.
//
// The doctor's warning is about TRAIL files; a backup somebody left next
// to them is not one, and reporting it would be a false alarm.
func TestANeighbouringFileOverTheCapIsNotReported(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl.bak")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := f.Truncate(MaxTrailBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()

	over, err := OverCap(dir)
	if err != nil {
		t.Fatalf("OverCap: %v", err)
	}
	if len(over) != 0 {
		t.Fatalf("a neighbouring file was reported as a trail file over the cap: %v", over)
	}
}

// The size of an existing file must be read, not assumed to be zero.
//
// The cap's accounting depends on it: a file that is already big when the
// process opens it has to be counted, or the cap is off by that much.
func TestTheSizeOfAnExistingFileIsRead(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	path := filepath.Join(dir, "existing.jsonl")
	if err := os.WriteFile(path, []byte("12345"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f, err := openAppend(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if got := fileSize(f); got != 5 {
		t.Errorf("the file holds %d bytes, want 5", got)
	}
	// And appending must not erase what was there.
	f.WriteString("67890")
	if got := fileSize(f); got != 10 {
		t.Errorf("after appending the file holds %d bytes, want 10: it was truncated", got)
	}
}

// A line of exactly the limit must be read.
//
// The limit says "the longest trail line a read accepts" — so a line of
// exactly that length is accepted, and a line one byte longer is skipped.
func TestALineOfExactlyTheLimitIsRead(t *testing.T) {
	quiet(t)
	dir := useTempTrail(t)

	old := maxTrailLine
	maxTrailLine = 512
	defer func() { maxTrailLine = old }()

	head := `{"ts":"2026-10-28T09:00:00Z","service":"jumpserver-exec","tool":"jmsx_exec","args":"`
	tail := `"}`
	pad := maxTrailLine - len(head) - len(tail)
	if pad < 0 {
		t.Skip("the limit is too small for this fixture")
	}
	line := head + strings.Repeat("x", pad) + tail
	if len(line) != maxTrailLine {
		t.Fatalf("the fixture line is %d bytes, want %d", len(line), maxTrailLine)
	}
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 0 {
		t.Errorf("a line of exactly the limit was skipped (%d skipped)", res.Skipped)
	}
	if res.Total != 1 {
		t.Errorf("the count says %d matched, want 1", res.Total)
	}
}

// An empty directory means there is NO trail file — and the reader has to
// say the same thing the writer says.
//
// ⚠️ The two sides used to disagree: the writer took an empty Dir as "the
// file trail is off", while the reader turned it into a RELATIVE glob and
// went looking in the process's working directory. The consequence was not
// a wrong count — it was that any file in the working directory whose NAME
// had a trail file's shape was read back as a fact about what was attempted
// on this machine. A name is a shape, not a provenance.
func TestAnEmptyTrailDirectoryReadsNothing(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	line := `{"ts":"2026-10-29T01:00:00.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	name := filepath.Join(dir, "audit-20261029-123-aaaaaaaa.jsonl")
	if err := os.WriteFile(name, []byte(line), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer os.Chdir(old)

	res, err := Read(ReadOptions{Dir: ""})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Total != 0 || len(res.Entries) != 0 {
		t.Errorf("an empty trail directory read %d line(s) out of the working directory", res.Total)
	}
}

// A line that does not parse is a line the reader could not take — and it
// has to be COUNTED.
//
// ⚠️ The long lines were counted and this one was not, and the gap is the
// same gap in a different place: the answer said "that is everything" while
// a line was quietly gone. A broken line is a fact about the trail's
// health, and the trail's health is what the reader came for.
func TestALineThatDoesNotParseIsCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	good := `{"ts":"2026-10-29T01:00:00.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}`
	bad := `{"ts":"2026-10-29T01:00:01.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_`
	path := filepath.Join(dir, "audit-20261029-123-bbbbbbbb.jsonl")
	if err := os.WriteFile(path, []byte(good+"\n"+bad+"\n"+good+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines could not be read, want 1 (the one that does not parse)", res.Skipped)
	}
	if res.Total != 2 {
		t.Errorf("the count says %d matched, want 2 (the good lines)", res.Total)
	}
}

// A write that fails halfway leaves half a line in the file — and half a
// line has no newline in it, so the NEXT line would be appended to it, and
// the two of them would become one unreadable line.
//
// ⚠️ Two lines lost for one failure, and nobody could tell that anything
// was lost: the reader skips what it cannot parse and the answer says it
// saw everything. The writer seals the half line off with a newline, so
// the broken line is broken ALONE and the line after it is still readable.
func TestAPartialWriteDoesNotGlueTheNextLine(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "audit-20261029-123-dddddddd.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	w := &halfWriter{f: f, cut: 20}
	// ⚠️ opened: true — the file is opened by the first WRITE now (a
	// server that never gets a call must not leave an empty file behind),
	// and this test hands the writer a file of its own.
	trail := &trailFile{f: w, path: path, max: 1 << 20, opened: true}

	// The first write fails halfway through the line.
	trail.write(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
	}})
	// The next one goes through whole.
	trail.write(reg.Record{Gate: invoke.Record{
		Call:    invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
		Allowed: true,
	}})
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("the count says %d matched, want 1: the line after the broken one was glued to it", res.Total)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines could not be read, want 1 (the half-written one)", res.Skipped)
	}
}

// halfWriter writes only part of the FIRST line it is given and then fails,
// which is what a full disk does. Every write after that goes through.
type halfWriter struct {
	f    *os.File
	cut  int
	used bool
}

func (w *halfWriter) Write(p []byte) (int, error) {
	if !w.used {
		w.used = true
		n := w.cut
		if n > len(p) {
			n = len(p)
		}
		if _, err := w.f.Write(p[:n]); err != nil {
			return 0, err
		}
		return n, io.ErrShortWrite
	}
	return w.f.Write(p)
}

func (w *halfWriter) Close() error { return w.f.Close() }

func (w *halfWriter) Stat() (os.FileInfo, error) { return w.f.Stat() }

// The trail's own health check: every branch has to answer with a status,
// and none of them may fall through to "ok".
func TestTheTrailHealthCheckAnswers(t *testing.T) {
	dir := t.TempDir()

	if st, _, _ := CheckTrail(""); st != jms.Status_warn {
		t.Errorf("an unset trail directory reported %v, want warn", st)
	}
	if st, _, _ := CheckTrail(filepath.Join(dir, "not-there")); st != jms.Status_warn {
		t.Errorf("a trail directory that does not exist reported %v, want warn", st)
	}
	notADir := filepath.Join(dir, "a-file")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if st, _, _ := CheckTrail(notADir); st != jms.Status_fail {
		t.Errorf("a file where the trail directory should be reported %v, want fail", st)
	}
	if st, _, _ := CheckTrail(dir); st != jms.Status_ok {
		t.Errorf("an empty trail directory reported %v, want ok", st)
	}

	// A file over the cap: the cap is 32 MiB, so the file is written with
	// a hole in it (a sparse file) rather than 32 MiB of zeros.
	over := filepath.Join(dir, FileName())
	f, err := os.Create(over)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := f.Truncate(MaxTrailBytes + 1); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	f.Close()
	st, _, detail := CheckTrail(dir)
	if st != jms.Status_warn {
		t.Errorf("a trail file over the cap reported %v (%s), want warn", st, detail)
	}
	if !strings.Contains(detail, "over the") {
		t.Errorf("the warning does not say what is wrong: %s", detail)
	}
}

// A broken line that has nothing to do with the question must NOT be
// counted.
//
// ⚠️ The count used to be of every unreadable line, so an agent asking
// "which jmsx_exec calls were refused" was told "one more line could not
// be read" because some OTHER tool's line was too long — and would then
// believe a refusal was missing. A count that counts the wrong lines is
// worse than no count.
func TestABrokenLineAboutSomethingElseIsNotCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	mine := `{"ts":"2026-10-29T01:00:00.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}`
	// A line about a DIFFERENT tool, and too long to read.
	other := `{"ts":"2026-10-29T01:00:01.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_put_file","args":"` +
		strings.Repeat("x", 2_000_000) + `"}`
	path := filepath.Join(dir, "audit-20261029-123-eeeeeeee.jsonl")
	if err := os.WriteFile(path, []byte(mine+"\n"+other+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Asked about jmsx_exec: the other tool's line is not about it.
	res, err := Read(ReadOptions{Dir: dir, Tool: "jmsx_exec"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 0 {
		t.Errorf("the answer says %d lines could not be read, want 0 (the broken line is about another tool)", res.Skipped)
	}
	if res.Total != 1 {
		t.Errorf("the count says %d matched, want 1", res.Total)
	}

	// Asked about the tool the broken line belongs to: now it counts.
	res, err = Read(ReadOptions{Dir: dir, Tool: "jmsx_put_file"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines could not be read, want 1 (the broken line is about that tool)", res.Skipped)
	}
}

// A broken line that cannot be PROVED irrelevant is counted: over-reporting
// is the harmless direction, because the answer says "could not read".
func TestABrokenLineThatCannotBePlacedIsCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	// No tool field at all: the reader cannot tell what it is about.
	bad := `{"ts":"2026-10-29T01:00:01.000000000+08:00","service":"jumpserver-exec","tool":`
	path := filepath.Join(dir, "audit-20261029-123-ffffffff.jsonl")
	if err := os.WriteFile(path, []byte(bad+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := Read(ReadOptions{Dir: dir, Tool: "jmsx_exec"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines could not be read, want 1 (it cannot be proved irrelevant)", res.Skipped)
	}
}

// A read that breaks in the MIDDLE must still report what it read.
//
// ⚠️ The lines that were read are already in the answer, so dropping their
// count would make "everything that matched" smaller than the answer
// itself — and "truncated" would say "no" while the answer is obviously
// cut. This path needs a stream that breaks halfway, which is why the
// reader takes a stream and not a path.
func TestAReadThatBreaksHalfwayStillCountsWhatItRead(t *testing.T) {
	quiet(t)
	line := `{"ts":"2026-10-29T01:00:00.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"

	kept := &newest{limit: 10}
	matched, skipped, err := readStream(&brokenReader{data: []byte(line)}, opts10(), kept, time.Now())
	if err == nil {
		t.Fatal("the read did not fail")
	}
	if matched != 1 {
		t.Errorf("the read counted %d matched lines, want 1: the line it DID read was not counted", matched)
	}
	if skipped != 0 {
		t.Errorf("the read counted %d skipped lines, want 0", skipped)
	}
	if len(kept.items) != 1 {
		t.Errorf("the answer holds %d lines, want 1", len(kept.items))
	}
}

// brokenReader hands out its data and then fails.
type brokenReader struct {
	data []byte
	off  int
}

func (r *brokenReader) Read(p []byte) (int, error) {
	if r.off >= len(r.data) {
		return 0, errors.New("the disk went away")
	}
	n := copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}

func (r *brokenReader) Close() error { return nil }

// opts10 is a read that matches everything.
func opts10() ReadOptions {
	return ReadOptions{Dir: "x", Limit: 10}
}

// The trail must not write down a payload.
//
// ⚠️ The arguments are scrubbed, and the scrubbing has two halves: the
// shape-based one (a PEM block, a "password: …" pair) and the payload one
// (a big base64 or binary blob replaced by its SIZE). The second half is
// what catches a base64 private key — it has no PEM header to recognise,
// so the shape-based half alone would write it down verbatim.
//
// ⚠️ Nothing tested that: the whole suite stayed green with the payload
// half removed, and a base64 key went into the trail file in the clear.
func TestTheTrailDoesNotWriteDownAPayload(t *testing.T) {
	quiet(t)
	dir := t.TempDir()

	// A base64 private key: no PEM header, so only the payload rule can
	// catch it.
	key := "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
	rec := reg.Record{Gate: invoke.Record{
		Call: invoke.Call{
			Name:   "jmsx_put_file",
			Server: "jumpserver-exec",
			Args:   `{"asset":"node-071","remote_path":"/tmp/k","content_base64":"` + key + `"}`,
		},
		Allowed: true,
	}}

	// ⚠️ Through the SINK, not through the file writer: the trail has two
	// exits and both of them have to carry the same, scrubbed text. The
	// file writer is package-private — Trail is the only thing that
	// writes it, and Trail scrubs once for both.
	Trail(Options{Service: "jumpserver-exec", Dir: dir})(rec)

	paths, err := filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no trail file was written: %v", err)
	}
	raw, err := os.ReadFile(paths[0])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if strings.Contains(string(raw), key) {
		t.Errorf("the trail file carries the payload verbatim:\n%s", raw)
	}
	if !strings.Contains(string(raw), "scrubbed") {
		t.Errorf("the trail file does not say that the payload was reduced:\n%s", raw)
	}
}

// A file that breaks in the MIDDLE must still have its lines counted.
//
// ⚠️ The lines that were read are already in the answer, so dropping their
// count would make "everything that matched" smaller than the answer
// itself — and "truncated" would say "no" while the answer is obviously
// cut. The path needs a stream that breaks halfway, which is why the
// reader takes a seam instead of opening the file itself.
func TestAFileThatBreaksHalfwayStillHasItsLinesCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	line := `{"ts":"2026-10-29T01:00:00.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	path := filepath.Join(dir, "audit-20261029-123-99999999.jsonl")
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// The file breaks after the first line.
	old := openTrailFile
	openTrailFile = func(string) (io.ReadCloser, error) {
		return &brokenReader{data: []byte(line)}, nil
	}
	defer func() { openTrailFile = old }()

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Total != 1 {
		t.Errorf("the answer counts %d matched lines, want 1: the line it DID read was not counted", res.Total)
	}
	if len(res.Entries) != 1 {
		t.Errorf("the answer holds %d lines, want 1", len(res.Entries))
	}
}

// A BROKEN line (not a long one) about something else must not be counted
// either.
//
// ⚠️ The long-line case and the broken-line case are two different paths
// in the reader, and a guard on one of them says nothing about the other.
func TestABrokenLineAboutAnotherToolIsNotCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	// A line that does not parse, and whose tool is another one.
	bad := `{"ts":"2026-10-29T01:00:01.000000000+08:00","service":"jumpserver-exec","tool":"jmsx_put_file","args":"unterminated`
	path := filepath.Join(dir, "audit-20261029-123-88888888.jsonl")
	if err := os.WriteFile(path, []byte(bad+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	res, err := Read(ReadOptions{Dir: dir, Tool: "jmsx_exec"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 0 {
		t.Errorf("the answer says %d lines could not be read, want 0 (the broken line is about another tool)", res.Skipped)
	}
}

// The log line and the file line must carry the SAME text.
//
// ⚠️ The trail has two exits and the scrubber rewrites the arguments (it
// re-marshals the JSON to replace a payload with its size), so the two
// exits can end up with two different strings for the same call. That is
// the "two waterlines" this package exists to end — and nothing was
// watching for it: the shape checks looked at each side on its own.
func TestTheLogLineAndTheFileLineCarryTheSameText(t *testing.T) {
	quiet(t)

	var logBuf bytes.Buffer
	logx.SetDefault(logx.NewSlogLogger("audit-test",
		logx.WithHandler(slog.NewJSONHandler(&logBuf, nil))))

	// ⚠️ The arguments carry BOTH a payload and a password shape: the
	// payload half of the scrubber is idempotent, but the shape half is
	// NOT — it rewrites `"password":"x"` into `"password=****`, which is
	// no longer valid JSON, and a second pass swallows the separator
	// after it. So only this shape makes the two exits differ.
	//
	// ⚠️ And the shapes that make the two exits differ are NOT all the
	// same shape: a key the upstream rules recognise and this repository's
	// word list does not ("mytoken") breaks it too — the upstream rules
	// eat the key's closing quote, only the backstop can put it back,
	// and a backstop that does not know the key leaves the structure
	// broken ⇒ the second pass eats one more character.
	cases := []struct {
		name string
		args string
	}{
		{"a password and a payload",
			`{"asset":"node-071","command":"hostname","password":"hunter2","content_base64":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="}`},
		{"a key with an arbitrary prefix",
			`{"asset":"node-071","mytoken":"hunter2","user":"opsuser"}`},
		{"a credential in escaped quotes",
			`{"command":"export PASSWORD=\"hunter2\""}`},
		{"a credential in a non-scalar field",
			`{"secret":{"value":"hunter2"}}`},
	}
	for _, c := range cases {
		logBuf.Reset()
		// ⚠️ A directory of its own per case: the trail is append-only,
		// so a shared directory would carry the previous case's line into
		// this one.
		caseDir := useTempTrail(t)
		Trail(Options{Service: "jumpserver-exec", Dir: caseDir})(reg.Record{
			Gate: invoke.Record{
				Call: invoke.Call{
					Name:   "jmsx_put_file",
					Server: "jumpserver-exec",
					Args:   c.args,
				},
				Allowed: true,
			},
		})

		res, err := Read(ReadOptions{Dir: caseDir})
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if len(res.Entries) != 1 {
			t.Fatalf("%s: read %d lines, want 1", c.name, len(res.Entries))
		}
		fileArgs := res.Entries[0].Args

		var logged map[string]any
		line := strings.TrimSpace(logBuf.String())
		if line == "" {
			t.Fatalf("%s: the trail wrote no log line", c.name)
		}
		if err := json.Unmarshal([]byte(line), &logged); err != nil {
			t.Fatalf("%s: the log line is not JSON: %v (%s)", c.name, err, line)
		}
		logArgs, _ := logged["args"].(string)
		if logArgs != fileArgs {
			t.Errorf("%s: the two exits disagree about the arguments:\n  log:  %s\n  file: %s",
				c.name, logArgs, fileArgs)
		}
		// And the credential must be gone on BOTH sides.
		if strings.Contains(fileArgs, "hunter2") {
			t.Errorf("%s: the file line carries the credential: %s", c.name, fileArgs)
		}
		if strings.Contains(logArgs, "hunter2") {
			t.Errorf("%s: the log line carries the credential: %s", c.name, logArgs)
		}
		// And the payload must be gone on BOTH sides.
		if strings.Contains(fileArgs, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=") {
			t.Errorf("%s: the file line carries the payload: %s", c.name, fileArgs)
		}
		if strings.Contains(logArgs, "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=") {
			t.Errorf("%s: the log line carries the payload: %s", c.name, logArgs)
		}
	}
}

// A value that was cut off mid-way reads as UNKNOWN, not as a half value.
//
// ⚠️ A half value is not equal to the tool the caller asked about, so the
// line was judged "about something else" and NOT counted — and the line
// cut in the middle of its tool name is exactly the one a caller most
// needs to hear about.
func TestACutOffValueCountsAsUnknown(t *testing.T) {
	quiet(t)
	if got := jsonStringField(`{"ts":"2026-10-29T01:00:00Z","service":"jumpserver-exec","tool":"jmsx_e`, "tool"); got != "" {
		t.Errorf("a cut-off value read as %q, want \"\" (unknown)", got)
	}
	if got := jsonStringField(`{"ts":"2026-10-29T01:00:00Z","service":"jumpserver-exec","tool":"jmsx_exec"}`, "tool"); got != "jmsx_exec" {
		t.Errorf("a whole value read as %q, want \"jmsx_exec\"", got)
	}
}

// A half-written last line of a file that has been STILL for a while is
// not "being written" — it is what a killed process leaves behind, and it
// is the last line of its file forever.
//
// ⚠️ Without the time limit every read exempted it and the line was lost
// silently, forever.
func TestAStaleHalfWrittenLineIsCounted(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	good := `{"ts":"2026-10-28T09:00:00+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"
	half := `{"ts":"2026-10-28T09:00:01+08:00","service":"jumpserver-exec","tool":"jmsx_`
	path := filepath.Join(dir, "audit-20261028-1-aaaaaaaa.jsonl")
	if err := os.WriteFile(path, []byte(good+half), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// The file has been still for longer than the grace period: the
	// process that was writing it is gone.
	stale := time.Now().Add(-2 * halfWrittenGrace)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if res.Skipped != 1 {
		t.Errorf("the answer says %d lines could not be read, want 1 (the half line of a dead process)", res.Skipped)
	}
	if res.Total != 1 {
		t.Errorf("the count says %d matched, want 1", res.Total)
	}
}

// A server that starts and never gets a tool call must not leave a file
// behind.
//
// ⚠️ On this machine 368 of the 510 trail files were empty shells of
// processes that had done nothing at all: they are facts about nothing, and
// they make the directory — and every query that scans it — heavier for
// nothing.
func TestAProcessThatWritesNothingLeavesNoFile(t *testing.T) {
	quiet(t)
	dir := t.TempDir()

	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail could not be set up")
	}
	paths, err := filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("a process that wrote nothing left %d file(s) behind", len(paths))
	}

	// The first write creates it.
	trail.write(reg.Record{Gate: invoke.Record{
		Call: invoke.Call{Name: "jmsx_exec", Server: "jumpserver-exec"},
	}})
	paths, err = filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) != 1 {
		t.Errorf("the first write left %d file(s) behind, want 1", len(paths))
	}
}

// The old files are pruned when a process starts.
//
// ⚠️ The rules exist because of how this could destroy evidence: only our
// own files, only empty ones once they are quiet, only old ones, and never
// the caller's own.
func TestTheOldTrailFilesArePruned(t *testing.T) {
	quiet(t)
	dir := t.TempDir()

	write := func(name string, content string, age time.Duration) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(p, when, when); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
		return p
	}
	line := `{"ts":"2026-10-28T09:00:00+08:00","service":"jumpserver-exec","tool":"jmsx_exec","allowed":true}` + "\n"

	emptyOld := write("audit-20261028-999911-aaaaaaaa.jsonl", "", 2*time.Hour)
	emptyNew := write("audit-20261028-999912-bbbbbbbb.jsonl", "", time.Minute)
	oldFull := write("audit-20260101-999913-cccccccc.jsonl", line, 40*24*time.Hour)
	freshFull := write("audit-20261028-999914-dddddddd.jsonl", line, time.Hour)
	foreign := write("audit-notes.txt", "my own notes", 40*24*time.Hour)
	// ⚠️ Two files that the LOOSE glob finds but that are not ours: the
	// name filter is what keeps them, and it had no guard at all.
	foreignJSONL := write("audit-notes.jsonl", "my own notes", 40*24*time.Hour)
	foreignBak := write("audit-20261028-999917-bbbbbbbb.jsonl.bak", "a backup", 40*24*time.Hour)

	// ⚠️ The seam, not the platform implementation: the question "is that
	// process alive" is answered differently on different platforms, and
	// this test is about the RULE (a live process's file is kept), not
	// about one platform's answer.
	pruneTrail(dir, 7, func(int) AliveState { return AliveYes })

	// And the OTHER rule — a DEAD process's file is judged by its age —
	// is checked with the seam as well.
	pruneTrail(dir, 7, func(int) AliveState { return AliveDead })

	if _, err := os.Stat(emptyOld); !os.IsNotExist(err) {
		t.Errorf("an empty file that has been quiet for two hours was not pruned")
	}
	if _, err := os.Stat(emptyNew); err != nil {
		t.Errorf("an empty file that may belong to a live process was pruned")
	}
	if _, err := os.Stat(oldFull); !os.IsNotExist(err) {
		t.Errorf("a file older than the retention was not pruned")
	}
	if _, err := os.Stat(freshFull); err != nil {
		t.Errorf("a file inside the retention was pruned")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("a file that is not ours was pruned: %v", err)
	}
	if _, err := os.Stat(foreignJSONL); err != nil {
		t.Errorf("a file that is not ours was pruned: %v", err)
	}
	if _, err := os.Stat(foreignBak); err != nil {
		t.Errorf("a backup of a trail file was pruned: %v", err)
	}
}

// Scrubbing the arguments keeps the document: the mask lands on the VALUE,
// the separators around it survive, and the column is still parseable JSON.
//
// ⚠️ The arguments are scrubbed more than once in production: the registry
// scrubs before handing the record over, and the trail scrubs again for its
// two exits. That is safe ONLY because the combined scrubber
// (pkg/redact.Scrub) is idempotent: the shape rules alone eat the closing
// quote of the value they mask, and a second pass of those eats the
// separator after it too. (This test used to claim the arguments were
// scrubbed "exactly once" and that the registry had stopped scrubbing;
// the registry scrubs, the trail scrubs, and the two passes agree.)
func TestScrubbingTheArgumentsKeepsTheDocument(t *testing.T) {
	in := `{"asset":"node-071","command":"hostname","password":"hunter2"}`
	once := scrubArgs(in)
	if strings.Contains(once, "hunter2") {
		t.Errorf("the credential survived: %s", once)
	}
	// ⚠️ The separator AFTER the mask is still there: the mask replaces
	// the VALUE and keeps the structure around it intact.
	if !strings.Contains(once, `password":"****`) {
		t.Errorf("the arguments do not carry the mask: %s", once)
	}
	// ⚠️ And the result is STILL valid JSON: the backstop replaces the
	// VALUE and keeps the structure, so the column a reader parses does
	// not fall apart. (The combined scrubber keeps the quote and the structure; the shape
	// rules alone would eat it — see pkg/redact.Scrub.)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(once), &parsed); err != nil {
		t.Errorf("the arguments are not valid JSON after scrubbing: %v (%s)", err, once)
	}
	if !strings.Contains(once, `"asset":"node-071"`) {
		t.Errorf("the arguments lost the fields around the mask: %s", once)
	}
	// ⚠️ The separator AFTER the mask is where a destructive mask shows up
	// first: the mask has to be followed by the closing quote or comma of
	// the field it was in.
	tail := once[strings.Index(once, `"password":"****"`)+len(`"password":"****"`):]
	if tail == "" || (tail[0] != '}' && tail[0] != ',') {
		t.Errorf("the separator after the mask is gone: %s", once)
	}

	// ⚠️ And a SECOND pass changes nothing: the registry and the trail
	// both scrub, and that is only safe because the combination is
	// idempotent (pkg/redact.Scrub says why). Pin it at this exit too.
	if twice := scrubArgs(once); twice != once {
		t.Errorf("the scrubber is not idempotent: %q became %q", once, twice)
	}
}

// A directory that cannot be written to means the trail is OFF, and the
// check has to say so.
//
// ⚠️ The old check only asked whether the directory EXISTS — a root-owned
// or read-only directory passed it, the writer's open failed, and the
// process kept NO file trail for its whole life while the doctor said
// everything was fine.
func TestAnUnwritableTrailDirectoryIsNotHealthy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0o700)

	st, reason, detail := CheckTrail(dir)
	if st == jms.Status_ok {
		t.Errorf("a directory that cannot be written to reported ok (%s)", detail)
	}
	if reason != ReasonUnreadable {
		t.Errorf("an unwritable directory reported the reason %q, want %q", reason, ReasonUnreadable)
	}
	if advice := Advice(reason); advice == "" {
		t.Error("an unhealthy trail has no advice")
	}
}

// A file that belongs to a LIVE process is never removed.
//
// ⚠️ The process holds it open: removing the name would leave that
// process writing into a file with no directory entry, and its trail
// would be gone, silently. The mtime rules cannot tell a dead process
// from an idle one — a server that has not been called for an hour looks
// exactly like a corpse — so the pid in the name decides.
func TestTheFileOfALiveProcessIsNeverPruned(t *testing.T) {
	quiet(t)
	dir := t.TempDir()

	// This process is alive by definition.
	name := fmt.Sprintf("audit-20261028-%d-abcdefab.jsonl", os.Getpid())
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Empty and quiet for far longer than the grace period: by the mtime
	// rules alone this file would be removed.
	stale := time.Now().Add(-10 * time.Hour)
	if err := os.Chtimes(p, stale, stale); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	pruneTrail(dir, 7, processAlive)

	if _, err := os.Stat(p); err != nil {
		t.Errorf("the file of a live process was pruned: %v", err)
	}
}

// A text that merely CONTAINS something that looks like a mark must still
// be scrubbed.
//
// ⚠️ The idempotency guard used to be a loose pattern, and it skipped the
// WHOLE text when the text contained `"x=****` — so a secret elsewhere in
// the same text survived into the trail. The probe that caught it:
// `{"note":"x=****","password":"hunter2"}` kept the password.
func TestATextThatLooksLikeAMarkIsStillScrubbed(t *testing.T) {
	// The arguments column.
	got := scrubArgs(`{"cmd":"ls","note":"x=****","password":"hunter2"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("the arguments kept the secret: %s", got)
	}
	// ⚠️ And the columns that are scrubbed exactly once — they must never
	// be skipped at all. The shape used here is one logredact DOES
	// recognise, so the assertion is about the guard and not about what
	// the scrubber can do.
	got = failureText(`the tool said {"token=****","password":"hunter2"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("the error column kept the secret: %s", got)
	}
	got = refusedText(`refused because {"token=****","password":"hunter2"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("the refusal column kept the secret: %s", got)
	}
}

// The retention window must never overflow.
//
// ⚠️ A retention of 200000 days ("keep it for a very long time")
// multiplies out past the largest int64 duration, wraps around to a
// NEGATIVE number — and a negative window says "this file is older than
// the window" about EVERY file ⇒ the whole trail is deleted.
func TestTheRetentionWindowNeverOverflows(t *testing.T) {
	for _, days := range []int{1, 7, 365, 106751, 106752, 200000, 1 << 30} {
		w := retentionWindow(days)
		if w <= 0 {
			t.Errorf("a retention of %d days gave a window of %v", days, w)
		}
	}
	// And a huge retention must not delete a file that is younger than it.
	dir := t.TempDir()
	name := "audit-20260101-999911-cccccccc.jsonl"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(`{"ts":"2026-01-01T00:00:00Z","service":"s","tool":"t","allowed":true}`+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	pruneTrail(dir, 200000, processAlive)
	if _, err := os.Stat(p); err != nil {
		t.Errorf("a retention of 200000 days deleted a 40-day-old file: %v", err)
	}
}

// The scrubber must catch a credential in EVERY shape, and the shape of
// the text around it must not matter.
//
// ⚠️ The guard that used to sit here (skip the whole text when it looked
// like it had been scrubbed) was bypassable in six ways, and each of them
// left a password in the trail: a value that merely CONTAINS `=****`,
// with a comma / space / tab / newline / backslash / an escaped quote
// after it. The scrubber now works INSIDE the JSON structure, so there
// is no guard to bypass.
func TestACredentialIsCaughtWhateverSurroundsIt(t *testing.T) {
	shapes := []string{
		`{"note":"x=****","password":"hunter2"}`,
		`{"note":"x=****,","password":"hunter2"}`,
		`{"note":"x=**** ","password":"hunter2"}`,
		`{"note":"x=****\t","password":"hunter2"}`,
		`{"note":"x=****\n","password":"hunter2"}`,
		`{"note":"x=****\\","password":"hunter2"}`,
		`{"cmd":"echo \"password=****\"","password":"hunter2"}`,
		`{"nested":{"password":"hunter2"}}`,
	}
	for _, in := range shapes {
		got := scrubArgs(in)
		if strings.Contains(got, "hunter2") {
			t.Errorf("the credential survived %s -> %s", in, got)
		}
	}
}

// A file whose process cannot be judged must fall back to the mtime
// rules.
//
// ⚠️ "I cannot tell" must not be the same as "it is dead": on Windows
// the question cannot be answered, and answering "alive" there
// SHORT-CIRCUITED both mtime rules — so on Windows the directory was
// never pruned at all.
func TestAnUnknownProcessFallsBackToTheAgeRules(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	line := `{"ts":"2026-01-01T00:00:00Z","service":"s","tool":"t","allowed":true}` + "\n"
	name := "audit-20260101-999911-cccccccc.jsonl"
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(line), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Unknown: the file is judged by its age, and 40 days is past the
	// retention ⇒ removed.
	pruneTrail(dir, 7, func(int) AliveState { return AliveUnknown })
	if _, err := os.Stat(p); err == nil {
		t.Errorf("an unknown process's file was kept although it is past the retention")
	}
}

// The scrubber must mask the credential whatever its shape — and it must
// leave the REST of the value alone.
//
// ⚠️ Two things went wrong in one round:
//   - a NUMBER value was not masked at all (the structure-internal
//     scrubber only handled strings, and the text scrubber's value
//     pattern does match numbers) ⇒ a numeric password landed in the
//     trail in the clear;
//   - a value containing a NEWLINE was not masked (the pair was built
//     from the DECODED value, where the newline is a real LF, while the
//     scrubber's value pattern excludes LF — the JSON text has it
//     escaped as two characters, and that is the form the scrubber sees).
//
// ⚠️ And the command must SURVIVE: the trail's whole point is "who
// tried to run what", so masking the whole value would throw the
// command away.
func TestTheCredentialIsMaskedWhateverItsShape(t *testing.T) {
	cases := []string{
		`{"password":"hunter2"}`,
		`{"password":12345678}`,
		`{"token":987654321}`,
		`{"password":"s3cret\nline2"}`,
		`{"password":true}`,
	}
	for _, in := range cases {
		got := scrubArgs(in)
		if strings.Contains(got, "hunter2") || strings.Contains(got, "12345678") ||
			strings.Contains(got, "987654321") || strings.Contains(got, "s3cret") {
			t.Errorf("the credential survived %s -> %s", in, got)
		}
	}
	// The command stays: only the credential inside it is masked.
	got := scrubArgs(`{"command":"export PASSWORD=hunter2 && ls -la"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("the credential survived: %s", got)
	}
	if !strings.Contains(got, "ls -la") {
		t.Errorf("the command was thrown away with the credential: %s", got)
	}
}

// The SAME credential must look the SAME in every column of one line.
//
// ⚠️ A column that was masked while its neighbour was not is two water
// levels in one line — and that is exactly what happens when the
// credential-key backstop is applied to the arguments only: the error
// column (which carries the tool's own message, often quoting the
// credential back) kept the credential in the clear.
func TestTheSameCredentialLooksTheSameInEveryColumn(t *testing.T) {
	args := scrubArgs(`{"password":"p&ssw0rd"}`)
	errText := failureText(`the tool said: {"password":"p&ssw0rd"}`)
	for _, col := range []string{args, errText} {
		if strings.Contains(col, "p&ssw0rd") {
			t.Errorf("the credential is in the clear: %s", col)
		}
	}
	// And the mask is spelled the same way on both sides.
	if !strings.Contains(args, `password":"****`) {
		t.Errorf("the arguments are not masked the expected way: %s", args)
	}
	if !strings.Contains(errText, `password":"****`) {
		t.Errorf("the error column is not masked the same way: %s", errText)
	}
}

// A credential must be masked WHOLE, whatever shape it has.
//
// ⚠️ The upstream scrubber cannot always do that: its value pattern
// excludes `&` (so nothing matches at all), and it stops at the first
// inner quote (so only the prefix is masked and the tail stays clear).
// The backstop masks the whole value of every field whose NAME says it is
// a credential.
func TestACredentialIsMaskedWholeWhateverItsShape(t *testing.T) {
	cases := []string{
		`{"asset":"node","password":"p&ssw0rd"}`,
		`{"asset":"node","password":"s3cret\"line2"}`,
		`{"asset":"node","password":12345678}`,
		`{"asset":"node","password":true}`,
		`{"asset":"node","password":"s3cret\nline2"}`,
		`{"asset":"node","token":"abc","api_key":"def"}`,
	}
	for _, in := range cases {
		got := scrubArgs(in)
		for _, secret := range []string{"p&ssw0rd", "line2", "12345678", "abc", "def"} {
			if strings.Contains(got, secret) {
				t.Errorf("the credential %q survived %s -> %s", secret, in, got)
			}
		}
	}
	// ⚠️ And the command must SURVIVE: the field is not named like a
	// credential, so the backstop leaves it alone.
	got := scrubArgs(`{"command":"export PASSWORD=hunter2 && ls -la"}`)
	if strings.Contains(got, "hunter2") {
		t.Errorf("the credential survived: %s", got)
	}
	if !strings.Contains(got, "ls -la") {
		t.Errorf("the command was thrown away with the credential: %s", got)
	}
}

// A reused pid must not pin a dead file forever.
//
// ⚠️ The pid in a trail file name can be REUSED: a dead process's file
// would then look like a live process's file, and the pruner would keep
// it forever — so the directory would grow past what it promises to
// keep.
//
// ⚠️ Removing it is safe because the writer REOPENS the file when it
// finds it gone (reopenIfGone) — so the process does not go on writing
// into an unlinked inode.
func TestAReusedPidDoesNotPinADeadFile(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	// This process is alive — and its pid is in the name.
	name := fmt.Sprintf("audit-20260101-%d-abcdefab.jsonl", os.Getpid())
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(`{"ts":"2026-01-01T00:00:00Z","service":"s","tool":"t","allowed":true}`+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// The pid is alive, but the file is past the retention period.
	pruneTrail(dir, 7, func(int) AliveState { return AliveYes })
	if _, err := os.Stat(p); err == nil {
		t.Errorf("a file past the retention period was pinned by a reused pid")
	}
}

// A file that the pruner removed must not swallow the next line.
//
// ⚠️ The writer holds the file open, so removing the NAME leaves it
// writing into an unlinked inode — and every line after that would be
// invisible, with no error anywhere.
func TestTheWriterReopensItsFileWhenThePrunerTookIt(t *testing.T) {
	quiet(t)
	dir := t.TempDir()
	trail := openTrail(Options{Service: "jumpserver-exec", Dir: dir})
	if trail == nil {
		t.Fatal("the trail could not be set up")
	}
	defer func() {
		if trail.f != nil {
			trail.f.Close()
		}
	}()

	write := func(tool string) {
		trail.write(reg.Record{Gate: invoke.Record{
			Call:    invoke.Call{Name: tool, Server: "jumpserver-exec"},
			Allowed: true,
		}})
	}
	write("jmsx_first")

	// The pruner takes the file away (this is what a reused pid does).
	if err := os.Remove(trail.path); err != nil {
		t.Fatalf("remove: %v", err)
	}

	write("jmsx_second")

	res, err := Read(ReadOptions{Dir: dir})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	found := map[string]bool{}
	for _, e := range res.Entries {
		found[e.Tool] = true
	}
	if !found["jmsx_second"] {
		t.Errorf("the line written after the file was taken away was lost: %+v", res.Entries)
	}
}
