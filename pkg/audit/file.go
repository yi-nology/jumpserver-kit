package audit

// file.go is the part of the trail that SURVIVES the process.
//
// Why it exists. The trail used to be one log line per tool call, written to
// the server's stderr. That is a good place to read it while the server is
// running and a bad place to look for it afterwards: stderr belongs to
// whoever started the process, and a host that does not keep it keeps
// nothing.
//
// That matters most for the case the trail exists for. A DANGEROUS command
// refused for want of a confirmation never reaches the bastion, so the
// bastion has no session and no log line for it — the refusal leaves no
// trace on either side unless THIS machine keeps one.
//
// So the trail is also written to a file: one file per process, one JSON
// object per line, 0600, in a directory the operator points at.
//
// One file per process, and not one file for everything: two servers may run
// at the same time, and appending to the same file from two processes is a
// portability problem (and a locking problem on Windows) for no benefit —
// the lines carry a timestamp and a service name, so they can be merged when
// they are read.
//
// Two things the file must not become: a place where secrets pile up, and a
// place that grows without end. The first is handled by scrubbing the
// arguments before they are written; the second by rotating the file once it
// gets too big.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oekit/logx"

	"github.com/yi-nology/jumpserver-kit/pkg/fspath"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/textx"
)

// MaxTrailBytes is how big one trail file may get before it is rotated.
//
// The trail is not a log archive: it is the evidence for the last few hours
// of what was attempted on this machine. A file that grew without end would
// be read (and kept) long after anyone cares about the oldest line in it.
//
// ⚠️ It is a HARD bound, not a wish: when the rotation fails, the file
// trail stops instead of growing past it (see rotate). The lines already
// in the file stay there; what is lost is the FILE trail for the rest of
// the process's life — the log line still carries every call.
const MaxTrailBytes = 32 << 20 // 32 MiB

// OverCap reports the trail files that are over the size cap.
//
// A file over the cap means the rotation did NOT happen — and the writer
// stops the file trail when it cannot rotate. So this is how the doctor
// says out loud what the log line said once: the file trail stopped there.
func OverCap(dir string) ([]string, error) {
	paths, err := filepath.Glob(filepath.Join(fspath.ExpandHome(dir), trailGlob))
	if err != nil {
		return nil, err
	}
	var over []string
	for _, p := range paths {
		if !trailFileName.MatchString(filepath.Base(p)) {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.Size() > MaxTrailBytes {
			over = append(over, p)
		}
	}
	return over, nil
}

// Entry is one line of the trail.
//
// It is a different shape from the log line on purpose. The log line is for
// a human reading a log, and it spells the gate's stages as dynamic keys
// (stage.risk, stage.confirm, ...). A file that a PROGRAM has to read back
// cannot have dynamic keys, so the stages are a list here.
type Entry struct {
	// Ts is when the call CLOSED — the moment the trail wrote the line
	// down (RFC3339, with nanoseconds).
	//
	// ⚠️ It is the moment the call ENDED, not the moment it was made.
	// The gate's record carries how long a call took but not when it
	// started, so the end is the one moment that is actually known — and
	// the difference between the two is the length of the call. The
	// `Since` filter compares against this moment.
	Ts string `json:"ts"`
	// Service is the server that made the call.
	Service string `json:"service"`
	// Tool is the tool that was called.
	Tool string `json:"tool"`
	// Client is the MCP client that made the call — the "who" of the
	// question "who tried to run rm -rf". Empty when the client did not
	// say who it is.
	//
	// It is the name the client reported for itself, so it is a lead and
	// not evidence.
	Client string `json:"client,omitempty"`
	// Args is what it was called with — scrubbed, cut short, and with the
	// heavy payloads reduced to their size.
	Args string `json:"args,omitempty"`
	// Allowed is whether the call was STOPPED.
	//
	// It is false for a call the gate stopped, for a call the tool refused,
	// and for a rehearsal — all three mean the same thing to whoever reads
	// the trail later: nothing ran.
	//
	// ⚠️ It is TRUE for a call that broke: it went through and failed. The
	// failure is in the `failed` and `error` columns, and whether it
	// reached the machine is the `delivery` column's business.
	Allowed bool `json:"allowed"`
	// Refused is why the tool refused to act, when it did.
	//
	// It is empty for a rehearsal: a rehearsal was not stopped, it was
	// asked for. Recording it as a refusal is a false alarm.
	Refused string `json:"refused,omitempty"`
	// DryRun says the call was a rehearsal.
	DryRun bool `json:"dry_run,omitempty"`
	// WouldExecute says a rehearsal would have run the command had it been
	// confirmed. It is absent when the answer did not say — "unknown" and
	// "it would not have run" are different facts.
	WouldExecute *bool `json:"would_execute,omitempty"`
	// Stages is the gate's reasoning, stage by stage.
	Stages []Stage `json:"stages,omitempty"`
	// DurationMs is how long the call took.
	DurationMs int64 `json:"duration_ms"`
	// OutBytes is how much the answer was.
	OutBytes int64 `json:"out_bytes"`
	// Error is why the call closed with an error, when it did.
	//
	// It carries BOTH kinds of error, and the `failed` column below is what
	// tells them apart: a call the GATE stopped (nothing ran) and a call
	// whose work FAILED (it may already have reached the machine) are very
	// different facts, and "what broke here" must not answer with the
	// first one.
	Error string `json:"error,omitempty"`
	// Failed says the TOOL's work failed — it answered with an error, or
	// its body returned an error.
	//
	// It is NOT set when the gate stopped the call: the gate stopping
	// something is the gate working, not a failure. Nothing ran in either
	// case, but only one of them is a broken call.
	Failed bool `json:"failed,omitempty"`
	// Delivery says how far the action got, when the error knew.
	//
	// "not_sent" means it never left this process — retrying is safe.
	// "maybe_sent" means it may ALREADY be running on the machine — it is
	// never replayed. It is absent when nobody said, which is not the
	// same as "it did not get there".
	Delivery string `json:"delivery,omitempty"`
}

// Stage is one step of the gate's reasoning.
type Stage struct {
	// Stage is what was checked.
	Stage string `json:"stage"`
	// Allow is whether that step let the call through.
	Allow bool `json:"allow"`
	// Reason is why.
	Reason string `json:"reason,omitempty"`
}

// clientNameMax is how long a client name may be in the trail.
//
// The name comes from the client, so its length is the client's choice; the
// arguments beside it are cut short, and this is cut short too.
const clientNameMax = 128

// clientName is the client name as it is written down: trimmed, and cut to
// a length the trail can carry.
//
// The trimming matters for the query as much as for the storage: a filter
// that trims what it compares against would not match a stored name that
// was stored with spaces.
//
// ⚠️ The cut is on a RUNE boundary, not a byte boundary. A byte slice that
// lands inside a multi-byte character leaves invalid UTF-8 behind, and the
// JSON encoder turns those bytes into U+FFFD — so the name written down is
// not the name that was sent, and a filter carrying the original name never
// matches the line. The cut lives in pkg/textx for that reason — and the
// name keeps no "..." on purpose: a name should still read as a name.
func clientName(name string) string {
	return textx.Trunc(strings.TrimSpace(name), clientNameMax, "")
}

// trailWriter is what the trail file is written through.
//
// ⚠️ It is an interface so that a test can hand the writer a file that
// WRITES HALF A LINE and then fails — which is what a full disk does, and
// what leaves a half line behind in the file. That half line is the shape
// of the worst thing this package can produce: it glues itself to the next
// line, and then BOTH lines are unparseable, and then both are gone —
// silently, because the reader cannot tell a broken line from a line that
// was never finished.
type trailWriter interface {
	io.Writer
	io.Closer
	Stat() (os.FileInfo, error)
}

// trailFile is the file one process writes its trail to.
type trailFile struct {
	mu sync.Mutex
	f  trailWriter
	// opened says whether the file has been opened yet.
	//
	// ⚠️ It is a field of its own because "not opened yet" and "the file
	// trail STOPPED" both leave f == nil, and they call for opposite
	// behaviour: the first one means "open it now", the second one means
	// "the rotation failed and the file trail is over".
	opened bool
	// path is where the file lives; it is what gets rotated.
	path string
	// size is how much has been written to it.
	size int64
	// max is how big it may get before it is rotated.
	//
	// It is a field and not the constant so that a test can lower it: the
	// rotation is the one thing that has to be exercised end to end, and a
	// test that had to write 32 MiB to reach it would not be run.
	max int64
}

// FileName is the name of a trail file.
//
// It is exported because the reader recognises trail files by this shape
// (see trailFileName), and a fixture that made its own name up would be a
// fixture the reader ignores — a test that stops testing anything without
// failing. The writer and the reader share this one function, so the two
// cannot drift apart.
func FileName() string {
	return fmt.Sprintf("audit-%s-%d-%s.jsonl",
		time.Now().Format("20060102"), os.Getpid(), randomSuffix())
}

// openTrail opens this process's trail file.
//
// It returns nil when there is no directory to write to — which is what
// "the file trail is off" means. The trail must never be the reason a server
// refuses to start.
func openTrail(opts Options) *trailFile {
	if strings.TrimSpace(opts.Dir) == "" {
		return nil
	}
	dir := fspath.ExpandHome(opts.Dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		logx.Error("the audit trail directory could not be created; the file trail is off",
			"dir", dir, "err", err)
		return nil
	}
	// The name carries a random suffix as well as the pid: a pid is reused
	// on a long-lived host, and a new process must not append to a dead
	// one's file.
	path := filepath.Join(dir, FileName())

	// ⚠️ The old files are pruned HERE, at the start of a process, and
	// not by the reader. The trail is one file per PROCESS, so the number
	// of files grows with the number of restarts — and a directory that
	// only ever grows is a directory that eventually makes every query
	// slow (the reader opens every file it finds).
	pruneTrail(dir, opts.RetentionDays, processAlive)

	// ⚠️ The file is NOT opened here. It is opened by the first write.
	//
	// A server that starts and never gets a tool call used to leave an
	// EMPTY file behind — and on this machine 368 of the 510 trail files
	// were empty shells of processes that had done nothing at all. They
	// are facts about nothing, and they make the directory (and every
	// query that scans it) heavier for nothing.
	return &trailFile{path: path, max: MaxTrailBytes}
}

// pruneTrail removes the trail files that are no longer worth keeping.
//
// ⚠️ Three rules, each of which exists because of a way this could destroy
// evidence:
//
//   - only files THIS package wrote are touched (the reader recognises the
//     same shape) ⇒ a neighbouring file, a note or a backup is never
//     deleted;
//   - an EMPTY file is only removed once it has been quiet for a while —
//     a process that started and has not written yet still has an empty
//     file, and deleting it would leave that process writing into a file
//     with no directory entry (its trail would be gone, silently);
//   - ⚠️ there is NO "the caller's own file" rule: the file is created by
//     the FIRST WRITE (a server that is never called leaves nothing
//     behind), so at this moment the caller's own file does not exist yet
//     and there is nothing to protect. What protects a live process's
//     file is the PID check above.
func pruneTrail(dir string, retentionDays int, alive func(int) AliveState) {
	paths, err := filepath.Glob(filepath.Join(dir, trailGlob))
	if err != nil {
		return
	}
	now := time.Now()
	failed := 0
	var firstErr error
	for _, p := range paths {
		base := filepath.Base(p)
		if !trailFileName.MatchString(base) {
			continue
		}
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		// ⚠️ A file that belongs to a LIVE process is NEVER removed.
		//
		// The process holds it open: removing the name would leave that
		// process writing into a file with no directory entry, and its
		// trail would be gone, silently. The mtime rules below cannot
		// tell a dead process from an idle one — a server that has not
		// been called for an hour looks exactly like a corpse — so the
		// pid in the name decides.
		age := now.Sub(info.ModTime())
		// ⚠️ The two decisions are kept apart so that each can be
		// disturbed on its own: "is the process alive" and "is the file
		// still inside the retention period". A single condition would
		// make a mutation of one of them indistinguishable from a
		// mutation of the other — and the sweep would report a healthy
		// guard as fake.
		//
		// ⚠️ A live process's file is kept — but only while it is INSIDE
		// the retention period. The pid in the name can be REUSED, and a
		// reused pid would pin a dead file forever: the directory would
		// grow past what it promises to keep.
		//
		// ⚠️ Removing it is safe because the writer REOPENS the file
		// when it finds it gone (see reopenIfGone) — so the process does
		// not go on writing into an unlinked inode.
		if pid, ok := trailPid(base); ok && alive(pid) == AliveYes && keepByAge(retentionDays, age) {
			continue
		}
		switch {
		case info.Size() == 0:
			// An empty file is a fact about nothing — but only once it is
			// old enough that no live process still holds it open.
			if age < emptyFileGrace {
				continue
			}
		case retentionDays > 0:
			if age < retentionWindow(retentionDays) {
				continue
			}
		default:
			// Retention is off: keep everything that has something in it.
			continue
		}
		if err := os.Remove(p); err != nil {
			// ⚠️ One line, not one per file: a read-only directory with
			// five hundred files in it would otherwise print five hundred
			// error lines at every start.
			failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
	}
	if failed > 0 {
		// ⚠️ The cause is kept: "count=500" alone does not tell the
		// operator whether it is permissions, a read-only filesystem or
		// somebody else's file.
		logx.Error("some old audit trail files could not be removed",
			"count", failed, "dir", dir, "err", firstErr)
	}
}

// AliveState is what "is that process still running" can answer.
type AliveState int

const (
	// AliveUnknown means the question could not be answered (the platform
	// does not offer a way). The caller then falls back to the mtime
	// rules.
	AliveUnknown AliveState = iota
	// AliveYes means the process is running: its file must not be removed.
	AliveYes
	// AliveDead means the process is gone: its file is only kept if it is
	// still inside the retention period.
	AliveDead
)

// keepByAge says whether a file is still inside the retention period.
//
// ⚠️ A retention of zero (or less) means "keep them all" — so nothing is
// ever removed on account of its age.
func keepByAge(retentionDays int, age time.Duration) bool {
	if retentionDays <= 0 {
		return true
	}
	return age < retentionWindow(retentionDays)
}

// trailPid reads the pid out of a trail file name.
//
// ⚠️ It is the same shape the reader recognises, so the pid is where the
// reader would find it: the name is "audit-<date>-<pid>-<suffix>.jsonl".
// A name that does not carry a pid (a foreign file that happens to match
// the glob) yields nothing, and the caller then treats it as "no process
// to protect" — which is why the caller also checks the name's shape.
func trailPid(base string) (int, bool) {
	parts := strings.Split(base, "-")
	if len(parts) < 4 {
		return 0, false
	}
	pid, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, false
	}
	return pid, true
}

// MaxRetentionDays is the longest retention the pruner will honour.
//
// ⚠️ It is a century, and it is also the CLAMP: the multiplication
// overflows past it, and an overflowed window is negative — and a negative
// window says "this file is older than the window" about EVERY file.
//
// ⚠️ It is exported because the answer has to say the same number the
// pruner uses: a note that promises more than the machine keeps is a lie
// about the evidence.
const MaxRetentionDays = 36500

// retentionWindow is how long a trail file is kept.
//
// ⚠️ It is CLAMPED, and it has to be: the arithmetic overflows. A
// retention of 200000 days ("keep it for a very long time") multiplies
// out past the largest int64 duration, wraps around to a NEGATIVE
// number — and a negative window says "this file is older than the
// window" about EVERY file ⇒ the whole trail is deleted.
//
// ⚠️ The clamp is at a century: no real trail needs longer, and a value
// beyond it is treated as "keep it for a century" rather than "delete
// everything".
func retentionWindow(days int) time.Duration {
	if days > MaxRetentionDays {
		days = MaxRetentionDays
	}
	return time.Duration(days) * 24 * time.Hour
}

// emptyFileGrace is how long an EMPTY trail file is left alone.
//
// ⚠️ The reason it is not "immediately": a server that has started but
// not been called yet still holds an empty file, and removing it would
// leave that server writing into a file that has no directory entry —
// its trail would be gone, and nothing would say so.
const emptyFileGrace = time.Hour

// openAppend opens a trail file for APPENDING.
//
// ⚠️ Append, never truncate: the name carries a random suffix, so a name
// that already exists means the suffix collided with an earlier run — and
// truncating would erase that run's trail. It is a function of its own so
// that this can be tested (nothing else lets a test control the name).
func openAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

// write appends one record.
//
// A line that cannot be written is logged and dropped. Losing a line of the
// trail is bad, but failing a tool call because the trail could not be
// written is worse: the call itself is the thing that was asked for.
func (t *trailFile) write(rec reg.Record) {
	if t == nil {
		return
	}
	line, err := json.Marshal(entryOf(rec))
	if err != nil {
		logx.Error("an audit trail line could not be encoded", "err", err)
		return
	}
	line = append(line, '\n')
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.opened {
		// The first write of this process opens the file (see openTrail).
		f, err := openAppend(t.path)
		if err != nil {
			logx.Error("the audit trail file could not be opened; the file trail is off",
				"path", t.path, "err", err)
			// The file trail is over for this process — but the LOG line
			// still carries every call, so the trail is not lost, only
			// the file half of it.
			t.opened = true
			return
		}
		t.f = f
		t.opened = true
		t.size = fileSize(f)
	}
	// ⚠️ The pruner may have removed this file (the pid in its name can
	// be reused, and a file past the retention period goes even then).
	// Writing into the unlinked inode would lose the line silently, so
	// the file is reopened when it is gone.
	//
	// ⚠️ It runs BEFORE the nil check below, because a failed reopen
	// leaves t.f nil — and with the check first, the reopen would never
	// be reached again: one transient failure (a full disk, a directory
	// briefly read-only) would silence the file trail for the rest of
	// the process, with one error line and no further trace.
	t.reopenIfGone()
	if t.f == nil {
		// The rotation failed earlier, or the file could not be reopened:
		// the file trail stops there.
		return
	}
	// The file is rotated before it grows past its cap, so a long-lived
	// process cannot fill the disk with its own trail.
	//
	// ⚠️ When the rotation FAILS the file trail STOPS (rotate says so):
	// the cap is a bound on the disk, and a bound a broken filesystem can
	// lift is not a bound. The lines already written stay in the file, and
	// the log line still carries every call.
	if t.size+int64(len(line)) > t.max {
		if !t.rotate() {
			return
		}
	}
	if t.f == nil {
		return
	}
	n, err := t.f.Write(line)
	t.size += int64(n)
	if err != nil {
		logx.Error("an audit trail line could not be written", "err", err)
		// ⚠️ A partial write leaves half a line in the file, and half a
		// line has no newline in it — so the NEXT line is appended to it
		// and the two of them become one unparseable line. Two lines lost
		// for one failure, and the reader cannot tell that anything was
		// lost at all.
		//
		// So the half line is sealed off with a newline: it becomes a line
		// of its own, broken but separate, and the reader skips THAT one
		// and still reads the ones after it. A full disk is exactly the
		// case this is for.
		//
		// The newline may fail too — the disk is full. Then the glue
		// happens anyway, and the only thing left is the log line, which
		// says the write failed.
		if n > 0 {
			if _, e := t.f.Write([]byte{'\n'}); e == nil {
				t.size++
			}
		}
	}
}

// rotate moves the current file aside and starts a new one.
//
// It reports whether the rotation worked.
//
// ⚠️ There is deliberately NO "remove the previous .1 first" step. The
// rename REPLACES its destination atomically — POSIX rename(2) does, and
// Go's Windows implementation asks for the same — so the archived
// generation is only ever replaced by a rename that actually worked.
// A removal before the rename destroys that generation even when the
// rename then fails, and the trail would answer "nothing matched" over a
// generation that was there a moment ago.
//
// ⚠️ When the rotation FAILS the file trail STOPS here. The alternative —
// keeping appending — lifts the cap for good: the file would grow past it
// and keep growing, and every call would try the rotation again (closing
// the file, reopening it, logging an error). Stopping keeps the disk
// bounded, keeps every line already written, and leaves the LOG line as
// the record for the rest of the process's life.
func (t *trailFile) rotate() bool {
	_ = t.f.Close()
	t.f = nil
	if err := os.Rename(t.path, t.path+".1"); err != nil {
		logx.Error("the audit trail file could not be rotated; the file trail stops here",
			"path", t.path, "err", err)
		return false
	}
	f, err := os.OpenFile(t.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		logx.Error("the audit trail file could not be reopened; the file trail is off",
			"path", t.path, "err", err)
		return false
	}
	t.f = f
	t.size = 0
	return true
}

// reopenIfGone makes sure the file this process writes to still exists.
//
// ⚠️ The pruner removes a file that is older than the retention period
// even when the pid in its name is alive — the pid may have been reused,
// and a reused pid would pin a dead file forever. Writing into the
// unlinked inode would lose the line silently, so the trail is put back.
func (t *trailFile) reopenIfGone() {
	if _, err := os.Stat(t.path); err == nil {
		return
	}
	f, err := openAppend(t.path)
	if err != nil {
		logx.Error("the audit trail file is gone and could not be reopened",
			"path", t.path, "err", err)
		t.f = nil
		t.opened = true
		return
	}
	_ = t.f.Close()
	t.f = f
	t.size = fileSize(f)
}

// fileSize is how much the file holds, or zero when it cannot be told.
//
// ⚠️ Zero means "unknown" here, and the only caller is openTrail — where
// the file was just created under a name that carries a random suffix, so
// it is empty unless the random suffix collided with an earlier run. That
// is the one case where "unknown" is the wrong answer, and it costs at
// most one file's worth of the cap.
func fileSize(f trailWriter) int64 {
	info, err := f.Stat()
	if err != nil {
		return 0
	}
	return info.Size()
}

// entryOf turns a call record into the line that goes into the file.
func entryOf(rec reg.Record) Entry {
	gate := rec.Gate
	e := Entry{
		Ts:      time.Now().Format(time.RFC3339Nano),
		Service: gate.Call.Server,
		Tool:    gate.Call.Name,
		Client:  clientName(gate.Call.Caller),
		// ⚠️ The arguments are not scrubbed HERE — the registry scrubs
		// them and the trail scrubs them again; the two passes together
		// are idempotent (on valid JSON), so both exits read the same
		// value.
		//
		// The trail has two exits (the log and the file) and they must
		// carry the SAME string — and the scrubber is NOT idempotent:
		// logredact rewrites `"password":"x"` into `"password=****`, which
		// is no longer valid JSON, and a second pass swallows the
		// separator after it. Scrubbing here as well as in Trail would
		// have the two exits write two different strings — and the file's
		// copy would be the broken one (a missing comma between two
		// fields).
		//
		// So the scrubbing happens in TWO places — the registry and Trail —
		// and the COMBINATION is idempotent (on valid JSON), so both exits
		// read the same value.
		Args:       truncate(gate.Call.Args, 500),
		Allowed:    allowed(rec),
		DryRun:     gate.DryRun(),
		OutBytes:   int64(gate.OutBytes),
		DurationMs: gate.Duration.Milliseconds(),
	}
	if refused(gate) {
		// ⚠️ Scrubbed like the error column: the refusal reason and the
		// error come from the same answer, and a line whose two columns
		// sit on different water levels is a line nobody can read safely.
		e.Refused = refusedText(gate.Outcome.RefusalReason())
	}
	if gate.DryRun() {
		e.WouldExecute = rec.WouldExecute
	}
	switch {
	case gate.Err != nil:
		e.Error = failureText(gate.Err.Error())
	case rec.ToolError != "":
		// The tool answered with an error result: the protocol call
		// succeeded, the work did not. See the same field in audit.go.
		e.Error = failureText(rec.ToolError)
	case rec.Failure != "":
		// The tool reported the failure inside the answer: the call
		// succeeded, the work did not. See the same field in audit.go.
		e.Error = failureText(rec.Failure)
	}
	e.Failed = toolFailed(rec)
	if rec.Delivery != "" {
		e.Delivery = rec.Delivery
	}
	for _, st := range gate.Stages {
		e.Stages = append(e.Stages, Stage{
			Stage:  st.Stage,
			Allow:  st.Allow,
			Reason: reasonText(st.Reason),
		})
	}
	return e
}

// randomSuffix is a short random string, so that two processes never write
// to the same file even when they share a pid (a reused one).
//
// ⚠️ The fallback has to have the SAME SHAPE as the real thing (8 hex
// characters): the reader recognises trail files by their name, so a
// four-character fallback would produce a file the reader does not know —
// and that would make the whole process's trail invisible, silently.
func randomSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return randomSuffixFallback
	}
	return hex.EncodeToString(b[:])
}

// randomSuffixFallback is what a failed rand.Read falls back to.
//
// ⚠️ It has to have the SAME SHAPE as a real suffix (eight hex
// characters): the reader recognises trail files by their name, so a
// four-character fallback would produce a file the reader does not know —
// and that would make the whole process's trail invisible, silently.
const randomSuffixFallback = "00000000"
