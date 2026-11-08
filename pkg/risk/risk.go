package risk

import (
	_ "embed"
	"github.com/oekit/pkg/slicex"
	"strings"
	"sync"

	"github.com/oagentkit/tools/bashguard"
	"gopkg.in/yaml.v3"
	"mvdan.cc/sh/v3/syntax"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// readonlyTable is the fleet's read-only vocabulary.
//
//go:embed readonly.yaml
var readonlyTable []byte

// table is the read-only policy table: the analyzer's base table plus the
// commands this fleet's daily sweeps actually run.
//
// It is built once. DefaultTable() hands out a copy, and a classification
// happens on every command an agent runs.
var table = sync.OnceValue(buildTable)

// tableFile is the shape of readonly.yaml.
type tableFile struct {
	Version  int                    `yaml:"version"`
	Commands map[string]commandSpec `yaml:"commands"`
}

// commandSpec is one command's entry.
//
// A subcommand list is deliberately a list of what is SAFE: the writing
// verbs are not mentioned, so they cannot be reached by a typo in a deny
// list.
type commandSpec struct {
	SafeFlags   map[string]string      `yaml:"safe_flags"`
	UnsafeFlags []string               `yaml:"unsafe_flags"`
	Subcommands map[string]commandSpec `yaml:"subcommands"`
}

// buildTable merges the analyzer's base table with the file's additions.
func buildTable() *bashguard.Table {
	t := bashguard.DefaultTable()

	var f tableFile
	if err := yaml.Unmarshal(readonlyTable, &f); err != nil {
		// The table is embedded, so a parse failure is a build-time
		// mistake, not a runtime condition. Refusing to classify anything
		// as read-only is the safe answer: the confirmation gate then
		// applies to every command.
		return t
	}
	for name, spec := range f.Commands {
		t.Commands[name] = spec.policy()
	}
	return t
}

// policy turns one entry into the analyzer's policy shape.
func (s commandSpec) policy() bashguard.Policy {
	p := bashguard.Policy{
		ReadOnly:    true,
		SafeFlags:   map[string]bashguard.FlagKind{},
		UnsafeFlags: s.UnsafeFlags,
	}
	for flag, kind := range s.SafeFlags {
		k, ok := flagKind(kind)
		if !ok {
			continue
		}
		p.SafeFlags[flag] = k
	}
	if len(s.Subcommands) > 0 {
		p.Subcommands = map[string]bashguard.Policy{}
		for name, sub := range s.Subcommands {
			p.Subcommands[name] = sub.policy()
		}
	}
	return p
}

// flagKind maps the file's spelling onto the analyzer's kinds.
func flagKind(s string) (bashguard.FlagKind, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bool":
		return bashguard.FlagBool, true
	case "string":
		return bashguard.FlagString, true
	case "number":
		return bashguard.FlagNumber, true
	case "optional":
		return bashguard.FlagOptional, true
	}
	return "", false
}

// Classify buckets a shell command so the caller (and the agent) can decide
// whether to run it, run it dry, or stop and ask.
func Classify(cmd string) jms.CommandClass {
	return classify(cmd, 0)
}

// classify is Classify with a recursion budget: shell -c strings and eval
// arguments are classified again, and peel chains (sudo nohup timeout …) walk
// inward, so the budget stops a pathological nest from looping forever.
func classify(cmd string, depth int) jms.CommandClass {
	if strings.TrimSpace(cmd) == "" {
		return jms.CommandClass_UNKNOWN
	}
	if depth > 6 {
		return jms.CommandClass_UNKNOWN
	}
	// ⚠️ 超长 ⇒ DANGEROUS（2026-11-09 实测的填充绕过，dry_run 验证）：
	// bashguard 对 >MaxCommandLen 的命令拒绝判定（AllCalls/Invocations 全空）
	// ⇒ 归 UNKNOWN ⇒ 不要求确认——而 `<10KB 注释填充>\n rm -rf /x` 恰好
	// 撑过长度闸，确认门被无声绕过。一个 >10KB 的 agent 脚本正是「该让人
	// 看一眼的东西」：拒绝判定的命令按 DANGEROUS 走（比例恰当，且判定
	// 缺席本身就是风险信号）。上游 tools#80 会给 Decision 加 OverLength
	// 标记，届时改为按标记判定。
	if len(cmd) > bashguard.MaxCommandLen {
		return jms.CommandClass_DANGEROUS
	}
	d := bashguard.Analyze(cmd, table())
	if d.ReadOnly {
		// The parser says this cannot write. That is the strongest
		// statement we can make without running it.
		return jms.CommandClass_READ
	}
	// The destructive judgement walks the WHOLE shell AST via upstream's
	// AllCalls (bashguard v0.12.0+, oagentkit/tools#35 — the field exists
	// precisely because this fleet used to hand-roll the same syntax.Walk):
	// Invocations only carries the outermost call, so a destructive command
	// wrapped in sudo/nohup/timeout/env/xargs, hidden in $(...) or a
	// backtick, or sitting in the second half of a pipeline used to sail
	// past the gate (measured: `sudo -n rm -rf /x` classified MODIFY — no
	// confirmation asked). Measured 2026-11-05.
	judged := false
	for _, c := range d.AllCalls {
		if c.Name == "" {
			// A dynamic command name ($VAR) says nothing about what runs.
			continue
		}
		judged = true
		if judgeInvocation(c.Name, c.Args, depth) {
			return jms.CommandClass_DANGEROUS
		}
	}
	if !judged && len(d.Invocations) == 0 {
		// Nothing was parsed: the command is too long, uses a construct the
		// parser refuses, or is empty. It is not proven safe.
		return jms.CommandClass_UNKNOWN
	}
	for _, inv := range d.Invocations {
		if destructive(inv) {
			return jms.CommandClass_DANGEROUS
		}
	}
	// A redirect into a device file is the same write as `dd of=/dev/sda`,
	// which the table catches — `cat img > /dev/sda` sailed past it until
	// the walk looked at Stmt.Redirects (measured 2026-11-06).
	if dangerousRedirect(parsed(cmd)) {
		return jms.CommandClass_DANGEROUS
	}
	// It writes something, but nothing we know how to call irreversible.
	return jms.CommandClass_MODIFY
}

// parsed is the command's AST, or nil when it does not parse. classify's
// two consumers (dangerousRedirect here, upstream's Analyze inside
// bashguard) used to parse the same text twice — one parse, two readers.
func parsed(cmd string) *syntax.File {
	f, err := syntax.NewParser().Parse(strings.NewReader(cmd), "")
	if err != nil {
		return nil
	}
	return f
}

// dangerousRedirect reports whether the command aims an output redirect at
// a device file.
//
// `cat disk.img > /dev/sda` writes the boot disk exactly like `dd
// of=/dev/sda` — the table catches the dd spelling; the redirect spelling
// only shows up on the statement's Redirects, which Invocations never
// carried. /dev/null is excluded: discarding output is the everyday case,
// and /dev/zero discards writes the same way.
func dangerousRedirect(f *syntax.File) bool {
	if f == nil {
		return false
	}
	found := false
	syntax.Walk(f, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		for _, r := range st.Redirs {
			if !strings.Contains(r.Op.String(), ">") {
				continue // an input redirect reads; only writes count
			}
			target, lit := wordLiteral(r.Word)
			if !lit {
				continue // a dynamic target ($DEV) says nothing about where
			}
			if strings.HasPrefix(target, "/dev/") &&
				target != "/dev/null" && target != "/dev/zero" {
				found = true
				return false
			}
		}
		return true
	})
	return found
}

// wordLiteral is a word's spelling when every part of it is literal text.
func wordLiteral(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, p := range w.Parts {
		if !writePart(&b, p) {
			// ParamExp, CmdSubst, ArithmExp, ExtGlob … — dynamic.
			return "", false
		}
	}
	return b.String(), true
}

// writePart appends one word part when it is literal text; double quotes
// recurse because their contents are literal unless a $ or ` appears.
func writePart(b *strings.Builder, p syntax.WordPart) bool {
	switch t := p.(type) {
	case *syntax.Lit:
		b.WriteString(t.Value)
		return true
	case *syntax.SglQuoted:
		b.WriteString(t.Value)
		return true
	case *syntax.DblQuoted:
		for _, q := range t.Parts {
			if !writePart(b, q) {
				return false
			}
		}
		return true
	}
	return false
}

// judgeInvocation judges the command that will actually run: known wrappers
// are peeled (sudo, nohup, timeout, env, xargs, nice, stdbuf, setsid, exec,
// command), shells recurse into their -c string, and eval/exec execute their
// arguments as shell, so those arguments are classified again.
func judgeInvocation(name string, args []string, depth int) bool {
	name = baseName(name)
	// Shells: classify the script, not the shell.
	if isShell(name) {
		for i, a := range args {
			if a == "-c" && i+1 < len(args) {
				return RequiresConfirmation(classify(args[i+1], depth+1))
			}
		}
		return false
	}
	if name == "eval" && len(args) > 0 {
		// eval executes its arguments as shell text.
		return RequiresConfirmation(classify(strings.Join(args, " "), depth+1))
	}
	if real, rest, wrapped := peelWrapper(name, args); wrapped {
		return judgeInvocation(real, rest, depth+1)
	}
	return destructive(bashguard.Invocation{Name: name, Args: args})
}

func isShell(name string) bool {
	switch name {
	case "sh", "bash", "dash", "zsh", "ksh", "ash":
		return true
	}
	return false
}

// peelValueFlags names the flags of each wrapper that consume the NEXT
// argument, so the peel lands on the command and not on a flag's value
// (`sudo -u root rm …` must not judge "root").
var peelValueFlags = map[string]map[string]bool{
	"sudo":    {"-u": true, "-g": true, "-h": true, "-p": true, "-C": true, "-D": true, "-T": true, "-r": true, "-t": true, "-U": true},
	"timeout": {"-k": true, "-s": true, "--kill-after": true, "--signal": true},
	"env":     {"-u": true, "-C": true, "-S": true},
	"xargs":   {"-I": true, "-L": true, "-n": true, "-P": true, "-s": true, "-d": true, "-E": true, "-e": true, "-i": true, "-l": true, "--replace": true, "--max-lines": true, "--max-args": true, "--max-procs": true, "--max-chars": true, "--delimiter": true, "--eof": true, "--arg-file": true},
	"nice":    {"-n": true, "--adjustment": true},
	"stdbuf":  {"-i": true, "-o": true, "-e": true},
	"ionice":  {"-c": true, "-n": true, "-p": true, "-u": true},
}

// peelBare names the wrappers whose arguments start at the first word that
// is not a flag.
var peelBare = map[string]bool{
	"nohup": true, "setsid": true, "exec": true, "command": true, "builtin": true,
}

// peelWrapper strips one wrapper layer. ok is false when name is not a
// wrapper (or carries no inner command), and the caller judges it as-is.
func peelWrapper(name string, args []string) (inner string, rest []string, ok bool) {
	vf, isWrapper := peelValueFlags[name]
	if !isWrapper && !peelBare[name] {
		return "", nil, false
	}
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			break
		}
		if vf[a] {
			i += 2 // the flag's value is not the command
			continue
		}
		i++
	}
	if name == "env" {
		// env VAR=val … cmd: the assignments are not the command either.
		for i < len(args) && isAssignment(args[i]) {
			i++
		}
	}
	if name == "timeout" && i < len(args) && isDuration(args[i]) {
		i++ // the duration is not the command
	}
	if i >= len(args) {
		return "", nil, false
	}
	return args[i], args[i+1:], true
}

func isAssignment(s string) bool {
	eq := strings.IndexByte(s, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := s[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func isDuration(s string) bool {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == 0 {
		return false
	}
	if i < len(s) {
		switch s[i] {
		case 's', 'm', 'h', 'd':
			i++
		}
	}
	return i == len(s)
}

// RequiresConfirmation reports whether a command of this class has to be
// confirmed before it runs.
//
// Only DANGEROUS does. UNKNOWN is not escalated, and that is a deliberate
// trade-off: the classifier cannot place every command, so asking for a
// confirmation on everything it does not recognise would make the flag
// meaningless (the agent would set it without reading it).
//
// The flag is a speed bump, not a security boundary — the agent can always
// confirm. What it buys is that the destructive commands are the ones the
// agent has to think about.
func RequiresConfirmation(c jms.CommandClass) bool {
	return c == jms.CommandClass_DANGEROUS
}

// Rehearsal answers the question every dry run and every refusal answers
// the same way: would this command run, and if not, what is missing?
//
// A command runs when it needs no confirmation, or when the confirmation
// is already there. When it would not run, the answer carries the one
// sentence that tells the caller what to do about it.
//
// ⚠️ The WORDING is a cross-server contract: the management plane and the
// execution plane answer the same question ("would this run?"), and an
// agent that reads one of them has to read the other the same way. The
// sentence is built HERE, once — the planes each used to spell it for
// themselves, and one of them hard-coded "DANGEROUS" into a sentence that
// was supposed to name the class it actually found.
func Rehearsal(c jms.CommandClass, confirmed bool) (would bool, blocked string) {
	would = !RequiresConfirmation(c) || confirmed
	if !would {
		blocked = "classified " + c.String() + "; re-call with confirm=true to execute"
	}
	return would, blocked
}

// destructive reports whether one invocation is irreversible.
//
// The rules are on the command NAME and its arguments, because that is what
// the parser gives: the name of the program and its arguments. A dangerous
// word inside a string is not a command, and a dangerous command behind a
// wrapper (sudo, nohup, timeout) is still the same command.
func destructive(inv bashguard.Invocation) bool {
	name := baseName(inv.Name)
	args := inv.Args
	switch {
	case name == "rm":
		// A recursive delete is the classic one. `rm -f file` is not.
		return hasFlag(args, "-r", "-R", "--recursive") || hasShortFlag(args, 'r')
	case strings.HasPrefix(name, "mkfs"):
		return true
	case name == "wipefs", name == "shred":
		return true
	case name == "dd":
		// Writing to a device: dd if=... of=/dev/sda
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				return true
			}
		}
		return false
	case name == "reboot", name == "shutdown", name == "poweroff", name == "halt", name == "kexec":
		return true
	case name == "init":
		// init 0 / init 6
		return slicex.Contains(args, "0") || slicex.Contains(args, "6")
	case name == "userdel", name == "useradd", name == "usermod",
		name == "groupdel", name == "groupadd", name == "passwd", name == "chpasswd",
		name == "gpasswd", name == "visudo":
		// Account and privilege changes: they are how someone gets in, and
		// undoing one is not in the tool's hands.
		return true
	case name == "systemctl":
		for _, a := range args {
			switch a {
			case "disable", "mask", "poweroff", "reboot", "halt", "kexec":
				return true
			}
		}
		return false
	case name == "iptables", name == "nft", name == "ip6tables":
		return slicex.Contains(args, "-F") ||
			slicex.Contains(args, "--flush") ||
			slicex.Contains(args, "flush")
	case name == "chmod", name == "chown":
		// `chmod -R 777 /` reaches everything; `chmod 644 file` does not.
		return hasFlag(args, "-R", "--recursive")
	case name == "kill", name == "killall", name == "pkill":
		return hasFlag(args, "-9", "-KILL", "--signal", "-SIGKILL")
	case name == "journalctl":
		// Vacuuming the journal deletes the audit trail.
		return hasFlag(args, "--vacuum-size", "--vacuum-time", "--vacuum-files", "--rotate", "--flush")
	case name == "kubectl":
		// A dry run deletes nothing — asking for a confirmation on it
		// teaches the agent that the flag is meaningless (measured
		// 2026-11-06: `--dry-run=client` classified DANGEROUS).
		for _, a := range args {
			if a == "--dry-run" || strings.HasPrefix(a, "--dry-run=") {
				return false
			}
		}
		return slicex.Contains(args, "delete")
	case name == "docker", name == "podman":
		for i, a := range args {
			if a == "system" && i+1 < len(args) && args[i+1] == "prune" {
				return true
			}
		}
		return false
	case name == "git":
		return destructiveGit(args)
	}
	// The uninstall scripts are destructive by name.
	return strings.HasSuffix(name, "-uninstall.sh")
}

// destructiveGit is the git subset that throws work away.
func destructiveGit(args []string) bool {
	for _, a := range args {
		switch a {
		case "clean":
			// git clean -fd
			return hasFlag(args, "-f", "--force")
		case "reset":
			// git reset --hard
			return hasFlag(args, "--hard")
		case "push":
			// git push --force — and --force-with-lease, which overwrites
			// the remote the same way when the lease passes (it exists to
			// be run where --force would be; measured 2026-11-06:
			// --force-with-lease classified MODIFY, a silent bypass).
			return hasFlag(args, "-f", "--force", "--force-with-lease", "--force-if-includes")
		case "filter-branch":
			return true
		}
	}
	return false
}

// baseName is the program's name without its directory.
//
// A path is still a program: /usr/bin/rm is rm.
func baseName(name string) string {
	name = strings.TrimSpace(name)
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// hasFlag reports whether one of the flags is present.
func hasFlag(args []string, flags ...string) bool {
	for _, f := range flags {
		if slicex.Contains(args, f) {
			return true
		}
	}
	return false
}

// hasShortFlag reports whether a short flag bundle carries the letter.
//
// `rm -rf` carries the recursive flag in a bundle, and looking for the exact
// string "-r" would miss it.
func hasShortFlag(args []string, letter byte) bool {
	for _, a := range args {
		if len(a) < 2 || a[0] != '-' || a[1] == '-' {
			continue
		}
		if strings.ContainsRune(a[1:], rune(letter)) {
			return true
		}
	}
	return false
}
