package risk

import (
	_ "embed"
	"github.com/oekit/pkg/slicex"
	"strings"
	"sync"

	"github.com/oagentkit/tools/bashguard"
	"gopkg.in/yaml.v3"

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
	if strings.TrimSpace(cmd) == "" {
		return jms.CommandClass_UNKNOWN
	}
	d := bashguard.Analyze(cmd, table())
	if d.ReadOnly {
		// The parser says this cannot write. That is the strongest
		// statement we can make without running it.
		return jms.CommandClass_READ
	}
	if len(d.Invocations) == 0 {
		// Nothing was parsed: the command is too long, uses a construct the
		// parser refuses, or is empty. It is not proven safe.
		return jms.CommandClass_UNKNOWN
	}
	for _, inv := range d.Invocations {
		if destructive(inv) {
			return jms.CommandClass_DANGEROUS
		}
	}
	// It writes something, but nothing we know how to call irreversible.
	return jms.CommandClass_MODIFY
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
			// git push --force
			return hasFlag(args, "-f", "--force")
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
