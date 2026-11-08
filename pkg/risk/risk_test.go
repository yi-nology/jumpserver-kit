package risk

import (
	"testing"

	"github.com/yi-nology/jumpserver-kit/model/jms"
)

// The classification decides whether a command has to be confirmed, so the
// cases that matter are pinned here:
//
//   - a destructive command must never fall through;
//   - a harmless one must not need a confirmation;
//   - a dangerous WORD inside a string is not a dangerous command.
func TestClassify(t *testing.T) {
	cases := []struct {
		cmd  string
		want jms.CommandClass
	}{
		// Destructive.
		{"rm -rf /var/lib/thing", jms.CommandClass_DANGEROUS},
		{"rm -r /var/lib/thing", jms.CommandClass_DANGEROUS},
		{"rm --recursive /var/lib/thing", jms.CommandClass_DANGEROUS},
		{"reboot", jms.CommandClass_DANGEROUS},
		{"mkfs.ext4 /dev/sdb1", jms.CommandClass_DANGEROUS},
		{"dd if=/dev/zero of=/dev/sda", jms.CommandClass_DANGEROUS},
		{"userdel bob", jms.CommandClass_DANGEROUS},
		{"passwd bob", jms.CommandClass_DANGEROUS},
		{"systemctl disable nginx", jms.CommandClass_DANGEROUS},
		{"systemctl mask nginx", jms.CommandClass_DANGEROUS},
		{"iptables -F", jms.CommandClass_DANGEROUS},
		{"chmod -R 777 /", jms.CommandClass_DANGEROUS},
		{"kubectl delete pod web-1", jms.CommandClass_DANGEROUS},
		{"docker system prune -af", jms.CommandClass_DANGEROUS},
		{"git push --force origin main", jms.CommandClass_DANGEROUS},
		{"git reset --hard HEAD~1", jms.CommandClass_DANGEROUS},

		// Writes, but not the irreversible kind.
		{"rm -f /tmp/x", jms.CommandClass_MODIFY},
		{"chmod 644 /etc/app.conf", jms.CommandClass_MODIFY},
		{"systemctl restart nginx", jms.CommandClass_MODIFY},
		{"docker rm -f web", jms.CommandClass_MODIFY},
		{"apt-get install nginx", jms.CommandClass_MODIFY},
		{"sed -i 's/a/b/' /etc/app.conf", jms.CommandClass_MODIFY},
		{"./deploy.sh --force", jms.CommandClass_MODIFY},
		{"kubectl apply -f deploy.yaml", jms.CommandClass_MODIFY},

		// Inspection.
		{"df -h /", jms.CommandClass_READ},
		{"uptime", jms.CommandClass_READ},
		{"ps aux", jms.CommandClass_READ},
		{"free -m", jms.CommandClass_READ},
		{"systemctl status nginx", jms.CommandClass_READ},
		{"docker ps", jms.CommandClass_READ},
		{"kubectl get pods", jms.CommandClass_READ},
		{"journalctl -u nginx --since '1 hour ago'", jms.CommandClass_READ},
		{"cat /etc/os-release", jms.CommandClass_READ},
		{"grep foo /etc/hosts", jms.CommandClass_READ},
		{"id -un; hostname", jms.CommandClass_READ},

		// The dangerous word is an ARGUMENT, not a command. This is the case
		// a keyword matcher cannot get right: `echo "rm -rf /"` destroys
		// nothing.
		{`echo "rm -rf /"`, jms.CommandClass_READ},
		{`echo "systemctl disable nginx"`, jms.CommandClass_READ},
	}
	for _, c := range cases {
		if got := Classify(c.cmd); got != c.want {
			t.Errorf("Classify(%q) = %s, want %s", c.cmd, got, c.want)
		}
	}
}

// The rule the two planes share: only the destructive class asks for a
// confirmation.
func TestRequiresConfirmation(t *testing.T) {
	if !RequiresConfirmation(jms.CommandClass_DANGEROUS) {
		t.Error("DANGEROUS must require a confirmation")
	}
	for _, c := range []jms.CommandClass{
		jms.CommandClass_READ, jms.CommandClass_MODIFY, jms.CommandClass_UNKNOWN,
	} {
		if RequiresConfirmation(c) {
			t.Errorf("%s must not require a confirmation", c)
		}
	}
}

// The class is what the caller is told, so its spelling is part of the
// contract (the plan of jms_job_run carries it).
func TestClassSpelling(t *testing.T) {
	for _, c := range []jms.CommandClass{
		jms.CommandClass_READ, jms.CommandClass_MODIFY,
		jms.CommandClass_DANGEROUS, jms.CommandClass_UNKNOWN,
	} {
		if c.String() == "" {
			t.Errorf("class %d has no name", c)
		}
	}
	if jms.CommandClass_DANGEROUS.String() != "DANGEROUS" {
		t.Errorf("DANGEROUS spells as %q", jms.CommandClass_DANGEROUS.String())
	}
}

// A command the parser cannot place is not proven safe.
func TestUnparsableCommandIsNotReadOnly(t *testing.T) {
	if got := Classify(""); got == jms.CommandClass_READ {
		t.Error("an empty command must not be READ")
	}
	if got := Classify("   "); got == jms.CommandClass_READ {
		t.Error("a blank command must not be READ")
	}
}

// The redirect check's cheap precondition must not change a single verdict
// (issue #17): every write redirect operator contains '>' and every input
// operator this check ignores does not, so a command with no '>' byte can
// never produce a counted redirect — skipping the parse is equivalence, not
// an approximation. These pins walk the boundary of that claim.
func TestDangerousRedirectFastPathChangesNoVerdict(t *testing.T) {
	// Writes at device files stay DANGEROUS through the redirect spelling —
	// the cases that would break if the precondition were wrong in the
	// "skips a redirect it should have seen" direction.
	for _, c := range []string{
		"cat disk.img > /dev/sda",
		"./write.sh > /dev/mmcblk0",
		"grep x log >> /dev/vdb",
		"make 2>/dev/null > /dev/sdf",
	} {
		if got := Classify(c); got != jms.CommandClass_DANGEROUS {
			t.Errorf("Classify(%q) = %s, want DANGEROUS (the redirect must still be seen)", c, got)
		}
	}
	// No '>' byte anywhere: the second parse is skipped, and the answer is
	// the same "no counted redirect" the full walk would give — including
	// the cases whose danger comes from the COMMAND, not a redirect.
	for _, c := range []string{
		"dd if=/dev/zero of=/dev/sda", // dangerous by name, not by redirect
		"mkfs.ext4 /dev/sdb1",
		"touch /tmp/notes",
		"mkdir -p /tmp/a/b",
	} {
		if dangerousRedirect(c) {
			t.Errorf("dangerousRedirect(%q) = true, want false", c)
		}
	}
	// A device PATH in the arguments is not a redirect target: even with a
	// '>' present, an ordinary write stays MODIFY.
	if got := Classify("cp /etc/hosts /dev/null-copy"); got != jms.CommandClass_MODIFY {
		t.Errorf("Classify(cp … /dev/null-copy) = %s, want MODIFY", got)
	}
}
