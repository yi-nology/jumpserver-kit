package arch

// This file holds the guard against PLAINTEXT CREDENTIALS in the working
// tree.
//
// ⚠️ Why it exists: a credential written into a file in this repository is
// a credential that one `git push` publishes. That is not a theoretical
// risk — this repository's own history held a bastion administrator's
// token in clear text (in a publish script and in an end-to-end test) and
// it stayed there until somebody audited the history by hand. Nothing in
// the build caught it, because a credential in a script is a perfectly
// valid program: it compiles, it runs, it does its job.
//
// ⇒ The guard reads the working tree and looks for credential-SHAPED
// values sitting in credential CONTEXTS. Both halves matter:
//
//   - the SHAPE (a long hex string, a PEM private key block, an
//     Authorization header carrying a value) says "this could be a
//     secret";
//   - the CONTEXT (a key whose name says the value is a credential) says
//     "it was meant to be one".
//
// ⇒ Either half alone is wrong. Shape alone condemns every commit SHA in
// .github/workflows/ — they are forty hex characters, exactly the length
// of a bastion PrivateToken. Context alone condemns every long hash
// written under a key named "digest".
//
// ⚠️ The word list is NOT written here: it is redact.IsCredentialKey, the
// same list the audit trail and the answer path use. A second list would
// drift, and the drift would decide which credentials this guard is able
// to see at all.
//
// ⚠️ What it does NOT catch, on purpose: a credential assembled at run
// time ("tok" + "en") or pasted as an image. A static read of the tree
// cannot see those, and a guard that claimed it could would be lying
// about its own reach. What it does catch is the failure that actually
// happened here: a credential typed into a file and pushed.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/redact"
)

// CredentialHit is one place where a credential-shaped value sits in a
// credential context.
//
// ⚠️ It carries the file and the line on purpose: a guard that says
// "there is a credential somewhere" sends the reader hunting; a guard
// that says "here, on this line" is a thing that can be acted on.
type CredentialHit struct {
	// File is the path relative to the repository root.
	File string

	// Line is the 1-based line number inside File.
	Line int

	// Kind says which rule matched. It is a machine-readable name because
	// the report has to be able to group them.
	Kind string

	// Key is the credential key that was matched, when the rule had one.
	// It may be empty (a PEM block has no key).
	Key string
}

func (h CredentialHit) String() string {
	if h.Key == "" {
		return fmt.Sprintf("%s:%d: %s", h.File, h.Line, h.Kind)
	}
	return fmt.Sprintf("%s:%d: %s (%s)", h.File, h.Line, h.Kind, h.Key)
}

// CredentialReport is what one scan of a working tree found.
//
// ⚠️ It carries the EXEMPTIONS as well as the findings. A guard that can
// be switched off line by line without saying so is a guard with a hidden
// off switch ⇒ the exemptions travel with the report so that a reviewer
// sees them.
type CredentialReport struct {
	// Hits are the places where a credential is in the clear.
	Hits []CredentialHit

	// Allowances are the lines that were exempted, as "file:line".
	Allowances []string
}

// allowMarker is the text that exempts ONE LINE from the scan.
//
// ⚠️ It is line-scoped on purpose. A file-wide exemption is a place where
// a real credential can hide, and nobody would notice: the whole file
// stops being read. A line-scoped one says "this line is ABOUT
// credentials, not a credential" — and the next line is still read.
//
// ⚠️ It exempts the line it is ON and the line right after it (a marker
// on the line above a long literal is the usual way to write it).
//
// ⚠️ Every exemption is ACCOUNTED FOR: the guard logs the lines it
// exempted, so a reviewer sees them instead of having to go looking.
const allowMarker = "jms:allow-credential"

// The rules. Each one is a SHAPE; the context is applied afterwards.
//
// ⚠️ The PEM rule comes first because it is the one case where the shape
// is unambiguous on its own: a private key block is never a commit SHA
// and never a placeholder.
var (
	// privateKeyBlockRE matches the header of a PEM private key.
	privateKeyBlockRE = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)

	// authHeaderRE matches an Authorization header that carries a
	// credential value.
	//
	// ⚠️ The value shape is deliberately loose (any URL-safe/base64
	// alphabet run of sixteen characters or more) because the scheme
	// decides the encoding: "Token" carries hex, "Basic" and "Bearer"
	// carry base64. A hex-only rule would miss both of those.
	authHeaderRE = regexp.MustCompile(`(?i)authorization\s*[:=]\s*["']?(token|bearer|basic)\s+([A-Za-z0-9._~+/=-]{16,})`)

	// credentialKeyRE matches a key and the value that belongs to it.
	//
	// ⚠️ The key character class excludes the quote, so a JSON key
	// ("token") is captured without its quotes and without the quote of
	// the value.
	credentialKeyRE = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*["']?([0-9a-fA-F]{32,})["']?`)
)

// The minimum and maximum length of a hex value that counts as
// credential-shaped.
//
// ⚠️ Thirty-two is the floor: it is below every credential this
// repository has ever handled (a bastion PrivateToken is forty) and above
// the length at which a hash stops being plausible as a secret.
//
// ⚠️ Sixty-four is the ceiling: a sha256 digest is sixty-four hex
// characters, and a credential is not a digest. Without the ceiling a
// checksum table would be read as a credential.
const (
	minHexLength = 32
	maxHexLength = 64
)

// textExtensions are the file suffixes that are read as text.
//
// ⚠️ It is a WHITELIST, not a blacklist: a binary file (a built
// executable, an image, an archive) is not read at all, because a byte
// sequence that happens to look like a credential inside a binary is not
// a credential anybody wrote down.
var textExtensions = map[string]bool{
	".go": true, ".py": true, ".sh": true, ".bash": true, ".zsh": true,
	".md": true, ".yml": true, ".yaml": true, ".json": true, ".toml": true,
	".conf": true, ".cfg": true, ".ini": true, ".env": true, ".txt": true,
	".thrift": true, ".mod": true, ".sum": true, ".html": true, ".js": true,
	".ts": true, ".sql": true, ".example": true, ".template": true,
	".proto": true, ".xml": true, ".csv": true, ".properties": true,
	".service": true, ".bats": true, ".ps1": true, ".tf": true, ".hcl": true,
	// Key and certificate files: a PEM block is text, and the rule that
	// matches it says PRIVATE KEY — a public certificate is read and
	// found innocent.
	".pem": true, ".key": true, ".crt": true, ".cer": true, ".p12": true,
	".pfx": true,
}

// textNames are the file names that carry text but have no suffix (or a
// dot-only name).
var textNames = map[string]bool{
	"makefile": true, "dockerfile": true, "license": true, "notice": true,
	"readme": true, "codeowners": true, ".gitignore": true,
	".gitattributes": true, ".dockerignore": true, ".env": true,
	".npmrc": true, ".netrc": true,
}

// skippedDirs are the directories that are not part of the repository's
// own source.
//
// ⚠️ "bin" is here because the build writes binaries there, and a binary
// is not something anybody can fix by editing it.
var skippedDirs = map[string]bool{
	".git": true, "vendor": true, "node_modules": true, "__pycache__": true,
	"legacy": true, ".idea": true, "dist": true, "build": true, "bin": true,
	"coverage": true, ".next": true, ".venv": true, "venv": true, "target": true,
}

// ScanCredentials scans the working tree under root and reports every
// credential-shaped value that sits in a credential context, together
// with the lines that were exempted.
//
// ⚠️ It reads the working tree, not the git history: the history cannot
// be fixed by a commit, and a guard that only ever looks at the present
// is the one that can keep the present clean.
func ScanCredentials(root string) (CredentialReport, error) {
	var report CredentialReport
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if skippedDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if !isTextFile(path) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		rel = filepath.ToSlash(rel)

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		hits, allowances := scanText(rel, string(data))
		report.Hits = append(report.Hits, hits...)
		report.Allowances = append(report.Allowances, allowances...)
		return nil
	})
	if err != nil {
		return report, err
	}
	return report, nil
}

// isTextFile says whether a file is read as text.
func isTextFile(path string) bool {
	base := filepath.Base(path)
	lower := strings.ToLower(base)
	if textNames[lower] {
		return true
	}
	// ".env" and friends have no suffix but do have a dot.
	if strings.HasPrefix(lower, ".") && !strings.Contains(lower[1:], ".") {
		return true
	}
	return textExtensions[strings.ToLower(filepath.Ext(base))]
}

// scanText applies the rules to one file's text.
//
// ⚠️ It returns the exemptions too: a line that was let through is a fact
// about the scan, not a silence.
func scanText(rel, text string) ([]CredentialHit, []string) {
	var hits []CredentialHit
	var allowances []string
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		ln := i + 1

		// The marker on THIS line, or on the line right above it.
		marked := strings.Contains(line, allowMarker)
		if !marked && i > 0 {
			marked = strings.Contains(lines[i-1], allowMarker)
		}
		if marked {
			allowances = append(allowances, fmt.Sprintf("%s:%d", rel, ln))
			continue
		}

		if privateKeyBlockRE.MatchString(line) {
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "a PEM private key block",
			})
		}

		if m := authHeaderRE.FindStringSubmatch(line); m != nil {
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "an Authorization header carrying a value",
				Key: m[1],
			})
		}

		for _, m := range credentialKeyRE.FindAllStringSubmatch(line, -1) {
			key, value := m[1], m[2]
			if !redact.IsCredentialKey(key) {
				continue
			}
			if len(value) < minHexLength || len(value) > maxHexLength {
				continue
			}
			if isPlaceholderValue(value) {
				continue
			}
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "a credential-shaped value under a credential key",
				Key: key,
			})
		}
	}
	return hits, allowances
}

// isPlaceholderValue says whether a hex value is obviously a filler
// rather than a secret.
//
// ⚠️ It is a short list, on purpose: a long list of "these are fine"
// exceptions is a list that grows until it covers the real thing.
func isPlaceholderValue(v string) bool {
	lower := strings.ToLower(v)
	if strings.Count(lower, string(lower[0])) == len(lower) {
		// All one character ("0000…", "ffff…").
		return true
	}
	for _, p := range []string{
		"0123456789abcdef", "deadbeef", "cafebabe", "example",
		"placeholder", "changeme", "xxxxxxxx", "yourtoken", "redacted",
	} {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// CheckNoPlaintextCredentials is the guard: it fails the test when the
// working tree holds a credential in the clear.
//
// ⚠️ The message says WHERE and WHAT, because a guard that only says
// "no" leaves the reader with nothing to do.
func CheckNoPlaintextCredentials(t *testing.T, root string) {
	t.Helper()
	report, err := ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan %s for plaintext credentials: %v", root, err)
	}
	// ⚠️ The exemptions go to STDERR, not to t.Logf: "go test" prints the
	// log of a PASSING test only under -v ⇒ an exemption recorded in a log
	// line would be invisible in a CI run without -v ⇒ the accounting would
	// be bookkeeping that nobody ever sees, and a marker nobody sees is a
	// marker that grows.
	if len(report.Allowances) > 0 {
		fmt.Fprintf(os.Stderr, "credential scan: %d exempted line(s) under %s:\n",
			len(report.Allowances), root)
		for _, a := range report.Allowances {
			fmt.Fprintf(os.Stderr, "  %s (about credentials, not one)\n", a)
		}
	}
	for _, h := range report.Hits {
		t.Errorf("%s: a credential is in the clear — %s. "+
			"Credentials do not belong in this repository: a commit publishes them, "+
			"and a published credential has to be rotated, not just deleted. "+
			"Read it from the environment (the scripts already do that) and rotate "+
			"the credential that was exposed. If this line is about credentials "+
			"rather than one, mark it with %s — the exemption is reported above.",
			h.String(), h.Kind, allowMarker)
	}
}
