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
//   - the SHAPE (a long hex string, an opaque base64 blob, a PEM private
//     key block, an Authorization header carrying a value) says "this
//     could be a secret";
//   - the CONTEXT (a key whose name says the value is a credential) says
//     "it was meant to be one".
//
// ⇒ Either half alone is wrong. Shape alone condemns every commit SHA in
// .github/workflows/ — they are forty hex characters, exactly the length
// of a bastion PrivateToken. Context alone condemns every long hash
// written under a key named "digest".
//
// ⚠️ The word list is mostly NOT written here: it is
// redact.IsCredentialKey, the same list the audit trail and the answer
// path use. A second list would drift, and the drift would decide which
// credentials this guard is able to see at all.
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
// ⚠️ Every exemption is ACCOUNTED FOR: the guard prints the lines it
// exempted, so a reviewer sees them instead of having to go looking.
const allowMarker = "jms:allow-credential"

// incidentKeys are key names that the shared word list does not know but
// that this repository's own history leaked under.
//
// ⚠️ They are NOT added to pkg/redact's list, on purpose: that list
// decides what the audit trail stops recording and what the answer path
// masks ⇒ adding a word there changes the behaviour of two other paths,
// and that is a different decision than this guard.
//
// ⚠️ "tok" is here because the leak that motivated this guard was written
// as TOK = "…" ⇒ a word list that does not know the abbreviation does not
// see the accident. "auth" and "credentials" are here because they are
// ordinary names for a credential that the suffix rule misses (the shared
// list knows "credential", not "credentials").
//
// ⚠️ They are matched EXACTLY, not as a suffix: as a suffix, "auth"
// would also claim "oauth", and a false claim is a false alarm.
var incidentKeys = map[string]bool{
	"tok":         true,
	"auth":        true,
	"credentials": true,
}

// The rules.
//
// ⚠️ The PEM rule comes first because it is the one case where the shape
// is unambiguous on its own: a private key block is never a commit SHA
// and never a placeholder.
//
// ⚠️ The three key/value rules cover the THREE ways a credential turns up
// in a script or a config — and they are three because the leak this
// guard answers to lived in all three:
//
//	TOK = "…"                                  (assignment)
//	env.setdefault("JUMPSERVER_TOKEN", "…")    (positional argument)
//	JUMPSERVER_TOKEN="$JUMPSERVER_TOKEN:-…}" (shell default value)
//
// A rule that only knew the first one would have missed the accident.
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
	authHeaderRE = regexp.MustCompile(`(?i)authorization"?\s*[:=]\s*["']?(token|bearer|basic)\s+([A-Za-z0-9._~+/=-]{16,})`)

	// keyValueRE matches a key and the value that belongs to it.
	//
	// ⚠️ The closing quote of the key is OPTIONAL and sits AFTER the key:
	// a JSON member is "token": "…" ⇒ the quote is between the key and
	// the colon ⇒ without the optional quote the whole JSON shape is
	// invisible.
	//
	// ⚠️ The value shape here is deliberately WIDE (any token-ish run of
	// sixteen characters or more): the real question — "is this value
	// credential-shaped?" — is asked afterwards by
	// isCredentialShapedValue, which knows the difference between a
	// secret and a sentence.
	keyValueRE = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.-]*)"?\s*[:=]\s*["']?([A-Za-z0-9+/=_-]{16,})["']?`)

	// positionalRE matches a credential passed as a POSITIONAL argument:
	// env.setdefault("JUMPSERVER_TOKEN", "…").
	//
	// ⚠️ This shape has no colon and no equals sign between the key and
	// the value ⇒ the key/value rule cannot see it.
	positionalRE = regexp.MustCompile(`(?i)["']([A-Za-z_][A-Za-z0-9_.-]*)["']\s*,\s*["']([A-Za-z0-9+/=_-]{16,})["']`)

	// defaultValueRE matches a shell default value:
	// JUMPSERVER_TOKEN="$JUMPSERVER_TOKEN:-…}".
	//
	// ⚠️ The value sits behind a ":-" (or "-", ":=", "=") inside the
	// braces ⇒ neither the key/value rule nor the positional rule can
	// reach it.
	defaultValueRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_.-]*)(?::-|-|:=|=)([A-Za-z0-9+/=_-]{16,})\}`)
)

// The lengths that decide whether a value is credential-shaped.
//
// ⚠️ Thirty-two is the floor for hex: it is below every credential this
// repository has ever handled (a bastion PrivateToken is forty) and above
// the length at which a hash stops being plausible as a secret.
//
// ⚠️ Sixty-four is the ceiling for hex: a sha256 digest is sixty-four hex
// characters, and a credential is not a digest. Without the ceiling a
// checksum table would be read as a credential.
//
// ⚠️ Twenty-four is the floor for the base64 shape: below it, a blob is
// more likely to be a word or a short identifier than a key.
const (
	minHexLength    = 32
	maxHexLength    = 64
	minBase64Length = 24
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
	// The environment files that live behind a dot and a second word
	// (".env.local", ".env.production") are the MOST common place for a
	// credential to sit in a tree ⇒ they are read too.
	".local": true, ".production": true, ".development": true, ".staging": true,
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
	// A DOTFILE is read whatever comes after the dot: ".env", ".env.local",
	// ".npmrc.local" ⇒ they are all configuration, and configuration is
	// where a credential sits.
	if strings.HasPrefix(lower, ".") {
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

		for _, rule := range []struct {
			rx   *regexp.Regexp
			kind string
		}{
			{keyValueRE, "a credential-shaped value under a credential key"},
			{positionalRE, "a credential-shaped value passed under a credential key"},
			{defaultValueRE, "a credential-shaped value used as a default"},
		} {
			for _, m := range rule.rx.FindAllStringSubmatch(line, -1) {
				key, value := m[1], m[2]
				if !isCredentialKeyName(key) {
					continue
				}
				if !isCredentialShapedValue(value) {
					continue
				}
				hits = append(hits, CredentialHit{
					File: rel, Line: ln, Kind: rule.kind,
					Key: key,
				})
			}
		}
	}
	return hits, allowances
}

// isCredentialKeyName says whether a key names a credential.
//
// ⚠️ Two sources, and the difference matters: the shared word list (the
// one the audit trail and the answer path use) knows the ordinary names;
// the incident list knows the abbreviation this repository's own history
// leaked under. ⚠️ The incident list is matched EXACTLY — as a suffix it
// would claim innocent names.
func isCredentialKeyName(key string) bool {
	if redact.IsCredentialKey(key) {
		return true
	}
	return incidentKeys[strings.ToLower(key)]
}

// isCredentialShapedValue says whether a value looks like a secret.
//
// ⚠️ Two shapes, because credentials come in two shapes:
//
//   - HEX: a bastion PrivateToken, a GitHub token, an AWS key id —
//     thirty-two to sixty-four hex characters;
//   - BASE64: a base64 secret, a GitHub PAT with a prefix, a JWT —
//     twenty-four characters or more, and OPAQUE.
//
// ⚠️ "Opaque" is what keeps prose out: "my-very-long-service-name" is
// twenty-seven base64-shaped characters, but it is all lowercase letters
// and a dash ⇒ it is a name, not a secret. A secret has digits, or a mix
// of cases, in it.
func isCredentialShapedValue(v string) bool {
	if v == "" {
		return false
	}
	if len(v) >= minHexLength && len(v) <= maxHexLength && isHexString(v) {
		return !isPlaceholderValue(v)
	}
	if len(v) >= minBase64Length && isBase64ish(v) && looksOpaque(v) {
		return true
	}
	return false
}

// isHexString says whether every character is a hex digit.
func isHexString(v string) bool {
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// isBase64ish says whether every character belongs to the base64 /
// base64url alphabets.
func isBase64ish(v string) bool {
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '+' || r == '/' || r == '=' || r == '_' || r == '-':
		default:
			return false
		}
	}
	return true
}

// looksOpaque says whether a base64-shaped string looks random rather
// than like a name or a sentence.
//
// ⚠️ A name is letters and separators; a secret has entropy in it ⇒ the
// test is "does it carry a digit, or a mix of cases?".
func looksOpaque(v string) bool {
	var digit, upper, lower bool
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
			digit = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= 'a' && r <= 'z':
			lower = true
		}
	}
	if digit {
		return true
	}
	return upper && lower
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
	for _, h := range report.Hits {
		t.Errorf("%s: a credential is in the clear — %s. "+
			"Credentials do not belong in this repository: a commit publishes them, "+
			"and a published credential has to be rotated, not just deleted. "+
			"Read it from the environment (the scripts already do that) and rotate "+
			"the credential that was exposed. If this line is about credentials "+
			"rather than one, mark it with %s — the exemption is printed below.",
			h.String(), h.Kind, allowMarker)
	}
	// ⚠️ The exemptions are PRINTED, not logged: "go test" drops the log of
	// a PASSING test unless it runs with -v ⇒ an exemption recorded only
	// in a log line is bookkeeping nobody ever sees. ⚠️ They are still
	// dropped without -v (the stdout of a passing package is buffered and
	// discarded) ⇒ **the three repositories' CI runs "go test -v"** ⇒ there
	// the list is visible; locally, add -v to see it.
	for _, a := range report.Allowances {
		fmt.Printf("credential scan: %s was exempted (it is about credentials, not one)\n", a)
	}
}
