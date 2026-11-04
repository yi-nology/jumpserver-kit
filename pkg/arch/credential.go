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
//
// ⚠️ Two more shapes are OUT of reach of a line scanner, and are
// documented as boundaries instead of half-caught: a YAML block scalar
// ("token: |" and the value on the next line) and an AWS Access Key ID
// (AKIA…, twenty characters — an identifier, not the secret; the secret
// itself is caught like any other).

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
// ⚠️ The marker has to stand in a COMMENT and it has to be ANCHORED
// (markerWholeLineRE / markerTrailingRE below) — a bare "does the line
// contain the marker" test also fires on a documentation line that
// merely EXPLAINS the marker, and the line under that explanation
// silently stops being read. That is not hypothetical: the first
// version of this guard exempted exactly that way, and four prose lines
// in this repository's own AGENTS.md and CHANGELOG.md were accounted
// for as legitimate exemptions while exempting their neighbours.
//
// ⚠️ Two anchored shapes, two scopes (BOTH inside a comment):
//
//	# jms:allow-credential          (alone on its line) ⇒ the NEXT line
//	token = "…"  # jms:allow-credential              ⇒ ITS OWN line
//
// ⚠️ A bare marker line (no comment prefix) is NOT a marker: that
// shape is how a documentation list of markers is written.
//
// ⚠️ Every exemption is ACCOUNTED FOR: the guard prints the lines it
// exempted, so a reviewer sees them instead of having to go looking.
const allowMarker = "jms:allow-credential"

var (
	// markerWholeLineRE is the marker ALONE on its line INSIDE A COMMENT
	// (a trailing explanation is not a marker). ⚠️ The comment prefix is
	// REQUIRED, not optional: a bare marker line is how a documentation
	// LIST of markers is written ("可用标记：jms:allow-credential" alone
	// on a line), and that line would silently exempt whatever follows
	// it — the same prose-blindness the trailing anchor fixed, one shape
	// over. "The marker has to stand in a COMMENT" (above) is the
	// contract; the regex enforces it.
	markerWholeLineRE = regexp.MustCompile(
		`^\s*(?:#|//|--|;|/\*+|\*)\s*` + allowMarker + `\s*(?:\*/)?\s*$`)

	// markerTrailingRE is the marker at the END of a line, inside a
	// comment. ⚠️ The comment separator is part of the contract: prose
	// that ends with the marker ("the marker is called
	// jms:allow-credential") is NOT a marker.
	markerTrailingRE = regexp.MustCompile(
		`(?:#|//|--|;)\s*` + allowMarker + `\s*$`)
)

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
// ⚠️ They are matched EXACTLY, or with a SEPARATOR BOUNDARY ("my_tok",
// "api-tok", "my_tok2"), never as a bare suffix: as a bare suffix,
// "auth" would also claim "oauth", and a false claim is a false alarm.
// ⚠️ The boundary also keeps this list from silently becoming a second
// copy of the shared list's semantics: the shared list is an UNBOUNDED
// suffix match ("mytoken" counts) because the upstream rules it must
// cover are; this list is bounded because it would otherwise claim
// words, not names.
var incidentKeyRE = regexp.MustCompile(
	`(?i)^(?:.*[_\-.])?(?:tok|auth|credentials)(?:[_\-.]?\d+)?$`)

// The rules.
//
// ⚠️ The PEM rule comes first because it is the one case where the shape
// is unambiguous on its own: a private key block is never a commit SHA
// and never a placeholder.
//
// ⚠️ The key/value rules cover the ways a credential turns up in a
// script or a config — and there are several because the leak this
// guard answers to lived in three of them AT ONCE:
//
//	TOK = "…"                                  (assignment)
//	env.setdefault("JUMPSERVER_TOKEN", "…")    (positional argument)
//	JUMPSERVER_TOKEN="$JUMPSERVER_TOKEN:-…}" (shell default value)
//
// A rule that only knew the first one would have missed the accident.
//
// ⚠️ On top of that there are the shapes a plain "key = value" rule
// cannot see at all:
//
//	token := "…"               (Go/Python short declaration)
//	password <…>               (.netrc: whitespace is the separator)
//	url: db://user:pass@host    (credential inside a URL)
//	…?token=…&a=1              (credential inside a query string)
//
// ⚠️ The whitespace form is a SEPARATE rule on purpose: if the
// whitespace separator lived inside keyValueRE, a line like
// "export JUMPSERVER_TOKEN=<…>" would be swallowed as ONE match (key
// "export", value the whole assignment) and the real pair would never
// be looked at. Two regexes scan the line independently ⇒ neither can
// hide the other's pair.
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
	keyValueRE = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.-]*)["'\x60]?\s*(?:=|:=|:)\s*["'\x60]?([A-Za-z0-9+/=_-]{16,})["'\x60]?`)

	// whitespaceKVRE matches the shapes where WHITESPACE is the only
	// separator between the key and the value: ".netrc"
	// ("machine … password <…>") and its cousins.
	//
	// ⚠️ The value has to be the LAST thing on the line (an end-of-line
	// comment is allowed). That is what keeps this rule from claiming an
	// assignment under the wrong key: in "export JUMPSERVER_TOKEN=<…>"
	// the whitespace rule would otherwise read key "export" and value
	// "JUMPSERVER_TOKEN" — while the key/value rule, scanning the same
	// line independently, already has the real pair.
	whitespaceKVRE = regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_.-]*)[ \t]+["'\x60]?([A-Za-z0-9+/_-]{16,})["'\x60]?[ \t]*(?:[#;].*)?$`)

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
	// braces.
	//
	// ⚠️ The bare "-" shape is the one ONLY this rule sees: the ":-"
	// variant is ALSO matched by the key/value rule (as key "VAR" and
	// value "-…" — the dash is inside the value alphabet) and lands on
	// THAT rule's Kind ⇒ a test that pins THIS rule has to use the bare
	// "-" shape and assert the Kind. (This rule was once "pinned" by a
	// ":-" fixture that any rule would have caught — the test stayed
	// green with the rule deleted.)
	defaultValueRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_.-]*)(?::-|-|:=|=)([A-Za-z0-9+/=_-]{16,})\}`)

	// urlCredentialRE matches a credential EMBEDDED in a URL:
	// db://deploy:<…>@db.internal.
	//
	// ⚠️ There is no key name to check in this shape — a user name is a
	// user name ⇒ the password alone has to look like a credential
	// (isURLCredentialValue: shaped, or opaque and long enough not to be
	// a word). "https://user:password@host" is documentation, not a leak.
	//
	// ⚠️ The password runs to the LAST "@" on purpose: a password may
	// contain "@" itself, and stopping at the first one would leave the
	// tail of the password in the clear.
	urlCredentialRE = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://([^:/\s]+):([^/\s]*)@`)

	// urlQueryCredentialRE matches a credential in a QUERY STRING
	// parameter: …?token=<…>&a=1.
	//
	// ⚠️ What the key/value rule MISSES here: a plain "?token=<forty
	// hex>" it does catch (key "token", separator "="), but a URL whose
	// value carries dots or percent-encoding (a JWT, a percent-encoded
	// token) escapes its value alphabet ⇒ the query string needs its own
	// rule. The value runs to the next "&", "#" or space; the OTHER
	// parameters are not part of the match ⇒ the line still says what
	// was run.
	urlQueryCredentialRE = regexp.MustCompile(`(?i)[?&]([A-Za-z_][A-Za-z0-9_.-]*)=([^&#\s"']+)`)
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
	// A VARIANT of a known name is read too: "Dockerfile.prod",
	// "Makefile.local" — the suffix says which environment, not what
	// the file is. ⚠️ A name with a dot of its own (".gitignore") is
	// not a prefix host.
	for name := range textNames {
		if !strings.Contains(name, ".") && strings.HasPrefix(lower, name+".") {
			return true
		}
	}
	// A DOTFILE is read whatever comes after the dot: ".env", ".env.local",
	// ".npmrc.local" ⇒ they are all configuration, and configuration is
	// where a credential sits.
	if strings.HasPrefix(lower, ".") {
		return true
	}
	if ext := strings.ToLower(filepath.Ext(base)); ext != "" {
		return textExtensions[ext]
	}
	// NO SUFFIX AT ALL ("id_rsa", "id_ed25519"): the name says nothing
	// a whitelist could key on ⇒ read the head and look for a PEM
	// header. ⚠️ Only the head is read: a file is not slurped to decide
	// whether to read it.
	return looksLikePEMHead(path)
}

// looksLikePEMHead says whether a file starts with a PEM private key
// header.
func looksLikePEMHead(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := f.Read(head)
	return privateKeyBlockRE.Match(head[:n])
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

		// The marker, ANCHORED, on THIS line or on the line right above it:
		// a trailing marker (a comment at the END of the line) exempts its
		// OWN line; a marker alone on its line exempts the NEXT one.
		// The question "does the line contain the marker" is not enough —
		// see allowMarker above: a documentation line that merely EXPLAINS
		// the marker must not exempt anything.
		marked := markerTrailingRE.MatchString(line) || markerWholeLineRE.MatchString(line)
		if !marked && i > 0 {
			marked = markerWholeLineRE.MatchString(lines[i-1])
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

		// hitPairs: one line must not be reported twice for the same
		// secret. ⚠️ Deduped by VALUE, not by (key, value): the shapes
		// disagree about the key while carrying the same secret —
		// "Authorization: Bearer <…>" is also textually "Bearer <…>"
		// beside a whitespace (key "Bearer"), and "?token=<forty hex>"
		// is also "token:<forty hex>".
		hitPairs := map[string]bool{}

		if m := authHeaderRE.FindStringSubmatch(line); m != nil {
			hitPairs[m[2]] = true
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "an Authorization header carrying a value",
				Key: m[1],
			})
		}

		// A credential EMBEDDED in a URL. The shape has no key name —
		// a user name is a user name ⇒ Key stays empty (like the PEM
		// rule) and the file:line leads the reader.
		for _, m := range urlCredentialRE.FindAllStringSubmatch(line, -1) {
			if !isURLCredentialValue(m[2]) {
				continue
			}
			if hitPairs[m[2]] {
				continue
			}
			hitPairs[m[2]] = true
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "a credential embedded in a URL",
			})
		}

		for _, rule := range []struct {
			rx   *regexp.Regexp
			kind string
		}{
			{keyValueRE, "a credential-shaped value under a credential key"},
			{positionalRE, "a credential-shaped value passed under a credential key"},
			{defaultValueRE, "a credential-shaped value used as a default"},
			{whitespaceKVRE, "a credential-shaped value beside a credential key (whitespace-separated)"},
		} {
			for _, m := range rule.rx.FindAllStringSubmatch(line, -1) {
				key, value := m[1], m[2]
				if !isCredentialKeyName(key) {
					continue
				}
				if !isCredentialShapedValue(value) {
					continue
				}
				if hitPairs[value] {
					continue
				}
				hitPairs[value] = true
				hits = append(hits, CredentialHit{
					File: rel, Line: ln, Kind: rule.kind,
					Key: key,
				})
			}
		}

		// A credential in a QUERY STRING parameter. ⚠️ The key/value rule
		// sees the plain "?token=<forty hex>" shape but not values with
		// dots or percent-encoding (JWT-shaped tokens) ⇒ the parameter
		// needs its own rule. ⚠️ The value is checked against the rules
		// above so that a "?token=<forty hex>" line is reported once, not
		// twice.
		for _, m := range urlQueryCredentialRE.FindAllStringSubmatch(line, -1) {
			key, value := m[1], m[2]
			if hitPairs[value] {
				continue
			}
			if !isCredentialKeyName(key) {
				continue
			}
			if !isURLCredentialValue(value) {
				continue
			}
			hitPairs[value] = true
			hits = append(hits, CredentialHit{
				File: rel, Line: ln, Kind: "a credential in a URL query parameter",
				Key: key,
			})
		}
	}
	return hits, allowances
}

// isCredentialKeyName says whether a key names a credential.
//
// ⚠️ Two sources, and the difference matters: the shared word list (the
// one the audit trail and the answer path use) knows the ordinary names;
// the incident list (incidentKeyRE above) knows the abbreviations this
// repository's own history leaked under. ⚠️ The incident list matches
// EXACTLY or on a SEPARATOR BOUNDARY ("my_tok", "api-tok", "my_tok2"),
// never as a bare suffix: as a bare suffix "auth" would also claim
// "oauth", and a false claim is a false alarm.
func isCredentialKeyName(key string) bool {
	if redact.IsCredentialKey(key) {
		return true
	}
	return incidentKeyRE.MatchString(key)
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

// isURLCredentialValue says whether the credential part of a URL (the
// password, or a query parameter value) looks like a credential.
//
// ⚠️ It is LOOSER than isCredentialShapedValue on purpose: a URL
// password or a query token is often shorter than a body credential,
// and "opaque and at least eight characters" is what separates
// "MyP4ssw0rd@host" from "password@host" — a word, and documentation.
//
// ⚠️ OPAQUE ALONE IS NOT ENOUGH — it only asks for "a digit, or a mix
// of cases", and a run of CJK prose next to an uppercase acronym
// passes that ("abc）散文…URL"), as does a fragment of SOURCE CODE
// ("\\\"+aHexValue()+\"") and a redaction placeholder
// ("[REDACTED]@ss"). All three were false positives of this guard on
// its own repository. ⇒ the value must also live in the URL
// credential ALPHABET below: base64url plus the characters a
// percent-encoded or JWT-shaped credential really carries — "." (JWT
// segments), "%" (percent-encoding), "@" (a password may contain one;
// the match runs to the LAST "@"), "=" (base64 padding). Anything
// else — a quote, a bracket, a parenthesis, a CJK character — is not
// a credential standing in a URL, it is prose or code ABOUT one.
func isURLCredentialValue(v string) bool {
	if isCredentialShapedValue(v) {
		return true
	}
	return len(v) >= 8 && looksOpaque(v) && isURLCredentialAlphabet(v)
}

// isURLCredentialAlphabet says whether every character belongs to the
// alphabet a credential standing in a URL can be written in.
func isURLCredentialAlphabet(v string) bool {
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '+' || r == '/' || r == '=' || r == '_' || r == '-':
		case r == '.' || r == '%' || r == '@':
		default:
			return false
		}
	}
	return true
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
