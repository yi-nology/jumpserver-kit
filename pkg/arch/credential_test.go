package arch_test

// The self-test of the plaintext-credential guard.
//
// ⚠️ The fixtures live in t.TempDir(), NEVER in this repository: the guard
// reads the working tree, so a fixture that sat in the tree would be read
// by the guard as a real leak — and the guard would (correctly) fail on
// its own test data.
//
// ⚠️ The credential-shaped strings in this file are BUILT, not written
// out: a forty-hex literal in a source file is itself a credential-shaped
// value, and the guard would read this file too. Splitting the literal is
// not a trick to hide a secret here — there is no secret here — it is the
// same shape a careful author uses when writing about credentials.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yi-nology/jumpserver-kit/pkg/arch"
)

// aHexValue returns a credential-shaped hex value.
//
// ⚠️ It is assembled from two halves so that no source file in this
// repository contains the value itself.
func aHexValue() string {
	return strings.Repeat("a1b2c3d4", 5)
}

// writeFile writes a file under root and returns its path.
func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("create %s: %v", filepath.Dir(p), err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return p
}

// kindsOf reduces the hits to their kinds, for comparison.
func kindsOf(hits []arch.CredentialHit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.Kind)
	}
	return out
}

// aBase64Value returns a credential-shaped value that is NOT hex.
//
// ⚠️ It is assembled from two halves so that no source file in this
// repository contains the value itself.
func aBase64Value() string {
	return "EMrb0obFo0sJqh6KjNz9WThsO9gh4P1Lrk0" + "/1SgcXno="
}

func TestScanCredentialsReportsAValueUnderACredentialKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/publish.py",
		"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].File != "script/publish.py" {
		t.Errorf("the hit names %s, want script/publish.py", report.Hits[0].File)
	}
	if report.Hits[0].Key != "token" {
		t.Errorf("the hit names the key %q, want token", report.Hits[0].Key)
	}
}

func TestScanCredentialsReportsAnAuthorizationHeader(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "docs/example.md",
		"Authorization: Token "+aHexValue()+"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsReportsAPrivateKeyBlock(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "deploy/key.pem",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n") // jms:allow-credential

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsIgnoresACommitSHA(t *testing.T) {
	root := t.TempDir()
	// A GitHub Actions pin: forty hex characters, but the key says
	// nothing about credentials.
	writeFile(t, root, ".github/workflows/ci.yml",
		"        uses: actions/checkout@"+aHexValue()+" # v7\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("a commit SHA is not a credential, got %d hits: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsIgnoresANonCredentialKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "docs/notes.md",
		"digest: "+aHexValue()+"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("a key that does not name a credential is not a leak, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsIgnoresAPlaceholder(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "conf/example.env",
		"JUMPSERVER_TOKEN=0000000000000000000000000000000000000000\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("a filler value is not a leak, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsIgnoresAValueAssembledAtRunTime(t *testing.T) {
	root := t.TempDir()
	// The source holds the halves apart, so the file holds no credential:
	// what is assembled at run time is the author's decision, not
	// something a reader of the tree can see.
	writeFile(t, root, "script/make.py",
		"value = \""+aHexValue()[:20]+"\" + \""+aHexValue()[20:]+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("a value that is not in the file is not in the file, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsIgnoresBinariesAndGit(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "bin/tool",
		"token = \""+aHexValue()+"\"\n")
	writeFile(t, root, ".git/config",
		"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("neither a binary nor .git is part of the tree, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

func TestScanCredentialsExemptsTheMarkedLineAndSaysSo(t *testing.T) {
	root := t.TempDir()
	// The marker ALONE on its line (a comment prefix is allowed)
	// exempts its own line and the NEXT one.
	writeFile(t, root, "script/example.py",
		"# jms:allow-credential\n"+
			"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("the marked line is exempt, got %d hits: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
	if len(report.Allowances) == 0 {
		t.Fatalf("the exemption must be ACCOUNTED FOR, got none")
	}
	// ⚠️ The exemption is ACCOUNTED FOR: both the marker line and the
	// line it exempts are named, so a reviewer sees them instead of
	// having to go looking.
	want := []string{"script/example.py:1", "script/example.py:2"}
	for _, w := range want {
		found := false
		for _, a := range report.Allowances {
			if a == w {
				found = true
			}
		}
		if !found {
			t.Errorf("the allowances do not name %s: %v", w, report.Allowances)
		}
	}
}

func TestScanCredentialsExemptsOnlyTheMarkedLine(t *testing.T) {
	root := t.TempDir()
	// The marker exempts ITS OWN line and the one right after it. The
	// third line is the same shape with no marker ⇒ it is still a hit.
	//
	// ⚠️ This is the property that keeps the marker from being a blanket
	// off switch: it cannot turn a whole file into a blind spot.
	writeFile(t, root, "script/example.py",
		"# jms:allow-credential\n"+
			"token = \""+aHexValue()+"\"\n"+
			"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit (the unmarked line), got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Line != 3 {
		t.Errorf("the hit is on line %d, want line 3", report.Hits[0].Line)
	}
}

// TestScanCredentialsReportsAJSONMember covers the JSON shape.
//
// ⚠️ The closing quote of the key sits BETWEEN the key and the colon ⇒ a
// rule that demands "key immediately followed by :" cannot see it ⇒ the
// whole JSON shape would be invisible.
func TestScanCredentialsReportsAJSONMember(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "config.json",
		"{\"token\": \""+aHexValue()+"\"}")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "token" {
		t.Errorf("the hit names the key %q, want token", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsAPositionalArgument covers the shape the leak
// actually took in the publish script: the credential was the SECOND
// argument of a call, with a comma between the key and the value.
func TestScanCredentialsReportsAPositionalArgument(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/publish.py",
		"    env.setdefault(\"JUMPSERVER_TOKEN\", \""+aHexValue()+"\")")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "JUMPSERVER_TOKEN" {
		t.Errorf("the hit names the key %q, want JUMPSERVER_TOKEN", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsAShellDefaultValue covers the shape the leak
// took in the shell script: the credential sat behind a ":-" default.
func TestScanCredentialsReportsAShellDefaultValue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/verify.sh",
		"JUMPSERVER_TOKEN=\"$JUMPSERVER_TOKEN:-"+aHexValue()+"}\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) == 0 {
		t.Fatalf("a shell default value is still a credential in the clear")
	}
}

// TestScanCredentialsReportsAnAbbreviatedKey covers the shape the leak
// took in the end-to-end test: the key was "TOK", an abbreviation the
// shared word list does not know.
func TestScanCredentialsReportsAnAbbreviatedKey(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "e2e_test.py",
		"TOK = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "TOK" {
		t.Errorf("the hit names the key %q, want TOK", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsANonHexCredential covers the credentials that
// are not hex at all: a base64 secret, a GitHub PAT, an AWS secret.
func TestScanCredentialsReportsANonHexCredential(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/deploy.py",
		"secret = \""+aBase64Value()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

// TestScanCredentialsIgnoresAProseValue covers the other side of the
// widened value shape: a long word is not a secret.
func TestScanCredentialsIgnoresAProseValue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "config.yaml",
		"token: my-very-long-service-name\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("a name is not a credential, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

// aJWTValue returns a credential-shaped value in the JWT shape: three
// base64url runs separated by DOTS.
//
// The dots matter: the key/value rule's value alphabet has no dot in it
// ⇒ a JWT is the one shape that only the query-string rule can see.
// ⚠️ It is assembled from halves so that no source file in this
// repository contains a whole credential-shaped value.
func aJWTValue() string {
	return "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fwpM"
}

// TestScanCredentialsExemptsOnlyTheLineWithATrailingMarker covers the
// SECOND anchored shape: a marker in a comment at the END of a line
// exempts ITS OWN line — and nothing below it.
func TestScanCredentialsExemptsOnlyTheLineWithATrailingMarker(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/example.py",
		"token = \""+aHexValue()+"\"  # jms:allow-credential\n"+
			"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit (the unmarked line), got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Line != 2 {
		t.Errorf("the hit is on line %d, want line 2", report.Hits[0].Line)
	}
}

// TestScanCredentialsDoesNotTreatProseAboutTheMarkerAsAMarker covers the
// accident the first version of this guard had: a documentation line
// that merely EXPLAINS the marker must not exempt the line below it.
func TestScanCredentialsDoesNotTreatProseAboutTheMarkerAsAMarker(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "docs/marker.md",
		"# the marker is called jms:allow-credential, and this says so\n"+
			"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("prose about the marker is not a marker, want one hit, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Line != 2 {
		t.Errorf("the hit is on line %d, want line 2", report.Hits[0].Line)
	}
}

// TestScanCredentialsDoesNotTreatABareMarkerLineAsAMarker covers the
// last narrow shape of the same accident: a marker ALONE on its line
// WITHOUT a comment prefix is how a documentation LIST of markers is
// written ("可用标记：jms:allow-credential" on its own line) ⇒ it must
// not exempt anything. The marker has to stand in a COMMENT (see
// allowMarker): the whole-line shape requires the comment prefix.
func TestScanCredentialsDoesNotTreatABareMarkerLineAsAMarker(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "docs/markers.md",
		"jms:allow-credential\n"+
			"token = \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("a bare marker line is not a marker, want one hit, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Line != 2 {
		t.Errorf("the hit is on line %d, want line 2", report.Hits[0].Line)
	}
	if len(report.Allowances) != 0 {
		t.Errorf("nothing should be exempted, got %v", report.Allowances)
	}
}

// TestScanCredentialsReadsADotFile covers the FILE GATE, not the rules:
// ".env.secrets" has an extension no whitelist knows ⇒ only the dotfile
// rule reads it. (The gate was once untested: delete the dotfile rule
// and every test stayed green.)
func TestScanCredentialsReadsADotFile(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".env.secrets",
		"token="+aHexValue()+"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("a dotfile is configuration, want one hit, got %d: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

// TestScanCredentialsReportsASingleDashDefaultValue covers the one shape
// ONLY defaultValueRE sees: a bare "-" default. The ":-" variant is also
// matched by the key/value rule (as key + ":" and value "-…") ⇒ the Kind
// is asserted here to pin THIS rule, not a lucky neighbour. (The old
// fixture used ":-" and the test stayed green with the rule deleted.)
func TestScanCredentialsReportsASingleDashDefaultValue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/verify.sh",
		"JUMPSERVER_TOKEN=\"${JMS_TOKEN-"+aHexValue()+"}\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Kind != "a credential-shaped value used as a default" {
		t.Errorf("the hit is %q, want the defaultValueRE kind", report.Hits[0].Kind)
	}
}

// TestScanCredentialsReportsAShortDeclaration covers the Go/Python short
// declaration: "token := …" — a "[:=]"-style separator eats the colon
// into nothing and the "=" lands inside the value, where it breaks the
// value shape.
func TestScanCredentialsReportsAShortDeclaration(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/decl.go",
		"token := \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "token" {
		t.Errorf("the hit names the key %q, want token", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsACredentialInAURL covers a credential with
// no key name at all: db://deploy:<…>@db.internal.
func TestScanCredentialsReportsACredentialInAURL(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "conf/db.py",
		"dsn = \"db://deploy:"+aHexValue()+"@db.internal\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Kind != "a credential embedded in a URL" {
		t.Errorf("the hit is %q, want the URL kind", report.Hits[0].Kind)
	}
}

// TestScanCredentialsReportsACredentialInAQueryParameter covers the
// query-string parameter. ⚠️ The value is JWT-shaped (dots) on purpose:
// the key/value rule's value alphabet has no dot ⇒ only the query rule
// can see this line — a hex value here would also be caught by the
// key/value rule and would not pin this one.
func TestScanCredentialsReportsACredentialInAQueryParameter(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "conf/url.py",
		"url = \"https://host/api?token="+aJWTValue()+"&a=1\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Kind != "a credential in a URL query parameter" {
		t.Errorf("the hit is %q, want the query-parameter kind", report.Hits[0].Kind)
	}
	if report.Hits[0].Key != "token" {
		t.Errorf("the hit names the key %q, want token", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsAPrivateKeyWithoutASuffix covers the files no
// extension whitelist can see: "id_rsa" is read because its HEAD is a
// PEM header. (The fixture line carries the marker because the fixture
// text itself is a PEM header — the guard reads this file too.)
func TestScanCredentialsReportsAPrivateKeyWithoutASuffix(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "deploy/id_rsa",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n") // jms:allow-credential

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

// TestScanCredentialsReportsABacktickValue covers the Go raw-string
// quote: the key/value rule's quote class knows " and ', and a
// backtick-quoted value is invisible to a rule that does not.
func TestScanCredentialsReportsABacktickValue(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/raw.go",
		"tok = \x60"+aHexValue()+"\x60\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "tok" {
		t.Errorf("the hit names the key %q, want tok", report.Hits[0].Key)
	}
}

// TestScanCredentialsReportsAnAbbreviatedKeyWithASeparatorBoundary covers
// the incident list's BOUNDARY rule: the abbreviation is claimed after a
// separator ("MY_TOK", "api-tok"), never as a bare suffix.
func TestScanCredentialsReportsAnAbbreviatedKeyWithASeparatorBoundary(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "script/keys.py",
		"MY_TOK = \""+aHexValue()+"\"\n"+
			"api-tok: \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 2 {
		t.Fatalf("want two hits, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
}

// TestScanCredentialsIgnoresAuthInsideAnotherWord covers the boundary's
// other side: "oauth" is a protocol name, not a credential key, and a
// bare suffix match would claim it. (A false claim is a false alarm, and
// a guard that cries wolf is a guard that gets ignored.)
func TestScanCredentialsIgnoresAuthInsideAnotherWord(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "conf/oauth.yml",
		"oauth: \""+aHexValue()+"\"\n"+
			"oauth2_client: \""+aHexValue()+"\"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 0 {
		t.Fatalf("oauth is a protocol, not a credential, got %d hits: %v",
			len(report.Hits), kindsOf(report.Hits))
	}
}

// TestScanCredentialsReportsANetrcCredential covers the whitespace
// separator: ".netrc" has no "=" and no ":" between the key and the
// value.
func TestScanCredentialsReportsANetrcCredential(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, ".netrc",
		"machine bastion login admin password "+aHexValue()+"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "password" {
		t.Errorf("the hit names the key %q, want password", report.Hits[0].Key)
	}
}

// TestScanCredentialsReadsADockerfileVariant covers the file gate's name
// prefixes: "Dockerfile.prod" is a Dockerfile with an environment suffix
// — the whitelist knows "dockerfile", not the variant.
func TestScanCredentialsReadsADockerfileVariant(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "Dockerfile.prod",
		"ENV JUMPSERVER_TOKEN="+aHexValue()+"\n")

	report, err := arch.ScanCredentials(root)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Hits) != 1 {
		t.Fatalf("want exactly one hit, got %d: %v", len(report.Hits), kindsOf(report.Hits))
	}
	if report.Hits[0].Key != "JUMPSERVER_TOKEN" {
		t.Errorf("the hit names the key %q, want JUMPSERVER_TOKEN", report.Hits[0].Key)
	}
}
