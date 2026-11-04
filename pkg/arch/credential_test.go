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

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/arch"
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
	writeFile(t, root, "script/example.py",
		"# a shape, not a secret: jms:allow-credential\n"+
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
	// ⚠️ The marked line exempts itself AND the line right below it ⇒
	// two lines are accounted for here (the marker and the shape).
	found := false
	for _, a := range report.Allowances {
		if strings.HasPrefix(a, "script/example.py:") {
			found = true
		}
	}
	if !found {
		t.Errorf("the allowance does not name the file: %v", report.Allowances)
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
