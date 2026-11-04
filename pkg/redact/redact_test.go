package redact

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/oagentkit/guardx/logredact"
)

// A payload field is replaced by its SIZE, never by its content.
//
// A payload is bytes going over the wire (a file's content, a request
// body). Writing it down in full writes the file into the log.
func TestAPayloadFieldIsReplacedByItsSize(t *testing.T) {
	in := `{"target":"/etc/hosts","content":"a secret file body"}`
	out := Payloads(in)
	if strings.Contains(out, "a secret file body") {
		t.Errorf("the payload was written down: %s", out)
	}
	if !strings.Contains(out, "target") {
		t.Errorf("the other fields were dropped: %s", out)
	}
	// The marker has to be READABLE: Go's HTML escaping would turn the
	// angle brackets into \u003c…\u003e.
	if !strings.Contains(out, "<18 bytes scrubbed>") {
		t.Errorf("the marker is not readable: %s", out)
	}
}

// A payload is a payload whatever shape it holds.
//
// The shape rules match `password: <string>`; a payload passed as an array
// of chunks, or as an object, has none of those shapes — and leaving it
// alone wrote it down in full.
func TestAPayloadIsScrubbedWhateverShapeItHolds(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"an array of chunks", `{"content":["chunk-one","chunk-two"]}`},
		{"an object", `{"content":{"key":"chunk-one"}}`},
		{"a number", `{"content":12345}`},
		{"a nested payload", `{"opts":{"content":"chunk-one"}}`},
		{"a payload inside an array", `{"items":[{"content":"chunk-one"}]}`},
	}
	for _, c := range cases {
		out := Payloads(c.in)
		if strings.Contains(out, "chunk-one") {
			t.Errorf("%s: the payload was written down: %s", c.name, out)
		}
	}
}

// What is not a payload is left alone: the trail's arguments are worth
// reading, and scrubbing them into uselessness would cost more than it
// saves.
func TestOtherFieldsAreLeftAlone(t *testing.T) {
	in := `{"asset":"node-071","command":"uptime","timeout":60}`
	if out := Payloads(in); out != in {
		t.Errorf("the arguments were rewritten: %s", out)
	}
}

// Text that is not a JSON object is not ours to rewrite.
func TestTextThatIsNotAnObjectIsLeftAlone(t *testing.T) {
	for _, in := range []string{"", "not json", "[1,2,3]"} {
		if out := Payloads(in); out != in {
			t.Errorf("%q was rewritten: %q", in, out)
		}
	}
	// Blank text comes back blank — trimming it is not a rewrite.
	if out := Payloads("   "); out != "" {
		t.Errorf("blank text came back as %q", out)
	}
}

// Scrubbing a payload twice must not shrink the size twice.
//
// The trail scrubs the arguments on its own side AND the registry scrubs
// them before handing them over, so the same arguments pass through this
// function twice. Without the guard, the second pass would measure the
// MARKER of the first one ("<40 bytes scrubbed>" is 20 bytes) and report
// that as the size of the payload — a number that is wrong, and wrong in
// the direction that looks precise.
func TestScrubbingAPayloadTwiceKeepsTheSize(t *testing.T) {
	in := `{"target":"/etc/hosts","content":"a secret file body"}`

	once := Payloads(in)
	twice := Payloads(once)

	if once != twice {
		t.Errorf("the second pass changed the payload marker:\n once:  %s\n twice: %s", once, twice)
	}
	if !strings.Contains(once, "18 bytes scrubbed") {
		t.Errorf("the size is not reported: %s", once)
	}
	if strings.Contains(twice, "secret file body") {
		t.Errorf("the payload was written down: %s", twice)
	}
}

// The combined scrubber is the ONE thing the repository scrubs with, and
// it must be guarded here — not only where it happens to be used.
//
// ⚠️ Making Scrub a no-op leaves ./pkg/redact green: the guards live in
// pkg/audit, so the base package can lose its own behaviour without
// anything noticing.
func TestScrubMasksTheCredential(t *testing.T) {
	got := Scrub(`{"asset":"node","password":"p&ssw0rd"}`)
	if strings.Contains(got, "p&ssw0rd") {
		t.Errorf("the credential survived: %s", got)
	}
}

// The credential word list is the whole point of the backstop, and it has
// to be guarded in BOTH directions.
//
// ⚠️ Dropping words from it leaves credentials in the trail in the clear
// (the upstream rules match neither "authorization" nor "cookie" inside a
// JSON field), and matching words as SUBSTRINGS destroys innocent fields
// ("session", "key_id", "keywords") — which is not a theoretical worry:
// it hit this repository's own tools.
func TestTheCredentialWordList(t *testing.T) {
	must := []string{
		`{"password":"x"}`, `{"authorization":"Basic eA=="}`, `{"bearer":"x"}`,
		`{"cookie":"s=1"}`, `{"x-api-key":"x"}`, `{"api-key":"x"}`,
		`{"my_access_token":"x"}`, `{"oauth_access_token":"x"}`,
		`{"token_value":"x"}`, `{"secret_value":"x"}`, `{"api_key":"x"}`,
		`{"access_key":"x"}`, `{"client_secret":"x"}`, `{"private_key":"x"}`,
		`{"session_token":"x"}`, `{"PASSWORD":"x"}`, `{"accessKey":"x"}`,
		// ⚠️ The ESCAPED form — a JSON document carried as the value of
		// another field. There the key is written `\"password\"`, and
		// neither the upstream shape rules nor the plain backstop match
		// it: it has its own rule, and that rule is the only thing
		// standing between the credential and the trail.
		//
		// ⚠️ The word list was pinned without this form ⇒ the escaped
		// rule could be switched off entirely and the test would still
		// be green (a mutation scan showed exactly that).
		`{"params":"{\"password\":\"x\"}"}`,
		`{"params":"{\"api_key\":\"AKIAX\"}"}`,
		`{"params":"{\"client_secret\":\"x\"}"}`,
	}
	for _, in := range must {
		out := Scrub(in)
		// ⚠️ The assertion has to name EVERY secret in the list, not a
		// sample: the escaped form's value is `\"x\"`, and a check for
		// `"x"` does not see it (the escaped value carries a backslash
		// before the closing quote) ⇒ the check passed on a credential
		// that was still there.
		for _, secret := range []string{
			`"x"`, `\x\"`, `Basic eA==`, `"s=1"`, `AKIAX`,
		} {
			if strings.Contains(out, secret) {
				t.Errorf("the credential %q survived %s -> %s", secret, in, out)
			}
		}
	}

	keep := []string{
		`{"session":"abc"}`, `{"key_id":"k"}`, `{"secret_type":"password"}`,
		`{"token_count":5}`, `{"keyword":"x"}`, `{"monkey":"x"}`,
		`{"keywords":["a","b"]}`, `{"public_key":"ssh-rsa AAA"}`,
		`{"tokens":"t"}`, `{"passwords":"p"}`, `{"session_id":"s"}`,
		`{"secretary":"bob"}`,
	}
	for _, in := range keep {
		out := Scrub(in)
		if strings.Contains(out, "****") {
			t.Errorf("an innocent field was masked %s -> %s", in, out)
		}
	}
}

// A BOOLEAN is a flag, not a credential.
//
// ⚠️ `{"has_password":true}` says the account HAS a password — it is not
// one — and masking it would turn a fact into a string and lose the
// distinction. The shape rules alone get this wrong.
func TestABooleanFlagIsNotMasked(t *testing.T) {
	for _, in := range []string{
		`{"has_password":true,"user":"opsuser"}`,
		`{"need_password":false,"user":"opsuser"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "****") {
			t.Errorf("a boolean flag was masked %s -> %s", in, out)
		}
	}
	// ⚠️ But a number IS a credential: `{"password":123}`.
	out := Scrub(`{"password":123}`)
	if strings.Contains(out, "123") {
		t.Errorf("a numeric credential survived: %s", out)
	}
}

// A credential inside an ESCAPED JSON string must be masked too.
//
// ⚠️ `{"params":"{\"password\":\"x\"}"}` — a JSON document carried as
// the value of another field. The key there is written `\"password\"`,
// and neither the upstream shape rules nor the plain backstop match it.
//
// ⚠️ This is the shape a COMMAND reaches it in (`cat <<< '{"password":"x"}'`),
// so it was a real leak, not a theoretical one.
func TestACredentialInAnEscapedJSONStringIsMasked(t *testing.T) {
	in := `{"params":"{\"password\":\"p&ssw0rd\"}"}`
	out := Scrub(in)
	if strings.Contains(out, "p&ssw0rd") {
		t.Errorf("the credential survived in an escaped JSON string: %s", out)
	}
}

// A credential whose key is in CAPITAL letters must be masked too.
//
// ⚠️ The upstream rules are case-insensitive, and the local backstop has
// to be as well: it exists precisely for the shapes the upstream rules
// cannot match (a value containing `&`), and a lost `(?i)` there meant the
// big-key form leaked in the clear while every test stayed green — the
// existing capitalised test was masked by the UPSTREAM rules, so the
// backstop was never involved.
func TestACapitalisedCredentialKeyIsMasked(t *testing.T) {
	for _, in := range []string{
		`{"PASSWORD":"p&ssw0rd"}`,
		`{"API_KEY":"abc&def"}`,
		`{"Token":"x&y"}`,
		`{"Secret":"a&b"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "&") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// A value that merely STARTS with true/false is not a boolean.
//
// ⚠️ "trueX" is a VALUE, not a flag. Treating it as a boolean took it
// out of the scrubbing — and then neither the upstream rules nor the
// backstop could see it any more, so the credential stayed in the clear.
//
// ⚠️ The right outcome is that it is MASKED (it is a credential), not
// that it is kept as a boolean.
func TestAValueStartingWithTrueIsNotABoolean(t *testing.T) {
	out := Scrub(`{"password":trueX}`)
	if strings.Contains(out, "trueX") {
		t.Errorf("a value that starts with true was taken for a boolean: %s", out)
	}
	if !strings.Contains(out, "****") {
		t.Errorf("the credential was not masked: %s", out)
	}
}

// A string that CONTAINS a boolean-looking pair is not a JSON key.
//
// ⚠️ The pattern used to match the start of a string VALUE, so it ate
// part of the user's data — and a broken document makes the payload
// reduction fail, which leaves a base64 private key in the trail in the
// clear.
func TestABooleanLookingStringIsNotAJSONKey(t *testing.T) {
	out := Scrub(`{"cmd":"password=true"}`)
	if strings.Contains(out, `"password":true`) {
		t.Errorf("a string value was mistaken for a key: %s", out)
	}
	// ⚠️ And the payload must still be reduced: the document has to stay
	// parseable.
	out = Scrub(`{"content":"SECRETPAYLOAD","x":"password: true, y"}`)
	if strings.Contains(out, "SECRETPAYLOAD") {
		t.Errorf("the payload was not reduced: %s", out)
	}
}

// The escaped form must be masked whatever the case of the key.
//
// ⚠️ The escaped rule lost its `(?i)` once (when the plain one did), and
// nothing caught it: the existing escaped test used a lower-case key. A
// capitalised key inside an escaped JSON string is the shape a command
// would carry, and it is the shape the upstream rules cannot match.
func TestACapitalisedCredentialInAnEscapedJSONStringIsMasked(t *testing.T) {
	for _, in := range []string{
		`{"params":"{\"PASSWORD\":\"p&ssw0rd\"}"}`,
		`{"params":"{\"API_KEY\":\"abc&def\"}"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "&") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// The scrubbed document must still BE a document.
//
// ⚠️ The shape rules replace the key's quoting along with the value
// (`"password":123` becomes `"password=****`), so a credential field
// whose value is not a plain string took the closing brace of the object
// with it. A broken document is not a cosmetic problem: the payload
// reduction needs a parseable document, and the agent reading the trail
// gets text it cannot read as data.
//
// ⚠️ This test also pins the IDEMPOTENCE the two exits depend on: the
// registry scrubs the arguments and the trail scrubs them again, and the
// two results have to be byte for byte the same.
func TestScrubbingKeepsTheDocumentReadable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		keep string
	}{
		{"a quoted value", `{"password":"x","user":"opsuser"}`, `"user":"opsuser"`},
		{"a numeric value", `{"password":123,"user":"opsuser"}`, `"user":"opsuser"`},
		{"a signed numeric value", `{"password":-1,"user":"opsuser"}`, `"user":"opsuser"`},
		{"a boolean value", `{"has_password":true,"user":"opsuser"}`, `"user":"opsuser"`},
		{"two credential fields", `{"a":1,"password":2,"b":3}`, `"b":3`},
		{"a flag and a credential", `{"has_password":true,"password":123}`, `"has_password":true`},
		{"a client key", `{"client_key":"x","user":"opsuser"}`, `"user":"opsuser"`},
		// ⚠️ The DOUBLE-escaped document — the shape the trail really
		// holds, because the SDK serialises the arguments as JSON and a
		// command that carries its own JSON arguments ends up escaped
		// twice. ⇒ the replacement has to keep the same number of
		// backslashes, or the document stops being JSON.
		{"a doubly-escaped document", `{"params":"{\\\"password\\\":\\\"x\\\"}"}`, `"params"`},
		{"an escaped document", `{"params":"{\"password\":\"x\"}"}`, `"params"`},
		{"a credential inside a command", `{"cmd":"export PASSWORD=p&ss"}`, `"cmd"`},
		{"an innocent field", `{"session":"abc","key_id":"k"}`, `"key_id":"k"`},
		// ⚠️ A key the upstream rules recognise and this repository's word
		// list did not: the upstream rules eat the key's closing quote and
		// only the backstop can put it back ⇒ a word list that is not a
		// superset leaves the structure broken, and the SECOND pass then
		// eats one more character ⇒ the registry's copy of the arguments
		// and the trail's copy stop being the same string.
		{"a key with an arbitrary prefix", `{"mytoken":"x","user":"opsuser"}`, `"user":"opsuser"`},
		{"a key with a joined prefix", `{"dbpassword":"x","user":"opsuser"}`, `"user":"opsuser"`},
	}
	for _, c := range cases {
		out := Scrub(c.in)
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("%s: the scrubbed document is no longer JSON: %s (%v)", c.name, out, err)
		}
		// ⚠️ A document that is still JSON can still have LOST a field:
		// the upstream rules eat the closing quote of the key, and the
		// backstop's unquoted value then runs on into the NEXT field.
		// "the document parses" was not enough to catch it.
		if !strings.Contains(out, c.keep) {
			t.Errorf("%s: the scrubbing ate the rest of the document: %s", c.name, out)
		}
		if again := Scrub(out); again != out {
			t.Errorf("%s: scrubbing twice gives two different strings:\n once:  %s\n twice: %s",
				c.name, out, again)
		}
	}
}

// The DOUBLE-escaped document must keep its escaping.
//
// ⚠️ The replacement writes the mask back with the SAME number of
// backslashes the match had. ⇒ one backslash less and the nested
// document's quotes are no longer escaped ⇒ the document stops being
// the document it was (the next pass reads it differently, and the
// two exits stop agreeing).
//
// ⚠️ The document still PARSES in that case ⇒ "the document is still
// JSON" is not enough to catch it.
func TestTheDoubleEscapedDocumentKeepsItsEscaping(t *testing.T) {
	// ⚠️ The fixture is a Go RAW string ⇒ the bytes are exactly what they
	// look like ⇒ two levels of escaping, which is what the SDK produces
	// for a command that carries its own JSON arguments.
	in := `{"params":"{\"password\":\"x\"}"}`
	out := Scrub(in)
	if !strings.Contains(out, `{"params":"{\"password\":\"****\"}"}`) {
		t.Errorf("the escaping was not kept: %s -> %s", in, out)
	}
	// ⚠️ And the mask has to be there ⇒ the escaping was kept, not the
	// value.
	if strings.Contains(out, `\"x\"`) {
		t.Errorf("the credential survived: %s -> %s", in, out)
	}
}

// A credential in a JSON string, in escaped quotes, is the shape the
// execution plane actually produces.
//
// ⚠️ `{"command":"export PASSWORD=\"SECRET\""}` — the command is a JSON
// string, so the quotes inside it are escaped.
//
// ⚠️ The upstream rules cannot mask that value: their value pattern
// stops at the first `&` or quote — and a backslash is none of those, so
// they eat the backslash and leave `"SECRET\""` standing ⇒ the
// credential, in FULL, reaches the trail.
//
// ⚠️ So the free-text rule has to run BEFORE them: they must never see
// the credential at all.
func TestACredentialInEscapedQuotesIsMaskedWhole(t *testing.T) {
	for _, in := range []string{
		`{"command":"export PASSWORD=\"SECRET\""}`,
		`{"command":"export PASSWORD='SECRET'"}`,
		`{"command":"export PASSWORD=\"SECRET\" && ./run.sh"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "SECRET") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// A credential field whose value is an OBJECT or an ARRAY is masked
// WHOLE.
//
// ⚠️ The shape rules mask a FRAGMENT of such a value and leave the rest
// standing — and the rest may hold a credential under a name that does
// not say "credential": `{"secret":{"value":"s3cr3t"}}` left "s3cr3t"
// in the clear.
func TestANonScalarCredentialIsMaskedWhole(t *testing.T) {
	for _, in := range []string{
		`{"secret":{"type":"password","value":"s3cr3t"}}`,
		`{"secret":{"value":"s3cr3t"}}`,
		`{"secret":["s3cr3t"]}`,
		`{"secret":{"nested":{"deeper":["s3cr3t"]}}}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "s3cr3t") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("the scrubbed document is no longer JSON: %s (%v)", out, err)
		}
	}
}

// The text behind an `&` belongs to the URL or to the command, not to
// the credential.
//
// ⚠️ The `&` is ambiguous: it separates two query parameters ("?token=abc
// &user=bob"), it is a shell operator ("export PASSWORD=x&./run.sh"), and
// it can be part of the credential itself ("p&ssw0rd"). The rule tells
// them apart by what FOLLOWS it.
func TestTheTextBehindAnAmpersandStays(t *testing.T) {
	cases := []struct {
		in   string
		keep string
	}{
		{`{"url":"https://x/api?token=abc&user=bob"}`, `&user=bob`},
		{`{"cmd":"export PASSWORD=hunter2&./run.sh"}`, `&./run.sh`},
		{`{"cmd":"export PASSWORD=hunter2&&./run.sh"}`, `&&./run.sh`},
	}
	for _, c := range cases {
		out := Scrub(c.in)
		if strings.Contains(out, "hunter2") || strings.Contains(out, "abc") {
			t.Errorf("the credential survived %s -> %s", c.in, out)
		}
		if !strings.Contains(out, c.keep) {
			t.Errorf("the text behind the ampersand was lost %s -> %s", c.in, out)
		}
	}
}

// A SECOND credential behind the ampersand is a credential too.
//
// ⚠️ The tail behind a separating `&` was inside the value the match
// consumed ⇒ the outer pass never looked at it ⇒ "?token=abc&password=
// hunter2" kept the second one in the clear.
//
// ⚠️ And the tail has to be a shape the UPSTREAM rules cannot mask either,
// or this test proves nothing: upstream masks a plain "password=x" ⇒ the
// tail is covered without the re-scrub ⇒ the mutation would survive. The
// quoted value with an `&` inside is the shape upstream does not match.
func TestTheTailBehindAnAmpersandIsScrubbedToo(t *testing.T) {
	for _, in := range []string{
		`{"url":"https://x/api?token=abc&password=\"p&ssw0rd\""}`,
		`export TOKEN=abc && export PASSWORD=hunter2`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "hunter2") || strings.Contains(out, "ssw0rd") {
			t.Errorf("the second credential survived %s -> %s", in, out)
		}
	}
}

// The free-text rule must not mask what is not a credential.
//
// ⚠️ This repository has been bitten by exactly this: a word list that
// matched as a SUBSTRING masked "session" (on jms_command_audit) and
// "key_id" (on jms_user_sshkey_remove) ⇒ the trail stopped recording
// WHICH session was queried — the very thing it exists to record.
func TestTheProseFormDoesNotOverMask(t *testing.T) {
	for _, in := range []string{
		`export SESSION=abc && export KEY_ID=k`,
		`export MONKEY=x`,
		`export KEYWORD=y`,
		`export SECRET_TYPE=password`,
		`export PUBLIC_KEY=abc`,
		`export TOKEN_COUNT=5`,
		`curl https://x/api?session=abc&keyword=y`,
	} {
		if out := Scrub(in); out != in {
			t.Errorf("an ordinary assignment was masked %s -> %s", in, out)
		}
	}
}

// The upstream rules' REPLACEMENT shape is part of this repository's
// contract, and it is pinned here on purpose.
//
// ⚠️ The combination is idempotent only because this repository's masked
// values have the SAME shape as the upstream ones (`KEY=****`). If the
// upstream rules changed their replacement, the second pass would rewrite
// what the first pass produced ⇒ the registry's copy of the arguments and
// the trail's copy would stop being the same string.
//
// ⚠️ The free-text rule is the one that depends on it (the upstream rules
// do not match a quoted value that contains a `&`, so for that shape the
// mask is OURS) ⇒ the dependency has to be visible, not implied.
func TestTheUpstreamReplacementShapeIsPinned(t *testing.T) {
	if got := logredact.Redact("PASSWORD=x"); got != "PASSWORD=****" {
		t.Errorf("the upstream replacement shape changed: %q", got)
	}
}

// A credential in FREE TEXT is masked WHOLE.
//
// ⚠️ The upstream rules stop the value at the first `&` — and when the
// value is QUOTED and contains a `&`, they do not match it at all: their
// value pattern stops at the `&` and then insists on the closing quote,
// so the whole rule fails and `export PASSWORD='p&ssw0rd'` reaches the
// trail in the clear.
//
// ⚠️ The execution plane runs commands, and a command is where a
// credential usually is.
func TestAProseCredentialIsMaskedWhole(t *testing.T) {
	for _, in := range []string{
		`export PASSWORD=p&ssw0rd && ls`,
		`export PASSWORD='p&ssw0rd' && ls`,
		`export PASSWORD="p&ssw0rd" && ls`,
		`{"cmd":"export PASSWORD=p&ssw0rd"}`,
		`{"cmd":"password=p&ssw0rd"}`,
		// ⚠️ The COLON form ("login failed: password: …") is what a log
		// line carries, and the upstream rules accept it too — but they
		// only mask it up to the first `&` ⇒ the tail stayed in the clear.
		`login failed: password: p&ssw0rd`,
		`invalid token: p&ssw0rd`,
		// ⚠️ And the colon form with a QUOTED value: the upstream rules
		// do not match it at all, and the free-text rule only knew `=`.
		`secret: "p&ssw0rd"`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "ssw0rd") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// An `&` that is PART OF the credential must not be read as a separator.
//
// ⚠️ The separator test asks two questions: what FOLLOWS the `&`, and
// whether a `?` came before it. A parameter name after the `&` is only a
// separator inside a QUERY STRING — "?token=abc&user=bob" is two
// parameters, while "PASSWORD=AAA&bbb=1" is ONE credential that happens
// to contain an `&`.
//
// ⚠️ Without the `?` the two are told apart by nothing, and the wrong
// reading masks the head and leaves the tail in the clear: the trail
// would say "password=****" and the rest of the credential would sit
// next to it in the clear.
//
// ⚠️ And the "judge it the safe way" rule does not cover this: an `&`
// followed by a parameter name looks exactly like a separator, so the
// safe side and the wrong side are the SAME side here.
func TestAnAmpersandInsideACredentialIsNotASeparator(t *testing.T) {
	for _, in := range []string{
		`PASSWORD=AAA&bbb=1`,
		`password=AAA&bbb=1`,
		`export TOKEN=abc&def=ghi`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "AAA") || strings.Contains(out, "abc") {
			t.Errorf("the credential head stayed in the clear %s -> %s", in, out)
		}
		// The tail is the part that used to leak: "bbb=1" is the rest
		// of the credential, not a parameter of a URL.
		if strings.Contains(out, "bbb=1") || strings.Contains(out, "def=ghi") {
			t.Errorf("the credential tail stayed in the clear %s -> %s", in, out)
		}
	}
	// ⚠️ And a REAL query string keeps its other parameters: the trail
	// exists to record WHAT was run, and a URL is what was run.
	out := Scrub(`?token=abc&user=bob`)
	if !strings.Contains(out, "user=bob") {
		t.Errorf("a query string lost its other parameters: %s", out)
	}
}

// The `?` that licenses a separator must belong to THAT query string.
//
// ⚠️ The rule asks "is there a `?` in front of this `&`?" — and the
// obvious reading of that question ("anywhere in the text") is wrong: a
// `?` in an earlier sentence says nothing about the `&` that follows
// the credential.
//
// ⚠️ So the `?` has to OPEN the query string the `&` belongs to: the
// text between it and the credential must not contain whitespace or a
// quote — a URL has neither, and anything that has them ends the query
// string.
//
// ⚠️ When it cannot tell, it says NO ⇒ the credential is masked WHOLE
// ⇒ the tail does not survive.
func TestOnlyTheSameQueryStringLicensesASeparator(t *testing.T) {
	for _, in := range []string{
		`did it work? PASSWORD=AAA&bbb=1`,
		`curl 'https://x/api?a=1' --password=AAA&bbb=1`,
		`{"cmd":"curl 'https://x/api?a=1' --password=AAA&bbb=1"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "bbb=1") {
			t.Errorf("the credential tail stayed in the clear %s -> %s", in, out)
		}
	}
	// ⚠️ And the query string itself keeps its parameters — including the
	// ones BEHIND a credential ("?token=…&password=…&q=1" ⇒ "q=1" is a
	// parameter of the URL, not part of the credential).
	for _, in := range []string{
		`?token=abc&user=bob`,
		`{"url":"https://x/api?token=abc&user=bob"}`,
		`https://x/api?token=abc&user=bob`,
		`{"url":"https://x/api?token=abc&password=p&q=1"}`,
	} {
		out := Scrub(in)
		if !strings.Contains(out, "user=bob") && strings.Contains(in, "user=bob") {
			t.Errorf("a query string lost its other parameters: %s -> %s", in, out)
		}
		if !strings.Contains(out, "q=1") && strings.Contains(in, "q=1") {
			t.Errorf("a query string lost the parameter behind the credential: %s -> %s", in, out)
		}
	}
}

// The COLON form must not break the idempotence.
//
// ⚠️ The free-text rule used to run LAST — it was the cleanup that took
// away the tail the upstream rules left behind. Moving it to the front
// (to fix the escaped quotes) took that job away from it ⇒ the colon
// form's tail went back into the trail AND the second pass produced a
// different string ⇒ the registry's copy of the arguments and the
// trail's copy stopped being the same string.
func TestTheColonFormIsIdempotent(t *testing.T) {
	for _, in := range []string{
		`login failed: password: S3CRET&TAIL`,
		`invalid token: S3CRET&TAIL`,
		`mysql: password: S3CRET&TAIL`,
	} {
		once := Scrub(in)
		if again := Scrub(once); again != once {
			t.Errorf("scrubbing twice gives two different strings:\n once:  %s\n twice: %s",
				once, again)
		}
	}
}

// An unquoted value must not eat the NEXT field.
//
// ⚠️ The shape rules eat the key's closing quote when they mask a field,
// so the text right after such a field starts with a quote ⇒ an unquoted
// value that ran into it would swallow the next field with it, and the
// trail would lose a fact ("user" disappears).
//
// ⚠️ Both backstops have this rule, and both must keep it: the plain one
// and the ESCAPED one. The escaped one had not ⇒ a credential inside an
// escaped JSON string took its neighbour with it.
func TestAnUnquotedValueDoesNotEatTheNextField(t *testing.T) {
	for _, in := range []string{
		`{"password":x"user":"bob"}`,
		`{"params":"{\"password\":x\"user\":\"bob\"}"}`,
	} {
		out := Scrub(in)
		if !strings.Contains(out, "bob") {
			t.Errorf("the next field was eaten: %s -> %s", in, out)
		}
	}
}

// A fact's SPELLING does not change what it is.
//
// ⚠️ The pattern that finds the value is case-insensitive (`(?i)`), so it
// matches "TRUE" and "Null" as readily as "true" and "null" ⇒ a
// case-sensitive comparison would read "TRUE" as a CREDENTIAL and mask
// it ⇒ the flag "this account HAS a password" would turn into a string,
// and "there is NO password" would too.
func TestAFactIsAFactWhateverItsSpelling(t *testing.T) {
	for _, in := range []string{
		`{"password":NULL}`,
		`{"password":Null}`,
		`{"password":null}`,
		`{"has_password":TRUE}`,
		`{"has_password":True}`,
		`{"has_password":true}`,
		`{"need_password":FALSE}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "****") {
			t.Errorf("a fact was masked: %s -> %s", in, out)
		}
	}
}

// The free-text rule has to run TWICE — and the second pass has a shape
// the first one cannot see.
//
// ⚠️ The first pass runs BEFORE the shape rules, so it cannot see what
// they leave behind. The shape rules eat the key's CLOSING QUOTE when
// they mask a field ("password":"x" ⇒ "password=****"), and what they
// leave behind is a key that ends in a QUOTE: `password":x`.
//
// ⚠️ That shape is not matched by the first pass (the quote sits between
// the key and the separator) but it IS matched by the second one — and
// that is the pass that takes the tail the shape rules stopped at
// ("password=****&TAIL" ⇒ the tail is still in the clear).
//
// ⚠️ Without the second pass the credential's tail lands in the trail
// in the clear, and the first pass cannot clean it up: it ran before the
// shape rules mangled the key.
func TestTheFreeTextRuleRunsTwice(t *testing.T) {
	for _, in := range []string{
		`password":p&ssw0rd`,
		`password":AAA&BBB&CCC`,
		`export password":p&ssw0rd`,
		`login failed: password":p&ssw0rd`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "ssw0rd") || strings.Contains(out, "BBB") {
			t.Errorf("the credential tail survived %s -> %s", in, out)
		}
	}
}

// A `null` credential field is a FACT, not a credential — and it must not
// take the next field with it.
//
// ⚠️ The shape rules eat a `null` together with the `,` or `}` behind it
// ("{"password":null,"user":"bob"}" ⇒ the `user` field disappeared), and
// the backstop's unquoted value then ran on into the next field.
func TestANullCredentialFieldKeepsItsNeighbours(t *testing.T) {
	for _, in := range []string{
		`{"asset":"node","password":null,"user":"bob"}`,
		`{"asset":"node","user":"bob","password":null}`,
		`{"asset":"node","secret":null}`,
	} {
		out := Scrub(in)
		if strings.Contains(in, "bob") && !strings.Contains(out, "bob") {
			t.Errorf("the neighbour field was eaten: %s -> %s", in, out)
		}
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("the scrubbed document is no longer JSON: %s (%v)", out, err)
		}
	}
}

// The command behind the credential has to stay readable.
//
// ⚠️ `&&` is a shell OPERATOR, not part of the credential. Masking the
// whole value took the command with it, and the trail exists to record
// WHAT was run.
func TestAProseCommandKeepsItsTail(t *testing.T) {
	out := Scrub(`export PASSWORD=hunter2&&./run.sh --flag`)
	if strings.Contains(out, "hunter2") {
		t.Errorf("the credential survived: %s", out)
	}
	if !strings.Contains(out, "./run.sh") {
		t.Errorf("the command behind the credential was lost: %s", out)
	}
}

// A credential inside an ESCAPED JSON string must not escape.
//
// ⚠️ The SDK serialises the arguments as JSON, and a command that
// carries its own JSON arguments ends up with the key written
// `\"password\"` — an ESCAPED quote. Neither the upstream shape rules
// nor the plain backstop match that form ⇒ the credential survived in
// the clear (seen in the real trail: the args column of a jmsx_exec
// call whose command was `curl -d '{"username":…,"password":…}'`).
//
// ⚠️ And the escaped value must not CROSS an escaped quote: a value
// that ran past the next field's opening quote swallowed two fields at
// once ⇒ and when the FIRST key was not a credential word, the whole
// match was handed back unchanged ⇒ the credential in the SECOND
// field escaped with it.
func TestACredentialInsideAnEscapedJSONStringIsMasked(t *testing.T) {
	for _, in := range []string{
		`{\"username\":\"admin\",\"password\":\"gQacDGwVMXGRWDf9\"}`,
		`{\"a\":\"b\",\"password\":\"c\"}`,
		`{\"cmd\":\"x\",\"password\":\"c\"}`,
		`{\"password\":\"c\"}`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "gQacDGwVMXGRWDf9") || strings.Contains(out, `\"c\"`) {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// A legal document must stay a legal document.
//
// ⚠️ The idempotence checks do NOT cover this: a broken replacement can
// be idempotent (the broken shape is not matched again) ⇒ "scrubbing
// twice gives the same string" can hold while the document is no longer
// JSON.
//
// ⚠️ And the escape depth is where that happens: a pattern reads "\\"
// as ONE literal backslash, while a REPLACEMENT string does not
// interpret backslashes at all ⇒ the replacement needs HALF the
// characters the pattern does ⇒ getting that wrong doubles the
// escaping ⇒ the output is no longer the document it was.
func TestTheScrubbedDocumentIsStillJSON(t *testing.T) {
	for _, in := range []string{
		`{"params":"{\"password\":\"x\"}"}`,
		`{"cmd":"export PASSWORD=\"SECRET\""}`,
		`{"password":"x"}`,
		`{"secret":{"value":"s3cr3t"}}`,
		`{"a":1,"password":"x","b":2}`,
	} {
		out := Scrub(in)
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("the scrubbed document is no longer JSON: %s -> %s (%v)", in, out, err)
		}
	}
}

// The two paths must agree on WHICH shapes are credentials.
//
// ⚠️ The answer path masks "mysql -uroot --password secret" (the flag
// shape) and the trail's rule did not ⇒ the same word, the same shape,
// masked on one path and not the other ⇒ exactly the drift this
// repository's whole exercise is about.
//
// ⚠️ The separator is "=", ":" **or whitespace**: a command-line
// argument can be written with any of the three.
func TestTheTrailMasksTheCommandLineShapes(t *testing.T) {
	for _, in := range []string{
		`mysql -uroot --password=secret`,
		`mysql -uroot --password secret`,
		`mysql -uroot --password: secret`,
	} {
		out := Scrub(in)
		if strings.Contains(out, "secret") {
			t.Errorf("the credential survived %s -> %s", in, out)
		}
	}
}

// The two paths must agree on WHICH shapes are credentials.
//
// ⚠️ The answer path (biz/handler) masks "mysql -uroot
// --password secret" and the trail's rule did not ⇒ the same word, the
// same shape, masked on one path and not the other ⇒ exactly the drift
// this repository's whole exercise is about.
//
// ⚠️ The separator is "=", ":" **or whitespace**: a command-line
// argument can be written with any of the three.
