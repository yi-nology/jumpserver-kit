// Package redact scrubs credentials out of anything that may be written down.
//
// The audit trail of the gate records the arguments of every call, and the
// arguments can carry a password, a private key or a token. Writing those to
// a log is how credentials leak: not through the bastion, but through the
// operator's terminal.
//
// logredact already knows the shapes that matter (Authorization headers,
// token prefixes, password fields, PEM blocks), so the rule set is not
// re-invented here.
package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oagentkit/guardx/logredact"
)

// Text scrubs the credentials out of a string.
func Text(s string) string {
	return logredact.Redact(s)
}

// payloadFields are the argument fields that carry a PAYLOAD rather than a
// description.
//
// logredact knows the shapes it knows — a password field, a token, a PEM
// private key block. A base64 payload has none of those shapes: it is just
// letters. A private key in base64 would otherwise be written down in full,
// and it would be written down by every layer that logs the arguments.
var payloadFields = map[string]bool{
	"content":        true,
	"content_base64": true,
	"body":           true,
}

// Payloads replaces the value of every payload field with its SIZE.
//
// The size is the original one, which is why this runs BEFORE the shape
// rules: after them, the field holds a redacted remnant, and reporting its
// length would report the length of the remnant instead of the length of
// what was passed.
//
// ⚠️ A payload field is scrubbed at ANY depth, and it is scrubbed whatever
// shape it holds. A payload passed as an array of chunks, or as an object,
// is still a payload — leaving it alone wrote it down in full, and the
// shape rules do not recognise it (they match `password: <string>`).
//
// A field that is not there is left alone.
//
// ⚠️ It is IDEMPOTENT, and it has to be: the trail scrubs the arguments
// again on its own side (the trail must not depend on its caller having
// scrubbed them), so the same arguments pass through this function twice.
// Without the guard, the second pass would measure the MARKER of the first
// one ("<40 bytes scrubbed>", 20 bytes) and report that as the size of the
// payload — a number that is wrong, and wrong in the direction that looks
// precise.
func Payloads(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || !strings.HasPrefix(s, "{") {
		return s
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return s
	}
	if !scrubPayloads(m) {
		return s
	}
	// ⚠️ Without SetEscapeHTML(false) the angle brackets of the marker
	// come out as "<40 bytes scrubbed>" — and the
	// person reading the trail has to decode that before they can read it.
	out, err := marshalNoEscape(m)
	if err != nil {
		return s
	}
	return out
}

// Scrub scrubs a piece of free text: the shape rules, and then the
// credential-key backstop.
//
// ⚠️ It is the ONE place the repository scrubs with, and it is idempotent
// as a COMBINATION (not as either half): scrubbing twice gives the same
// string as scrubbing once. That is what lets the registry scrub the
// arguments before handing the record over AND the trail scrub them
// again for its two exits — either one alone is not idempotent.
//
// ⚠️ The backstop exists because the shape rules have holes: their value
// pattern excludes `&` (so a credential containing one defeats the whole
// rule) and it stops at the first inner quote (so only the prefix of such
// a credential is masked).
//
// ⚠️ The backstop keys on the FIELD NAME, not on the upstream rules'
// shape — so a change upstream does not silently open a hole here.
//
// ⚠️ The ORDER is load-bearing:
//
//	① the credential fields whose value is not a plain string are taken
//	   out (a number, a boolean, an array, an object);
//	② the payload reduction — it needs a parseable document;
//	③ the free-text (prose) form — BEFORE the shape rules, because they
//	   MANGLE what they mask: for a value in escaped quotes inside a
//	   JSON string (`{"command":"export PASSWORD=\"SECRET\""}`) their
//	   value pattern eats the backslash, so they leave `"SECRET\""`
//	   standing in the clear — the credential in full;
//	④ the shape rules, then the quoted-form backstop (which repairs the
//	   structure they broke).
func Scrub(text string) string {
	// ⚠️ A credential field whose value is not quoted is taken out
	// FIRST: `{"password":123}` — the shape rules mask such a value by
	// replacing it and everything up to the next space, and their value
	// pattern does NOT exclude `}` ⇒ they eat the closing brace of the
	// object ⇒ the JSON is broken and the brace cannot be put back.
	//
	// ⚠️ A boolean flag is taken out with it: `{"has_password":true}`
	// says the account HAS a password — it is not one — and the shape
	// rules (which see the key and mask whatever follows it) turn it into
	// a string and lose the distinction. Taking it out and putting it back
	// is the only way to keep it a boolean.
	text, flags := takeOutBareCredentials(text)
	text = maskProseCredentials(Payloads(text))
	text = maskCredentialKeys(Text(text))
	// ⚠️ The free-text rule runs a SECOND time, after the shape rules:
	// the shape rules mask a value only up to the first `&`
	// ("password=****&TAIL") ⇒ whatever is behind that `&` is still in
	// the clear, and this pass is the one that takes it.
	// (It used to be the ONLY pass — it ran last — and moving it to the
	// front to fix the escaped quotes took that job away from it ⇒ a
	// colon-form credential's tail went back into the trail.)
	text = maskProseCredentials(text)
	// 引号容忍的第二遍只在没有结构可保的文本上跑：整行仍是合法 JSON 时
	// 上游已经按键整值打码过，残余形状不存在——再跑只会把健康的 JSON 打
	// 坏（实测）。残余（password":尾巴）只出现在非 JSON 的自由文本里。
	if !json.Valid([]byte(text)) {
		text = maskProseCredentialsAgain(text)
	}
	return putBackBareCredentials(text, flags)
}

// bareValueRE finds a credential field whose value is NOT quoted — a
// number or a boolean.
//
// ⚠️ The key must be a REAL JSON key: it has to be preceded by the start
// of the object or a comma. Otherwise the pattern matches the start of a
// STRING VALUE ("cmd":"password=true") and eats part of the user's data —
// and a broken JSON document makes the payload reduction fail, which
// leaves the payload (a base64 private key) in the trail in the clear.
//
// ⚠️ The shape rules mask such a value by replacing it and everything up
// to the next space, and their value pattern does NOT exclude `}` ⇒ they
// eat the closing brace of the object (`{"password":123}` becomes
// `{"password=****`) ⇒ the JSON is broken and the brace cannot be put
// back.
//
// ⚠️ So these fields are taken out BEFORE the shape rules run, and put
// back afterwards: the number is masked (it is a credential) and the
// structure survives.
//
// ⚠️ The boundary after the value is `\b`, and it has to be ZERO-WIDTH.
// A pattern that CONSUMES the character after the value takes the comma
// that separates it from the next field — and then the next field has no
// prefix left, so it is not taken out either: one bare credential was
// enough to let the shape rules eat the closing brace of the second one.
// The first attempt at this pattern did exactly that (`{"a":1,"password":2}`
// came out with the `}` gone).
//
// ⚠️ `\b` is also what keeps "trueX" a VALUE: `e` and `X` are both word
// characters, so there is no boundary between them and the value is not a
// boolean. RE2 has no negative lookahead, so the boundary has to be
// expressed as a real boundary rather than as "not followed by".
//
// ⚠️ A number may carry a sign: `{"password":-1}` is a number, and the
// shape rules eat the closing brace of the object just the same.
//
// ⚠️ And `null` is one of them: the shape rules eat it together with the
// `,` or `}` behind it ("{"password":null,"user":"bob"}" ⇒ the `user`
// field disappeared), and the backstop's unquoted value then ran on into
// the next field. It is taken out like the numbers, and it goes back as
// it was: `null` says "there is no password", which is a FACT, not a
// credential.
var bareValueRE = regexp.MustCompile(
	`(?i)(^|[{,]\s*)"([a-z0-9_.-]+)"\s*:\s*((?:true|false|null)\b|[+-]?[0-9][0-9.eE+-]*\b)`)

// bareCredential is a credential field whose value is not quoted, taken
// out for the duration of the scrubbing.
type bareCredential struct {
	key string
	// value is the original bare value: a boolean is put back as it was
	// (it is a FACT, not a credential), a number is put back masked (it
	// IS a credential).
	value string
}

// takeOutBareCredentials replaces the credential FIELDS that carry an
// unquoted value with a neutral key, and returns them so they can be put
// back.
//
// ⚠️ The whole FIELD is replaced, not just its value: the shape rules mask
// whatever follows a credential key — a placeholder value would be masked
// too, and the boolean would be lost. A key that says nothing about
// credentials is left alone by both scrubbers.
//
// ⚠️ The two kinds share ONE counter: the placeholder names are the
// identity of the field, and two kinds with two counters would hand out
// the same name twice.
func takeOutBareCredentials(text string) (string, []bareCredential) {
	text, flags := takeOutScalarCredentials(text)
	text, more := takeOutNonScalarCredentials(text, len(flags))
	return text, append(flags, more...)
}

// takeOutScalarCredentials replaces the credential fields whose value is
// a number or a boolean.
func takeOutScalarCredentials(text string) (string, []bareCredential) {
	var flags []bareCredential
	out := bareValueRE.ReplaceAllStringFunc(text, func(m string) string {
		sub := bareValueRE.FindStringSubmatch(m)
		// ⚠️ sub[2] is the KEY: sub[1] is the prefix that has to be kept.
		if sub == nil || !isCredentialKey(sub[2]) {
			return m
		}
		flags = append(flags, bareCredential{key: sub[2], value: sub[3]})
		// ⚠️ The value becomes a neutral null: the key is neutral too, so
		// neither the shape rules nor the payload rules touch it.
		//
		// ⚠️ Nothing else is consumed: the boundary is zero-width, so the
		// comma that separates this field from the next one is still
		// there — and the next field needs it as its prefix.
		return fmt.Sprintf(`%s"%s":null`, sub[1], credPlaceholder(len(flags)-1))
	})
	return out, flags
}

// nonScalarValueRE finds a credential field whose value is an ARRAY or an
// OBJECT.
//
// ⚠️ The shape rules cannot mask such a value: their value pattern stops
// at the first space or quote, so they mask a FRAGMENT of it and leave
// the rest standing — and the rest may hold a credential under a name
// that does not say "credential" (`{"secret":{"value":"s3cr3t"}}` ⇒
// "s3cr3t" reached the trail in the clear).
//
// ⚠️ So the WHOLE field is taken out before the shape rules run, and put
// back masked afterwards: the credentials inside it go with it.
var nonScalarValueRE = regexp.MustCompile(
	`(?i)(^|[{,]\s*)"([a-z0-9_.-]+)"\s*:\s*([\[{])`)

// takeOutNonScalarCredentials replaces the credential fields whose value
// is an array or an object.
//
// ⚠️ The extent of such a value is NOT a regular expression's business —
// the brackets have to be COUNTED, and a string inside the value may hold
// brackets of its own ("{"cmd":"a{b"}").
func takeOutNonScalarCredentials(text string, first int) (string, []bareCredential) {
	matches := nonScalarValueRE.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text, nil
	}
	var b strings.Builder
	var flags []bareCredential
	last := 0
	for _, m := range matches {
		key := text[m[4]:m[5]]
		if !isCredentialKey(key) {
			continue
		}
		end, ok := MatchBracket(text, m[6])
		if !ok {
			// ⚠️ The value never closes ⇒ this is not a document we can
			// repair. Leave it: the shape rules will do what they do, and
			// a field we cannot read the end of is not one we may
			// rewrite.
			continue
		}
		b.WriteString(text[last:m[2]])
		flags = append(flags, bareCredential{key: key})
		b.WriteString(fmt.Sprintf(`%s"%s":null`, text[m[2]:m[3]],
			credPlaceholder(first+len(flags)-1)))
		last = end
	}
	if len(flags) == 0 {
		return text, nil
	}
	b.WriteString(text[last:])
	return b.String(), flags
}

// MatchBracket returns the position just after the bracket that closes
// the one at start.
//
// ⚠️ It counts BOTH kinds of bracket: a "{" inside an array closes with
// the "]", and counting only one kind would end the value early.
//
// ⚠️ And it counts brackets OUTSIDE strings only: a JSON string may hold
// braces of its own (`{"cmd":"a{b"}`), and a naive counter closes on the
// wrong one — which would cut the document in half.
//
// ⚠️ And it tracks ESCAPES inside the string: an escaped quote (`a\"b`)
// does not end the string.
//
// This is the BOUNDARY mechanics both masking paths share (the trail's
// and the answer's): where a value ends is not a formatting decision, so
// it must not be copied — a copy is a second place where the wrong brace
// can end the value in the middle.
func MatchBracket(text string, start int) (int, bool) {
	if start < 0 || start >= len(text) {
		return 0, false
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(text); i++ {
		c := text[i]
		if inString {
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == '"':
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
		case '[', '{':
			depth++
		case ']', '}':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
	}
	return 0, false
}

// putBackBareCredentials puts the credential fields back.
//
// ⚠️ The placeholder carries a run-unique token: a predictable one ("the
// user's own field is called __JMS_CRED_0__") would be picked up by the
// "replace the first occurrence" and the user's data would land on the
// credential key — and the second pass would then mask it, so the two
// exits would stop agreeing.
func putBackBareCredentials(text string, flags []bareCredential) string {
	for i, f := range flags {
		value := `"****"`
		if isBooleanLiteral(f.value) || isNullLiteral(f.value) {
			// ⚠️ A boolean is a FACT ("this account HAS a password"), not
			// a credential ⇒ it goes back as it was. And `null` says
			// "there is none" ⇒ that is a fact too.
			value = f.value
		}
		// ⚠️ The whole `"<placeholder>":null` goes back, not just the
		// name — otherwise the null that stood in for the value stays
		// behind as a second `:null`.
		text = strings.Replace(text, `"`+credPlaceholder(i)+`":null`, `"`+f.key+`":`+value, 1)
	}
	return text
}

// credPlaceholder is the name the i-th credential field hides under while
// the scrubbing runs.
//
// ⚠️ It has to be unique per run: a fixed name could collide with the
// user's own field.
func credPlaceholder(i int) string {
	return fmt.Sprintf("__JMS_CRED_%d_%x__", i, scrubRunID)
}

// scrubRunID makes the placeholders of one Scrub run unique.
//
// ⚠️ It is computed ONCE per PROCESS (at package init), not per call —
// so two calls in the same process use the same token. That is enough:
// the placeholder only has to be unique against the USER's own field
// names, and it is replaced back before the text is handed on.
var scrubRunID = fmt.Sprintf("%x", time.Now().UnixNano())

// credentialKeyRE matches a field whose NAME says the value is a
// credential.
//
// ⚠️ The key is matched WHOLE, not as a substring: a substring match
// treats "monkey", "keyword", "secretary" and "token_count" as
// credentials — and that is not a theoretical worry, it hit this
// repository's own tools ("session" on jms_command_audit, "key_id" on
// jms_user_sshkey_remove): a trail that hides WHICH session was queried
// has thrown away the very thing it exists to record.
//
// ⚠️ A prefix may be separated by "-" or "_" ("my_password"), and the
// closing quote may be MISSING — the upstream scrubber eats it when it
// masks a value, and a pattern that insists on the quote would never
// match.
//
// ⚠️ The value may not swallow a bracket or a brace: an array or object
// value must not be cut in half (that produced `{"keywords":"****","b"]}`).
// A non-scalar value is therefore masked WHOLE (the credentials inside it
// are masked with it) rather than half-masked.
//
// ⚠️ The key may have SEVERAL prefix segments ("my_access_token",
// "oauth_access_token") and may spell a compound name with "-" or "_"
// ("x-api-key", "api_key"). The prefix rule used to accept only one
// segment, and the dropped words (authorization, bearer, cookie, key)
// were the only defence for those shapes: the upstream rules match
// neither of them.
// credentialKeyRE finds a field and its value in one go.
//
// ⚠️ The KEY is matched as a whole and judged separately (see
// isCredentialKey): Go's regexp is RE2 and has NO negative lookahead, so
// "the word must not be followed by an identifier character" cannot be
// written in the pattern — and it matters, because matching a word as a
// SUBSTRING treats "monkey", "keyword", "secretary" and "tokens" as
// credentials, and that is not a theoretical worry: it hit this
// repository's own tools ("session" on jms_command_audit, "key_id" on
// jms_user_sshkey_remove). A trail that hides WHICH session was queried
// has thrown away the very thing it exists to record.
// ⚠️ The key starts with a PLAIN quote, and that is what keeps the two
// rules apart: the escaped form writes `\"password\"`, and there the
// quote is preceded by a backslash ⇒ the `[:=]` that follows the key
// cannot match ⇒ this rule does not touch it ⇒ the escaped rule has it
// to itself. (RE2 has no negative lookahead, so "a quote that is NOT
// preceded by a backslash" cannot be written in the pattern — the
// separation is a consequence of the shape, not a constraint on it.)
var credentialKeyRE = regexp.MustCompile(
	`(?i)"([a-z0-9_.-]+)"?\s*[:=]\s*(\\"(?:[^"\\]|\\[^"])*\\"|"(?:[^"\\]|\\[^"])*"|` + unquotedValueShape + `)`)

// credentialWords are the words a credential key ends with.
//
// ⚠️ It covers more than the upstream rules do — "authorization",
// "bearer" and "cookie" are not upstream credential words, and the
// upstream rules match neither of them inside a JSON field — so without
// these, "authorization":"Basic …" lands in the trail in the clear.
//
// ⚠️ It deliberately does NOT contain a bare "key": the compound forms
// (api_key, access_key, secret_key, private_key) are listed instead, so
// that "public_key" — a PUBLIC key, and no secret at all — is left alone.
//
// ⚠️ It must be a SUPERSET of the upstream rules' own words: the upstream
// rules mask a field whose key ends with one of theirs ("mytoken",
// "dbpassword"), and only this list can put the key's closing quote
// back. A word that is here but not there is a broken document; a word
// that is there but not here is two exits that stop agreeing.
var credentialWords = []string{
	"password", "passwd", "pwd",
	"token", "secret", "passphrase", "credential",
	"authorization", "bearer", "cookie", "kubeconfig",
	"api_key", "api-key", "apikey",
	"access_key", "access-key", "accesskey",
	"secret_key", "secret-key", "secretkey",
	"client_secret", "client-secret", "clientsecret",
	"client_key", "client-key", "clientkey",
	"private_key", "private-key", "privatekey",
	"session_token", "session-token", "sessiontoken",
	"auth_token", "auth-token", "authtoken",
	"id_token", "id-token", "idtoken",
	"refresh_token", "refresh-token", "refreshtoken",
	"token_value", "token-value",
	"secret_value", "secret-value",
	"password_value", "password-value",
	"cookie_value", "cookie-value",
	"authorization_header", "authorization-header",
}

// credentialWordPattern is the alternation of the credential words.
//
// ⚠️ It is BUILT from the list above, so the regular expressions and
// isCredentialKey cannot drift apart — and they did once: the list grew a
// word and the pattern did not, so the word was masked in one place and
// not in the other.
//
// ⚠️ It is EXPORTED as a pattern (CredentialWordPattern) because the
// management plane's answer path needs the same list **inside its own
// regular expressions**: a rule that matches ANY key and asks afterwards
// whether the key is a credential has a blind spot — the match eats the
// word in front of the credential ("login failed: password: x" ⇒ the
// key comes out as "login" ⇒ the credential is never looked at).
//
// ⇒ A pattern built from the word list matches the credential ITSELF ⇒
// the answer path's rules find it wherever it is, and the two paths
// cannot drift on WHICH words are credentials.
var credentialWordPattern = strings.Join(credentialWords, "|")

// CredentialWordPattern returns the alternation of the credential words,
// for callers that need it INSIDE a regular expression.
//
// ⚠️ It is the SAME list the trail's own patterns use (credentialWordPattern
// is built from it) ⇒ the two paths cannot drift on which words are
// credentials.
//
// ⚠️ A caller that matches a key and asks redact.IsCredentialKey
// afterwards has a blind spot: the match can eat the word in front of
// the credential ("login failed: password: x" ⇒ the key comes out as
// "login" ⇒ the credential is never looked at) ⇒ build the pattern from
// this instead.
//
// ⚠️ It is a FUNCTION, not a constant: the list is built at init time
// (the words come from a slice), and a constant cannot be built from a
// slice.
func CredentialWordPattern() string { return credentialWordPattern }

// IsCredentialKey says whether a field name says the value is a
// credential.
//
// ⚠️ It is exported because the repository's own tools have to be checked
// against it: a parameter of this repository that the scrubber mistakes
// for a credential is a parameter the trail stops recording (the trail
// exists to say WHICH session was queried, WHICH key was registered) —
// and that has bitten this repository twice.
//
// ⚠️ It is exported for a second reason: the management plane has its own
// redaction for the answers it hands back (the audit trail is not the
// only place a credential can leak into an operator's context window), and
// that one used to carry its OWN word list. Two lists drift — fourteen of
// the words here were unknown to it, so a `{"passphrase":"x"}` or a
// `{"id_token":"x"}` reached the agent in the clear.
//
// ⚠️ So the WORD LIST is shared and the SHAPES are not: the trail's
// shape is `****` (the whole field collapses) and the answer's is
// `[REDACTED]` (the key name survives, because the reader is an agent
// that has to see WHAT was run). The shape belongs to whoever reads it;
// the word list belongs to nobody in particular — it is the same fact
// ("this names a credential") either way.
//
// ⚠️ The word must END the name, and the word list must not contain a
// word that is also the tail of an innocent name: "key" is deliberately
// absent, so "monkey", "keyword" and "key_id" stay what they are.
//
// ⚠️ The PREFIX is not restricted to a separator ("my_password"), and
// that is not laxness — it is the upstream rules' own key grammar:
// theirs is `[A-Za-z0-9]*(?:[-_][A-Za-z0-9]*)*(?:token|secret|password|…)`,
// so "mytoken", "dbpassword" and "accesstoken" are credentials to THEM.
//
// ⚠️ The two rules have to agree on the KEYS, not just on the values:
// the upstream rules eat the key's closing quote when they mask such a
// field, and only the backstop can put it back. A key the backstop does
// not recognise ⇒ the structure stays broken ⇒ the second pass eats one
// more character ⇒ the registry's copy of the arguments and the trail's
// copy stop being the same string. That is the "the two exits must be
// byte for byte identical" invariant, and a key list that is not a
// superset of the upstream one breaks it.
func IsCredentialKey(key string) bool {
	lower := strings.ToLower(key)
	for _, w := range credentialWords {
		if strings.HasSuffix(lower, w) {
			return true
		}
	}
	return false
}

// isCredentialKey is the internal name of IsCredentialKey.
func isCredentialKey(key string) bool {
	return IsCredentialKey(key)
}

// escapedCredentialKeyRE matches a credential inside an ESCAPED JSON
// string — a JSON document carried as the value of another field.
//
// ⚠️ `{"params":"{\"password\":\"x\"}"}` — the key there is written
// `\"password\"`, and neither the upstream shape rules nor the plain
// backstop match it (the plain one needs the key to start with a quote
// that is not preceded by a backslash).
//
// ⚠️ It runs BEFORE the plain backstop: the plain one would match the
// inner `"password` and mask the value — but only partially, and the
// escaping around it would be left inconsistent. Masking the escaped
// pair as a whole is simpler and leaves nothing behind.
//
// ⚠️ Its unquoted value uses the SAME shape as the plain backstop's
// (unquotedValueShape): a shape that ate a quote would run into the
// next field's opening quote and swallow it with it ⇒ the field after
// the credential disappears. The plain backstop got that rule; this one
// had not.
//
// ⚠️ And its QUOTED value must not cross an escaped quote: the value
// `\"(?:[^"\\]|\\.)*\"` lets `\\.` match the `\"` that starts the NEXT
// field ⇒ the match swallowed two fields at once ⇒ and when the first
// key is not a credential word the whole match was handed back
// unchanged ⇒ the credential in the SECOND field escaped
// (`{\"username\":\"admin\",\"password\":\"secret\"}` ⇒ "secret" in the
// clear). ⇒ the value stops at the first `\"` that is not escaped.
var escapedCredentialKeyRE = regexp.MustCompile(
	`(?i)` + esc(1) + `"([a-z0-9_.-]+)` + esc(1) + `"\s*[:=]\s*(` +
		esc(1) + `"(?:[^"\\]|\\[^"])*` + esc(1) + `"|` + unquotedValueShape + `)`)

// doubleEscapedCredentialKeyRE matches a credential inside a JSON
// string that is itself inside a JSON string — the shape the trail
// actually holds.
//
// ⚠️ The SDK serialises the arguments as JSON, and a command that
// carries its own JSON arguments ("curl -d '{\"password\":\"x\"}'")
// ends up **doubly** escaped in the text that is written down:
// `{\"password\":\"x\"}` — the key is written `\"password\"` with TWO
// backslashes, not one.
//
// ⚠️ The one-level rule does not match that ⇒ the credential survived
// in the clear, and it was seen in the real trail (the args column of
// a jmsx_exec call).
//
// ⚠️ It runs AFTER the one-level rule (the one-level rule would match
// the inner pair of a doubly-escaped one and leave the outer escapes
// inconsistent).
var doubleEscapedCredentialKeyRE = regexp.MustCompile(
	`(?i)\\\\\"([a-z0-9_.-]+)\\\\\"\s*[:=]\s*(\\\\\"(?:[^"\\]|\\[^"])*\\\\"|` + unquotedValueShape + `)`)

// esc returns the escape prefix of that depth: one backslash per level.
//
// ⚠️ The depth is a NUMBER, not a written-out sequence of backslashes:
// writing them by hand is how the levels get counted wrong (the Go raw
// string keeps the backslashes, and whatever wrote the fixture may have
// doubled them) ⇒ the pattern is built from the count.
//
// ⚠️ And the depth does NOT make the levels exclusive: a pattern for two
// levels also matches the front of a three-level one ⇒ the deeper rule
// has to run FIRST (it is the more specific one).
// escLit returns the escape prefix as it appears in a REPLACEMENT.
//
// ⚠️ It is the HALF of esc(): a regular expression reads "\\" as ONE
// literal backslash, but a REPLACEMENT string does not interpret
// backslashes at all (only "$name" and "$$") ⇒ the replacement needs
// the LITERAL one backslash per level, while the pattern needs the
// ESCAPED form.
//
// ⚠️ Getting this wrong does not break the code: it just doubles the
// escaping in the output ⇒ the document stops being the document it was
// (and a JSON document stops being JSON).
func escLit(depth int) string {
	return strings.Repeat(`\`, depth)
}

// esc returns the escape prefix as it appears in a PATTERN.
//
// ⚠️ It is twice escLit(): a regular expression reads "\\" as ONE
// literal backslash ⇒ the pattern needs two characters per level.
func esc(depth int) string {
	return strings.Repeat(`\\`, depth)
}

// EscapePrefix returns the escape prefix of that depth, for callers that
// build a PATTERN for the same shape.
//
// ⚠️ It is the shared construction of the escape depth ⇒ the two paths
// cannot count the levels differently (writing "\\\"" by hand is how
// the levels get counted wrong).
func EscapePrefix(depth int) string { return esc(depth) }

// EscapeLiteral returns the escape prefix as it appears in a REPLACEMENT.
//
// ⚠️ It is the HALF of EscapePrefix: a pattern reads "\\" as one literal
// backslash, but a replacement string does not interpret backslashes at
// all ⇒ the replacement needs one literal backslash per level.
//
// ⚠️ Using EscapePrefix here would DOUBLE the escaping in the output ⇒
// the document stops being the document it was (a JSON document stops
// being JSON).
func EscapeLiteral(depth int) string { return escLit(depth) }

// unquotedValueShape is the shape of an UNQUOTED value: everything up
// to the next whitespace or structural character.
//
// ⚠️ It must NOT include the quote: the shape rules eat the key's
// closing quote when they mask a field, so the text right after such a
// field starts with a quote ⇒ a value that ran into it would swallow
// the NEXT field with it ("{"password":x"user":"bob"}" ⇒ "user"
// disappears). Both backstops use this one shape ⇒ they cannot drift.
const unquotedValueShape = `[^\s",}\]\[{}]*`

// proseCredentialRE matches a credential written as KEY=value — or KEY:
// value — in FREE TEXT: the shape a command line carries ("export
// PASSWORD=…", "mysql -uroot --password=…") and the shape a log line
// carries ("login failed: password: …").
//
// ⚠️ The separator is `=` **or** `:` because the upstream rules accept
// both: a colon-form credential ("password: S3CRET") that the upstream
// rules half-mask ("password=****&TAIL") would leave its tail in the
// clear — and this rule is the only one that sees the whole value.
//
// ⚠️ The key must not be part of a LONGER word: "monkey" and "keyword"
// are not credentials. The key is matched as a whole and judged
// separately (see isCredentialKey) — the pattern only has to FIND the
// shape, the word list decides what counts.
//
// ⚠️ The key may be preceded by a quote: `{"cmd":"password=x"}` — the
// text inside the JSON string is still free text, and it is the shape
// that leaks.
//
// ⚠️ And the JSON form is NOT matched: the key there is followed by a
// quote ("password":"x") ⇒ the separator never matches ⇒ the quoted
// forms stay the backstop's job.
//
// ⚠️ The value has FOUR forms, and they are not interchangeable:
//   - a quoted value (`"x"`, `'x'`, and the escaped `\"x\"` that a JSON
//     string carries) is masked WHOLE: the upstream rules do not match a
//     quoted value that contains a `&` at all (their value pattern stops
//     at the `&` and then insists on the closing quote ⇒ the whole rule
//     fails) ⇒ `export PASSWORD='p&ssw0rd'` would reach the trail in full;
//   - an unquoted value runs to the end of the word, and whether it stops
//     at a `&` depends on what that `&` separates (see
//     ampersandSeparates).
//
// ⚠️ The unquoted value must not swallow a quote, and it must swallow an
// ESCAPE SEQUENCE whole: it runs over JSON strings too
// ("{"cmd":"password=p&ss"}"), and eating the closing quote breaks the
// document — while cutting an escaped value in half ("&password=\"p&ss"
// ⇒ the tail behind it stayed in the clear).
//
// ⚠️ And a QUOTED value must not cross an ESCAPED quote: `\\.` would
// match the `\"` that starts the next field ⇒ the match swallowed two
// fields at once.
// ⚠️ The separator is "=" or ":" **or whitespace**: a command-line
// argument can be written "--password secret" ⇒ and the answer path
// already masks that shape ⇒ the two paths have to agree on the same
// shape (AGENTS.md: "the same word is a credential in both paths or in
// neither").
//
// ⚠️ And the key may carry the "--" of a command-line flag: the flag
// rule on the answer path owns that shape, and the two paths must not
// disagree about it.
var proseCredentialRE = regexp.MustCompile(
	`(?i)(^|[^a-z0-9_.-])((?:--)?[a-z0-9_.-]*(?:` + credentialWordPattern + `))(?:\s*[:=]\s*|[ \t]+)` +
		`("(?:[^"\\]|\\[^"])*"|\\"(?:[^"\\]|\\[^"])*\\"|'[^']*'|(?:[^"\s,}\]\\]|\\.)*)`)

// proseCredentialQuotedRE 是第二遍专用的变体：多认一个「键与分隔符之间粘着
// 引号」的形状（key" :value）。上游结构保形打码（guardx v0.18+）不再吃键的
// 收尾引号，残余正是这个形状——第一遍不该认它（良性 JSON 的键后就是引号，
// 认了会把结构打坏），只有打码之后的第二遍才该认（实测：password":p&ssw0rd
// 的尾巴漏进留痕）。
var proseCredentialQuotedRE = regexp.MustCompile(
	`(?i)(^|[^a-z0-9_.-])((?:--)?[a-z0-9_.-]*(?:` + credentialWordPattern + `))(?:"?\s*[:=]\s*|[ \t]+)` +
		`("(?:[^"\\]|\\[^"])*"|\\"(?:[^"\\]|\\[^"])*\\"|'[^']*'|(?:[^"\s,}\]\\]|\\.)*)`)

// paramNameRE matches the name of a URL parameter — the thing that
// follows a `&` when the `&` separates rather than belongs.
var paramNameRE = regexp.MustCompile(`^[a-z0-9_.-]+=`)

// maskProseCredentials masks the credentials that live in FREE TEXT.
//
// ⚠️ It runs BEFORE the upstream shape rules, and that is the whole
// point: those rules MANGLE what they mask. For a value in escaped
// quotes inside a JSON string — `{"command":"export PASSWORD=\"SECRET\""}`
// — their value pattern `[^\s&'"]+` eats the BACKSLASH (it is none of
// those characters) ⇒ they leave `"SECRET\""` standing in the clear ⇒
// the credential, in full, reaches the trail.
//
// ⚠️ And it runs AGAIN after them, for the other half of the job: the
// shape rules mask a value only up to the first `&` ⇒ what stands behind
// that `&` has to be cleaned up by somebody, and that somebody is this
// rule.
//
// ⚠️ The masked value has the SAME SHAPE as the one the upstream rules
// leave behind (`KEY=****`), quotes and all. Keeping the quotes would
// look nicer — and would break the combination: the upstream rules eat
// the quotes on the second pass, so the two exits (the registry's and
// the trail's) would stop agreeing.
//
// ⚠️ It walks the matches by hand rather than with ReplaceAllStringFunc:
// the `&` can only be told apart by the CONTEXT IN FRONT of it (a `?`
// means a query string), and the callback of ReplaceAllStringFunc does
// not get to see where the match was.
//
// ⚠️ The context is the text IN FRONT OF THE WHOLE SCAN, not of the
// current match: the tail after an `&` is scanned again by the recursion
// (below), and that recursion must judge the same `&` the same way the
// outer pass did ⇒ it needs the outer text, not just its own slice.
func maskProseCredentials(text string) string {
	return maskProseCredentialsIn(text, "")
}

// maskProseCredentialsAgain 是第二遍：用认「引号粘键」的变体收上游打码留下
// 的残余尾巴（见 proseCredentialQuotedRE 的注释）。
func maskProseCredentialsAgain(text string) string {
	return maskProseCredentialsInRE(text, "", proseCredentialQuotedRE)
}

// maskProseCredentialsIn is maskProseCredentials with the text in front
// of it.
//
// ⚠️ `before` is what tells a query string from a command line, and the
// recursion into a tail needs it: without it the recursion sees only
// the tail ("&user=bob") and cannot tell a query string from a
// credential ⇒ the SAME `&` gets two different answers in the two
// passes ⇒ the trail loses the text behind it.
func maskProseCredentialsIn(text, before string) string {
	return maskProseCredentialsInRE(text, before, proseCredentialRE)
}

func maskProseCredentialsInRE(text, before string, re *regexp.Regexp) string {
	matches := re.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		key := text[m[4]:m[5]]
		value := text[m[6]:m[7]]
		if !isCredentialKey(key) || value == "" || isBooleanLiteral(value) {
			continue
		}
		b.WriteString(text[last:m[0]])
		b.WriteString(text[m[0]:m[3]]) // the prefix the match consumed
		// ⚠️ The context is the text in front of the VALUE, in the
		// ORIGINAL string: it is what says whether the `&` inside the
		// value separates two URL parameters or is part of the
		// credential ⇒ the answer has to be looked up in the text as it
		// was, not in the text as it is being rebuilt.
		b.WriteString(maskProseValue(before+text[:m[6]], key, value))
		last = m[1]
	}
	b.WriteString(text[last:])
	return b.String()
}

// maskProseValue masks one free-text credential and says what it leaves
// behind.
//
// prefix is the text in front of the VALUE, in the original string —
// the only thing that tells a query string from a command line.
func maskProseValue(prefix, key, value string) string {
	// ⚠️ A quoted value is masked WHOLE — the `&` inside it is part of
	// the credential, not a separator.
	if value[0] == '"' || value[0] == '\'' || strings.HasPrefix(value, `\"`) {
		return key + "=****"
	}
	// ⚠️ An unquoted value stops at a `&` that separates: the rest of
	// a URL ("?token=abc&user=bob") and the rest of a command
	// ("export PASSWORD=x&./run.sh") have to stay readable — the trail
	// exists to record WHAT was run.
	//
	// ⚠️ And the tail is scrubbed AGAIN: it was inside the value this
	// match consumed, so the outer pass will never look at it — and
	// "?token=abc&password=hunter2" has a SECOND credential in it.
	//
	// ⚠️ The context goes WITH it: the recursion judges the same `&`
	// against the same "?" ⇒ the two passes cannot disagree.
	if i := strings.Index(value, "&"); i >= 0 && ampersandSeparates(value[i+1:], prefix+value[:i]) {
		return key + "=****" + maskProseCredentialsIn(value[i:], prefix+value[:i])
	}
	return key + "=****"
}

// ampersandSeparates says whether the `&` is a SEPARATOR (a shell
// operator or a URL parameter separator) rather than part of the value.
//
// ⚠️ The two are told apart by what FOLLOWS the `&` AND by what came
// before it:
//
//   - a shell operator or a path ("&&", "& ", "&./run.sh") ⇒ a separator,
//     wherever it is;
//   - a parameter name ("&user=bob") ⇒ a separator **only in a query
//     string** — the `?` in front of it is the only thing that tells
//     "?token=abc&user=bob" (two parameters) from "PASSWORD=AAA&bbb=1"
//     (one credential that happens to contain an `&`).
//
// ⚠️ The rule is a judgement call, and it is deliberately the SAFE side
// when it cannot tell: an `&` that is not known to separate is treated
// as part of the value, so the credential is masked WHOLE rather than
// half — a tail left in the clear is a credential in the clear.
func ampersandSeparates(rest, before string) bool {
	if rest == "" {
		return true
	}
	switch rest[0] {
	case '&', ' ', '\t', '\n', '/', '.', ';', '|', '>', '<':
		return true
	}
	// ⚠️ A parameter name is a separator ONLY in a query string: the `&`
	// of "PASSWORD=AAA&bbb=1" is part of the credential, and the `?` in
	// front of the query is the only thing that tells the two apart.
	if !paramNameRE.MatchString(rest) {
		return false
	}
	return InQueryString(before)
}

// InQueryString says whether the text in front of the match ends with
// the query string the `&` belongs to.
//
// ⚠️ It must be the SAME query string, not "there is a `?` somewhere in
// the text": a `?` in an earlier sentence ("did it work? PASSWORD=AAA&bbb=1")
// says nothing about the `&` that follows the credential — and reading
// it as if it did leaves the credential's tail in the clear.
//
// ⚠️ So the `?` has to be the one that OPENS this query string: the text
// between it and the match must be a query string's own characters —
// no whitespace, no quote. A space ends the query string (a URL does
// not contain spaces), and a quote ends it too (it ends the argument
// the URL was written in).
//
// ⚠️ Only the LAST `?` counts: an earlier one belongs to an earlier
// query string.
//
// ⚠️ When it cannot tell, it says NO ⇒ the `&` is part of the credential
// ⇒ the credential is masked WHOLE. A tail left in the clear is a
// credential in the clear.
//
// The answer path shares this boundary decision (it masks its own shape,
// but where an `&` BELONGS is not a shape): a second copy of the
// question is a second place where an earlier "?" can open the gate.
func InQueryString(before string) bool {
	i := strings.LastIndex(before, "?")
	if i < 0 {
		return false
	}
	tail := before[i+1:]
	return !strings.ContainsAny(tail, " \t\r\n\"'`")
}

// maskCredentialKeys masks the value of every field whose NAME says it is
// a credential, when the upstream rules did not already mask it whole.
//
// ⚠️ It replaces the WHOLE value, not just the matched part — that is the
// point: the upstream rules can only mask a fragment, and a fragment is
// not enough when the credential contains a quote.
//
// ⚠️ It only touches fields whose name says "credential", so an ordinary
// field (and a command) is left exactly as it was.
//
// ⚠️ A BOOLEAN value is not masked. `{"has_password":true}` is a FLAG —
// it says the account HAS a password, it is not one — and masking it
// would turn a fact into a string and lose the distinction. (The shape
// rules alone get this wrong: they turn it into `"****"`.) A number or a
// string IS masked: `{"password":123}` is a credential like any other.
func maskCredentialKeys(text string) string {
	// ⚠️ The replacement keeps ONE backslash before each quote — the
	// same shape the match had. It used to write TWO, and that is not a
	// cosmetic difference: the escaped document is a JSON STRING's
	// value, so `\\"` is an escaped backslash followed by a quote that
	// CLOSES the string ⇒ the document stops being JSON at all.
	//
	// ⚠️ And the masked value has the same shape as the plain rule's
	// (`"key":"****"`): the two rules have to agree, or the same
	// credential looks different in two exits.
	// ⚠️ The DOUBLE-escaped form runs AFTER the single one: the single
	// rule would match the inner pair of a doubly-escaped document and
	// leave the outer escapes inconsistent.
	text = doubleEscapedCredentialKeyRE.ReplaceAllStringFunc(text, func(m string) string {
		sub := doubleEscapedCredentialKeyRE.FindStringSubmatch(m)
		if sub == nil || !isCredentialKey(sub[1]) {
			return m
		}
		// ⚠️ The replacement keeps the SAME number of backslashes the
		// match had: one less and the document stops being JSON.
		return escLit(2) + `"` + sub[1] + escLit(2) + `":` + escLit(2) + `"****` + escLit(2) + `"`
	})
	text = escapedCredentialKeyRE.ReplaceAllStringFunc(text, func(m string) string {
		sub := escapedCredentialKeyRE.FindStringSubmatch(m)
		if sub == nil || !isCredentialKey(sub[1]) {
			return m
		}
		return `\"` + sub[1] + `\":\"****\"`
	})
	return credentialKeyRE.ReplaceAllStringFunc(text, func(m string) string {
		sub := credentialKeyRE.FindStringSubmatch(m)
		if sub == nil || !isCredentialKey(sub[1]) {
			return m
		}
		if isBooleanLiteral(sub[2]) {
			return m
		}
		// ⚠️ The key may have been escaped (`\"password\"` inside a
		// JSON string): the backslash belongs to the JSON, not to the
		// name, so it is kept.
		prefix := ""
		if strings.HasPrefix(m, `\`) {
			prefix = `\`
		}
		return prefix + `"` + sub[1] + `":"****"`
	})
}

// isBooleanLiteral says whether a matched value is a JSON boolean.
//
// ⚠️ The comparison is case-insensitive, and it has to be: the pattern
// that finds the value is case-insensitive too (`(?i)`), so it matches
// "TRUE" and "Null" as readily as "true" and "null" ⇒ a case-sensitive
// comparison here would read "TRUE" as a CREDENTIAL and mask it ⇒ the
// flag "this account has a password" would turn into a string.
func isBooleanLiteral(v string) bool {
	return strings.EqualFold(v, "true") || strings.EqualFold(v, "false")
}

// isNullLiteral says whether a matched value is the JSON null.
//
// ⚠️ Same case-insensitivity as the boolean, for the same reason.
func isNullLiteral(v string) bool {
	return strings.EqualFold(v, "null")
}

// scrubbedMarker matches the marker this package leaves behind.
var scrubbedMarker = regexp.MustCompile(`^<\d+ bytes scrubbed>$`)

// alreadyScrubbed says whether a value is this package's own marker.
//
// It is what makes Payloads idempotent: a marker is left exactly as it is,
// so the second pass measures nothing and changes nothing.
func alreadyScrubbed(s string) bool {
	return scrubbedMarker.MatchString(s)
}

// marshalNoEscape marshals without Go's HTML escaping.
//
// The trail is read by people; "\u003c40 bytes scrubbed\u003e" is the
// same fact with the reading part taken away.
func marshalNoEscape(v any) (string, error) {
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return strings.TrimRight(buf.String(), "\n"), nil
}

// scrubPayloads replaces the payload fields inside a decoded value with
// their size, and says whether it changed anything.
func scrubPayloads(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		for k, val := range t {
			if payloadFields[k] {
				if str, ok := val.(string); ok {
					// ⚠️ A value that is already this package's marker
					// is left exactly as it is — otherwise the second
					// pass would report the size of the marker as the
					// size of the payload.
					if alreadyScrubbed(str) {
						continue
					}
					t[k] = fmt.Sprintf("<%d bytes scrubbed>", len(str))
					changed = true
					continue
				}
				if val == nil {
					continue
				}
				raw, err := json.Marshal(val)
				if err != nil {
					continue
				}
				t[k] = fmt.Sprintf("<%d bytes scrubbed>", len(raw))
				changed = true
				continue
			}
			if scrubPayloads(val) {
				changed = true
			}
		}
		return changed
	case []any:
		changed := false
		for _, val := range t {
			if scrubPayloads(val) {
				changed = true
			}
		}
		return changed
	}
	return false
}
