package jmsapi

// The second way in: a LOGIN instead of a PrivateToken.
//
// Why this exists. The PrivateToken is the credential this repository was
// built around, and it works on BOTH versions — v4's authentication package
// registers PrivateTokenAuthentication, which is DRF's TokenAuthentication
// with model=PrivateToken, so "Authorization: Token <key>" means the same
// thing on v4 and on v5. On a deployment where an operator can mint a
// PrivateToken, nothing here is needed.
//
// But a PrivateToken is created in the admin UI, and a deployment that only
// ever hands out account passwords cannot produce one. For those, the bastion
// accepts a username and a password and exchanges them for a Bearer token:
// POST /api/v1/authentication/auth/ returns {"token": ...}, and the REST API
// then answers "Authorization: Bearer <token>". The same endpoint exists on
// v4 and on v5 — v4's apps/authentication/urls/api_urls.py registers
// path('auth/', api.TokenCreateApi) and v5's registers the same one — so this
// mode is NOT a version thing. It is a CREDENTIAL thing, and it is kept apart
// from the version for that reason.
//
// The lifetime is the awkward part. The PrivateToken does not expire; the
// Bearer token does — v4's BearerTokenSerializer carries a date_expired, and
// a long-running MCP process would outlive it. So the token is remembered
// until it is about to expire, and a request that comes back 401 refreshes it
// once and repeats.
//
// Repeating a request after a 401 is safe, and the reason matters: a 401 is
// the AUTHENTICATION LAYER refusing the request, so the request never reached
// the handler and was never applied. That is the same reasoning the retry
// policy already uses for a rate limit ("the server never saw it"). A request
// that was APPLIED and then failed would be a different thing, and it is not
// what a 401 is.
//
// Two MFA shapes exist and both are answered here: v4's TokenCreateApi
// answers a login that needs a second factor with 200 and the challenge in
// the body (NeedMoreInfoError), and the same endpoint on v5 answers the same
// way. The challenge is then verified with POST
// /api/v1/authentication/mfa/challenge/ and {"type": "otp", "code": ...}, and
// the login is repeated.
//
// ⚠️ **The challenge is answered by the bastion's DJANGO SESSION, not by the
// credential.** Checked against the upstream v4.10.20-lts source:
//
//	apps/authentication/api/mfa.py  MFAChallengeVerifyApi.initial()
//	    user = self.get_user_from_session()
//	    ... except SessionEmptyError: user = None
//	    if not user: raise exceptions.NotAuthenticated()
//
// and get_user_from_session reads `user_id` / `auth_password` / `auth_mfa`
// out of request.session — the login step is what puts them there
// (AuthMixin.mark_password_ok / mark_mfa_ok). ⇒ **the session cookie has to
// survive from the login to the challenge**, or the challenge answers 401 and
// the flow cannot finish.
//
// ⇒ That is why the login path has a client of its own, WITH a cookie jar,
// and the ordinary client has none: a request carrying a valid session
// cookie is authenticated AS THE SESSION USER by Django's session backend,
// which is the wrong identity for a call that is supposed to act as the token
// owner. The two paths must not share cookies.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/yi-nology/jumpserver-kit/pkg/errs"
)

// Credential is the material a client needs when it authenticates with a LOGIN
// rather than with a PrivateToken.
type Credential struct {
	// Username is the bastion account.
	Username string
	// Password is that account's password.
	Password string
	// OTP is the base32 TOTP secret, used when the deployment demands MFA.
	// It is optional: a deployment without MFA never asks for it, and one
	// with MFA says so plainly when it is missing.
	OTP string
}

// Configured reports whether there is enough material to log in.
func (c Credential) Configured() bool {
	return strings.TrimSpace(c.Username) != "" && c.Password != ""
}

// The login endpoints. They are here rather than in the endpoint table
// because they are the two endpoints a client calls BEFORE it has any
// credential — and the table is the table of resources.
const (
	// ResAuthLogin exchanges a username and a password for a Bearer token.
	ResAuthLogin Resource = "/authentication/auth/"
	// ResMFAChallenge verifies a second factor.
	ResMFAChallenge Resource = "/authentication/mfa/challenge/"
	// ResChatAI is the runtime store of the Chat AI application — the API
	// prefix v5 has and v4 does not. Its presence is what tells the two
	// apart; see version.go.
	ResChatAI Resource = "/chat-ai/runtime-store/"

	// ResProbeMissing is a route that exists on NO deployment.
	//
	// ⚠️ It is the second half of the version probe, and it exists because
	// a single path is not enough: v4's "no such route" handler is broken
	// and answers 500, so on v4 EVERY unknown path looks the same. ⇒ The
	// probe compares the chat-ai route's answer with THIS one's: the same
	// answer means the chat-ai route is not there either.
	//
	// ⚠️ The name is deliberately un-guessable: a route that a future
	// JumpServer release might add would turn the probe into a liar, and
	// the whole comparison would invert.
	ResProbeMissing Resource = "/zzz-jms-version-probe-404/"
)

// bearerRefreshMargin is how long before the stated expiry a token is
// considered stale.
//
// The expiry is the server's, and a request that crosses it is a 401 — which
// is recoverable, but only after a wasted round trip. Half a minute of margin
// is enough to cross it in time.
const bearerRefreshMargin = 30 * time.Second

// bearer is the cached Bearer token and its expiry.
type bearerToken struct {
	value  string
	expiry time.Time
}

// login performs the username/password exchange and returns the Bearer token.
//
// It does NOT go through Do: Do asks the client for its credential, and the
// credential is what this function is fetching. A login that authenticated with
// a credential would be a circle.
func (c *Client) login(ctx context.Context) (bearerToken, error) {
	body, err := json.Marshal(map[string]string{
		"username": c.Credential.Username,
		"password": c.Credential.Password,
	})
	if err != nil {
		return bearerToken{}, err
	}
	raw, err := c.postForm(ctx, string(ResAuthLogin), body)
	if err != nil {
		return bearerToken{}, err
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return bearerToken{}, fmt.Errorf("the login response was not JSON: %s", Truncate(string(raw), 200))
	}

	// The challenge comes back as a SUCCESS with a body that asks for a code
	// — not as a 401 — so the token has to be looked for, and its absence is
	// what says "a second factor is needed".
	if tok := Str(payload["token"]); tok != "" {
		return bearerToken{value: tok, expiry: bearerExpiry(payload)}, nil
	}
	if !mfaRequired(payload) {
		return bearerToken{}, fmt.Errorf("the login returned no token: %s", loginMessage(payload))
	}
	if err := c.challengeMFA(ctx); err != nil {
		return bearerToken{}, err
	}
	// The challenge is spent; the login has to be repeated.
	raw, err = c.postForm(ctx, string(ResAuthLogin), body)
	if err != nil {
		return bearerToken{}, err
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return bearerToken{}, fmt.Errorf("the login response after MFA was not JSON: %s", Truncate(string(raw), 200))
	}
	tok := Str(payload["token"])
	if tok == "" {
		return bearerToken{}, fmt.Errorf("the login after MFA returned no token: %s", loginMessage(payload))
	}
	return bearerToken{value: tok, expiry: bearerExpiry(payload)}, nil
}

// challengeMFA verifies the configured second factor.
func (c *Client) challengeMFA(ctx context.Context) error {
	secret := strings.TrimSpace(c.Credential.OTP)
	if secret == "" {
		return fmt.Errorf("the deployment asks for a second factor (MFA) and no TOTP secret is configured; "+
			"set JUMPSERVER_OTP or write the base32 secret to one of %s", strings.Join(OTPSecretFiles(), ", "))
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return fmt.Errorf("the configured TOTP secret is not a valid base32 secret: %w", err)
	}
	body, err := json.Marshal(map[string]string{"type": "otp", "code": code})
	if err != nil {
		return err
	}
	if _, err := c.postForm(ctx, string(ResMFAChallenge), body); err != nil {
		return fmt.Errorf("the MFA challenge was refused: %w", err)
	}
	return nil
}

// postForm sends one unauthenticated JSON POST to the bastion.
//
// It is deliberately separate from Do: the login endpoints are the only ones
// a client calls without a credential, and routing them through the
// credential-carrying path would ask for a credential to get a credential.
//
// It also uses the SESSION client, which is the one that carries the cookie
// jar: the MFA challenge is answered by the bastion's Django session, so the
// cookie the login set has to come along.
//
// Every error it returns is a CREDENTIAL error — the credential could not be
// obtained — and not a failed API call. The difference decides what happens
// next: a failed API call with a Bearer token may be a stale token (refresh
// and repeat), while a failed LOGIN is not something repeating fixes, and
// treating it as one would run the whole login and challenge again.
func (c *Client) postForm(ctx context.Context, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.apiURL(path), bytes.NewReader(body))
	if err != nil {
		return nil, &CredentialError{Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.sessionHTTP.Do(req)
	if err != nil {
		return nil, &CredentialError{Err: fmt.Errorf("call POST %s: %w", path, err)}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, &CredentialError{Err: err}
	}
	if resp.StatusCode >= 400 {
		return nil, &CredentialError{Err: &errs.APIError{
			Status: resp.StatusCode,
			Method: "POST",
			Path:   path,
			Body:   Truncate(string(raw), 400),
		}}
	}
	return raw, nil
}

// CredentialError is a failure to OBTAIN the credential, not a failure of a
// call made with it.
//
// The distinction decides what the caller does with it. A call that came back
// 401 may be carrying a stale Bearer token, and that is worth one refresh and
// one repeat. A LOGIN that came back 401 is the credential itself being
// refused, and repeating it would run the login and the MFA challenge a
// second time — twice the requests, and the error the caller finally sees is
// the second failure's, which hides the first one's cause.
type CredentialError struct {
	Err error
}

func (e *CredentialError) Error() string { return e.Err.Error() }

// Unwrap keeps the inner error in the chain.
func (e *CredentialError) Unwrap() error { return e.Err }

// authorization returns the Authorization header value for one request.
//
// Two forms, and the choice is the credential's, not the version's:
//
//   - a PrivateToken -> "Token <key>", which never expires;
//   - a login       -> "Bearer <token>", which does, and is refreshed.
//
// ⚠️ The Bearer token is NOT a JWT: upstream mints an opaque
// random_string(36) and keeps it in the Django cache (v4's
// apps/users/models/user/_token.py, create_bearer_token). It is a token in
// the "opaque handle" sense, and calling it a JWT would send anyone reading
// the code looking for claims that are not there.
func (c *Client) authorization(ctx context.Context) (string, error) {
	if c.Token != "" {
		return "Token " + c.Token, nil
	}
	if !c.Credential.Configured() {
		// No credential at all. The client is still usable for the
		// catalogue and for the tests, and the call that needs a
		// credential fails with the server's own answer rather than with
		// a locally invented one.
		return "", nil
	}
	tok, err := c.bearer(ctx)
	if err != nil {
		return "", err
	}
	return "Bearer " + tok, nil
}

// bearer returns the current Bearer token, logging in when there is none or
// when the remembered one is about to expire.
func (c *Client) bearer(ctx context.Context) (string, error) {
	c.bearerMu.Lock()
	defer c.bearerMu.Unlock()
	if c.bearerToken.value != "" &&
		(c.bearerToken.expiry.IsZero() || time.Now().Add(bearerRefreshMargin).Before(c.bearerToken.expiry)) {
		return c.bearerToken.value, nil
	}
	tok, err := c.login(ctx)
	if err != nil {
		return "", err
	}
	c.bearerToken = tok
	return tok.value, nil
}

// invalidateBearer forgets the remembered token, so the next call logs in
// again.
//
// It is called after a 401: the token was refused, and the only way to know
// whether it expired or was revoked is to ask for a new one.
func (c *Client) invalidateBearer() {
	c.bearerMu.Lock()
	defer c.bearerMu.Unlock()
	c.bearerToken = bearerToken{}
}

// bearerExpiry reads the expiry the server stated.
//
// A response without one leaves the expiry unset, and an unset expiry means
// "do not refresh on a timer" — the 401 path is then the only thing that
// refreshes it, which is the right behaviour for a token whose lifetime the
// server did not state.
func bearerExpiry(payload map[string]any) time.Time {
	raw := strings.TrimSpace(Str(payload["date_expired"]))
	if raw == "" {
		return time.Time{}
	}
	// ⚠️ The layouts are not interchangeable between versions, and the
	// one that matters was measured: v4 answers "2026/10/31 23:53:34 +0800"
	// (a slash-separated date and a numeric offset), not RFC3339.
	// ⇒ A layout that does not match leaves the expiry UNKNOWN, and an
	// unknown expiry means the token is never refreshed on a timer — only
	// on the 401 path. That still works, but it wastes a round trip.
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05Z0700",
		"2006/01/02 15:04:05 -0700",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t
		}
	}
	return time.Time{}
}

// mfaRequired reports whether a login response asks for a second factor.
//
// The body is SEARCHED rather than read from one key, because the API does
// not promise which key carries the answer — but ⚠️ it is NOT because the
// key changed between versions: both v4 and v5 answer with
// NeedMoreInfoError's data, whose shape is {"error": ..., "msg": ...}, and
// "mfa_required" lands in `error` in BOTH (checked against the upstream
// v4.10.20-lts and dev sources: apps/authentication/errors/redirect.py is
// byte-identical on the two).
//
// What matters is that the response carries NO token: a response with a
// token is a login that succeeded, whatever else is in it.
func mfaRequired(payload map[string]any) bool {
	if payload == nil {
		return false
	}
	if Str(payload["token"]) != "" {
		return false
	}
	for _, key := range []string{"code", "error", "msg", "detail", "message", "reason"} {
		s := strings.ToLower(Str(payload[key]))
		if strings.Contains(s, "mfa") {
			return true
		}
	}
	return false
}

// loginMessage extracts the human-readable part of a login failure.
func loginMessage(payload map[string]any) string {
	for _, key := range []string{"detail", "msg", "error", "code", "message"} {
		if s := Str(payload[key]); s != "" {
			return s
		}
	}
	encoded, _ := json.Marshal(payload)
	return Truncate(string(encoded), 200)
}

// LoadPassword resolves the login password.
//
// The order is: the environment variable, then a 0600 file. The file is the
// recommended home for a password — the environment of a long-running process
// is readable by anything that can read /proc on Linux, and an MCP server is
// started by an agent runtime whose environment is not a secret store.
func LoadPassword() (string, error) {
	if v := strings.TrimSpace(os.Getenv("JUMPSERVER_PASSWORD")); v != "" {
		return v, nil
	}
	for _, p := range PasswordFiles() {
		b, err := os.ReadFile(p)
		if err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no password found: set JUMPSERVER_PASSWORD, or write it to one of %s (mode 0600)",
		strings.Join(PasswordFiles(), ", "))
}

// LoadOTPSecret resolves the TOTP secret, the same way the password is
// resolved.
func LoadOTPSecret() (string, error) {
	if v := strings.TrimSpace(os.Getenv("JUMPSERVER_OTP")); v != "" {
		return v, nil
	}
	for _, p := range OTPSecretFiles() {
		b, err := os.ReadFile(p)
		if err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("no TOTP secret found: set JUMPSERVER_OTP, or write the base32 secret to one of %s (mode 0600)",
		strings.Join(OTPSecretFiles(), ", "))
}

// PasswordFiles lists where the password may live.
//
// The list is derived, not hard-coded in one place, so the two planes look in
// the SAME places: a password that one of them can find and the other cannot
// is a deployment that works for half the tools and fails for the other half.
func PasswordFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".config", "jumpserver-mgmt", "password"),
		filepath.Join(home, ".local", "etc", "jumpserver-mgmt", "password"),
	}
}

// OTPSecretFiles lists where the TOTP secret may live.
func OTPSecretFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".config", "jumpserver-mgmt", "otp"),
		filepath.Join(home, ".local", "etc", "jumpserver-mgmt", "otp"),
	}
}
