// Package jmsapi is the JumpServer REST protocol layer.
//
// It speaks to v4 and v5 alike. That is not an aspiration: the endpoint table
// (api.go), the authentication header, the connection-token body and the
// response shapes are the same on both versions, and version.go records the
// evidence — read from the upstream v4.10.20-lts source, not from a wiki.
//
// Why it lives in the kit.
//
// Both MCP servers talk to the same bastion, with the same credential, over
// the same wire format. While each server carried its own client, the two
// drifted, and the drift was not theoretical: the management plane's Truncate
// cuts on a rune boundary, because a byte slice can slice a multi-byte
// character in half and emit invalid UTF-8 into a JSON result; the execution
// plane's Truncate still cut on a byte boundary, because it was a copy of the
// older one. The same known bug, fixed on one side only.
//
// So the protocol now has exactly one home. What belongs here is the WIRE:
// the transport, the authentication shape, the two list shapes the API mixes,
// the labelled-choice fields, the retry policy, the pagination convention.
//
// What does not belong here is MEANING. "Does this permission actually let
// anybody in" is a rule about the bastion's data model, not about its
// transport, so it stays in the management plane's repository. Keeping the
// line here is what stops this package from turning into a second business
// layer: it knows how to ask and how to read the answer, never what the answer
// means.
//
// The layer takes primitives rather than a configuration struct, so no
// server's conf package can leak into it and no server can drift from it.
package jmsapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oekit/concurrency/ratelimit"
	"github.com/oekit/concurrency/retry"
	"golang.org/x/time/rate"

	"github.com/yi-nology/jumpserver-mcp-kit/pkg/errs"
)

// Options configures a Client.
//
// The fields are primitives on purpose: this package is shared by two servers
// that read their configuration differently, and a configuration struct here
// would tie the protocol to one of them.
type Options struct {
	// BaseURL is the root of the JumpServer deployment, without a trailing
	// slash and without /api/v1 (the client appends that itself).
	BaseURL string

	// Token is the JumpServer PrivateToken, presented as
	//
	//	Authorization: Token <key>
	//
	// v5 removed the classic AccessKey/Bearer authentication class, and the
	// OAuth tokens from POST /api/v1/authentication/tokens/ expire after 24h,
	// which makes them useless for a long-running MCP process.
	//
	// ⚠️ It is NOT a v5-only credential: v4 registers
	// PrivateTokenAuthentication too, which is DRF's TokenAuthentication
	// with model=PrivateToken — so the same header means the same thing on
	// both versions, and a deployment that can mint a PrivateToken needs no
	// other credential form at all.
	Token string

	// Credential is the LOGIN material, used when Token is empty.
	//
	// It is a separate form because it expires: the PrivateToken does not,
	// the Bearer token does. See auth.go.
	Credential Credential

	// Version says which JumpServer generation the deployment runs: "v4",
	// "v5", or "auto" to detect it at the first call that needs the answer.
	//
	// ⚠️ It is not a feature switch. Between v4 and v5 the endpoint table,
	// the authentication header, the connection-token body and the response
	// shapes are the SAME — what differs is that v4 has no Chat AI
	// delegation scheme. See version.go for the evidence.
	Version string

	// Timeout bounds a single API call. Zero means no client-side bound.
	Timeout time.Duration

	// HTTPClient replaces the client used for the calls. A nil one means a
	// client with the given Timeout. It exists for the callers that bring
	// their own transport — a test server's client, say.
	HTTPClient *http.Client

	// RequestsPerSecond caps how fast the client calls the bastion. The
	// bastion is a monolith; a runaway agent does not need to find that out
	// the hard way. Zero disables the limiter.
	RequestsPerSecond float64

	// Burst is the allowance for a call that legitimately needs several
	// requests at once (a list plus its details).
	Burst int
}

// Client talks to the JumpServer REST API.
//
// It is the protocol layer: it knows the endpoints' shapes, not their
// meaning. A caller that wants to know what a permission grants asks the
// management plane's repository, not this package.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client

	// Credential is the login material, used when Token is empty.
	Credential Credential

	// versionSetting is the CONFIGURED version ("" / "auto" = detect it). It
	// is kept apart from the resolved one because "the operator said v4" and
	// "we worked out that it is v4" are different facts, and the doctor
	// reports them differently.
	versionSetting string

	// profile is what the deployment HAS, and profileMu guards it. It is
	// resolved once — see Profile. A failed detection is remembered as an
	// UNKNOWN profile rather than as a guess (see Profile.MayPresent for why
	// the guess errs the way it does).
	profileMu       sync.Mutex
	profile         Profile
	profileResolved bool
	versionErr      error
	// profileFailedAt is when the last detection failed, so the failure is
	// remembered for a window rather than for ever. See profileFailureTTL.
	profileFailedAt time.Time

	// detectMu guards the remembered detection, which is kept apart from
	// the profile so the doctor can report what the deployment looks like
	// even when the setting says something else.
	detectMu sync.Mutex
	detected Version

	// bearerMu guards the remembered Bearer token and bearerToken itself.
	// The token belongs to one deployment, so the lock belongs to the
	// client rather than to the package.
	bearerMu    sync.Mutex
	bearerToken bearerToken

	// sessionHTTP is the client the LOGIN path uses, and sessionJar is the
	// cookie jar it carries.
	//
	// They are separate from HTTP on purpose, and not merely for
	// convenience: the MFA challenge is answered by the bastion's Django
	// SESSION, so the cookie the login sets has to come along — but a
	// request carrying a valid session cookie is authenticated AS THE
	// SESSION USER by Django's session backend, which is the wrong
	// identity for a call that is supposed to act as the token owner.
	// ⇒ The two paths must not share cookies, so the ordinary client has
	// no jar at all.
	sessionHTTP *http.Client
	sessionJar  http.CookieJar

	// limiter keeps a runaway caller from hammering the bastion.
	limiter *ratelimit.TokenBucket
}

// New builds a client.
//
// The token is not required here: the client is also built for the commands
// that only need the catalogue, and for the tests. What a missing token
// breaks is the API calls, not the construction.
func New(opts Options) *Client {
	c := &Client{
		BaseURL:        strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/"),
		Token:          opts.Token,
		Credential:     opts.Credential,
		versionSetting: strings.TrimSpace(opts.Version),
		HTTP: &http.Client{
			Timeout:       opts.Timeout,
			Transport:     directTransport(),
			CheckRedirect: noRedirect,
		},
	}
	if opts.HTTPClient != nil {
		c.HTTP = opts.HTTPClient
	}
	// The login path gets a client of its own, with a cookie jar: the MFA
	// challenge is answered by the bastion's Django session, so the cookie
	// has to survive from the login to the challenge. The jar must NOT be on
	// the ordinary client — see the field's comment.
	jar, _ := cookiejar.New(nil)
	c.sessionJar = jar
	c.sessionHTTP = &http.Client{
		Timeout:       opts.Timeout,
		Transport:     directTransport(),
		CheckRedirect: noRedirect,
		Jar:           jar,
	}
	if opts.HTTPClient != nil {
		// The caller's client is honoured for the TRANSPORT (a test
		// server's client, say) and for the timeout; the jar is ours.
		if opts.HTTPClient.Transport != nil {
			c.sessionHTTP.Transport = opts.HTTPClient.Transport
		}
		if opts.HTTPClient.Timeout > 0 {
			c.sessionHTTP.Timeout = opts.HTTPClient.Timeout
		}
	}
	if opts.RequestsPerSecond > 0 {
		burst := opts.Burst
		if burst <= 0 {
			burst = 1
		}
		c.limiter = ratelimit.NewTokenBucket(rate.Limit(opts.RequestsPerSecond), burst)
	}
	return c
}

// noRedirect refuses to follow a redirect.
//
// ⚠️ Why it matters: the version probe asks "is this path a registered
// route", and the answer it reads is 404-or-not. A redirect to the login
// page answers 200 — which the probe would read as "the route is there",
// i.e. as v5. On a v4 deployment that is a false positive: the delegation
// credential gets presented, comes back 401, and every session walks the
// slow terminal path.
//
// The bastion's API does not redirect, so refusing costs nothing.
func noRedirect(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}

// directTransport is the transport the bastion is reached through.
//
// It deliberately does NOT use the environment's HTTP proxy. The bastion is on
// a private network, and every request carries a long-lived API token:
// sending that through whatever proxy happens to be configured in the
// environment is wrong twice over — a private address does not belong on a
// public proxy, and a proxy that happens to be down (or pointed somewhere
// else) takes the whole service with it.
//
// The default transport's settings are kept; only the proxy is dropped.
func directTransport() *http.Transport {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{Proxy: nil}
	}
	c := t.Clone()
	c.Proxy = nil
	return c
}

// Do performs an authenticated API call. `out` may be nil to discard the body.
//
// A failure is classified (see pkg/errs) so the caller can tell a rate limit
// from a permission problem from a transient hiccup — and only the failures
// that are safe to repeat are retried. "Worth retrying" and "safe to resend"
// are two different questions: a timeout is worth another try, but the server
// may well have applied the request the first time, so repeating it blindly
// could apply a side effect twice. A read may always be repeated; a write
// only when the server never saw it (a rate limit).
func (c *Client) Do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	return retry.Do(ctx, retry.Config{
		Attempts:    3,
		Delay:       200 * time.Millisecond,
		Exponential: true,
		MaxDelay:    2 * time.Second,
		// Proportional jitter: a fixed jitter is negligible in the later
		// exponential rounds, which is exactly when a retry storm forms.
		JitterRatio: 0.25,
		Retryable:   func(err error) bool { return c.retryable(method, err) },
		// The bastion's own advice beats our backoff when it gives one.
		DelayHint: errs.RetryAfter,
	}, func(attempt int) error {
		return c.attempt(ctx, method, path, query, body, out)
	})
}

// attempt performs one call, refreshing an expired Bearer token once.
//
// The refresh is safe to repeat the request — but only for a READ, and only
// when the failure was the CREDENTIAL being stale:
//
//   - a 401 is usually the authentication layer refusing the request, so it
//     never reached the handler and was never applied. That is the same
//     reasoning the retry policy uses for a rate limit ("the server never
//     saw it"). ⚠️ But upstream also answers 401 from VIEWS (a session that
//     is no longer active, a command that was never accepted), and those are
//     indistinguishable from the authentication layer's refusal. Today they
//     are all validation branches with no side effect, so repeating is
//     harmless — but "harmless today" is not a property to rely on.
//   - ⇒ **only a read is repeated.** A write is NEVER sent twice on the
//     strength of a 401: the cost of a write that ran twice (an account
//     reset, a permission change) is not something a heuristic should
//     decide. A write that comes back 401 is reported, and the caller
//     decides.
//
// A PrivateToken is not refreshed: it does not expire, and a 401 with one
// means the token itself is wrong — which repeating does not fix.
func (c *Client) attempt(ctx context.Context, method, path string, query url.Values, body, out any) error {
	err := c.doOnce(ctx, method, path, query, body, out)
	if err == nil || c.Token != "" {
		return err
	}
	// A credential that could not be OBTAINED is not a stale credential:
	// repeating the call would run the whole login (and the MFA challenge)
	// again, and the error the caller finally sees would be the second
	// failure's — which hides the first one's cause.
	var credErr *CredentialError
	if errors.As(err, &credErr) {
		return err
	}
	if !IsReadMethod(method) {
		return err
	}
	var apiErr *errs.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized {
		return err
	}
	c.invalidateBearer()
	return c.doOnce(ctx, method, path, query, body, out)
}

// IsReadMethod reports whether an HTTP method only reads.
//
// Everything else writes. The rule is deliberately blunt: the method the
// caller names decides what happens, so the method has to be what the
// decision is about.
//
// This is PROTOCOL vocabulary (which methods read) and it is shared: the
// transport's retry-on-401 and the delegation tool's confirm gate both
// ask it. A copy is a second place for "read" to mean something else.
func IsReadMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// retryable reports whether this failure may be tried again.
//
// The policy table comes from guardx/toolfail: retryable says a retry can
// produce a different outcome, safe-to-resubmit says the server never saw the
// request. Only the two together (or a read) justify a repeat.
func (c *Client) retryable(method string, err error) bool {
	policy := errs.Policy(err)
	if !policy.Retryable {
		return false
	}
	if policy.SafeToResubmit {
		return true
	}
	switch strings.ToUpper(method) {
	case "GET", "HEAD", "OPTIONS":
		return true
	}
	return false
}

// doOnce performs one attempt.
func (c *Client) doOnce(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u := c.apiURL(path)
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return err
	}
	// ⚠️ The header is whatever the CREDENTIAL says, not what the version
	// says: "Token <PrivateToken>" on both v4 and v5, and "Bearer <token>"
	// when the deployment was reached with a login. See auth.go.
	auth, err := c.authorization(ctx)
	if err != nil {
		return err
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	// The bucket is the last line of defence against a caller that loops.
	if c.limiter != nil {
		if err := c.limiter.Wait(ctx); err != nil {
			return err
		}
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("call %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		return &errs.APIError{
			Status:     resp.StatusCode,
			Method:     method,
			Path:       path,
			Body:       Truncate(string(raw), 400),
			RetryAfter: retryAfter(resp),
		}
	}
	if out == nil {
		return nil
	}
	// Several v5 endpoints answer a successful write with 204 and an empty
	// body — PUT /accounts/gathered-accounts/status/ and every DELETE among
	// them. Decoding that as JSON turns a write that worked into
	// "unexpected end of JSON input", which reads as a failure and, worse,
	// makes the caller believe nothing happened.
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode %s: %w (body starts: %s)", path, err, Truncate(string(raw), 160))
	}
	return nil
}

// raw performs one request with the caller's own headers and no
// authentication of its own, and returns the status and the body.
//
// ⚠️ It is deliberately UNEXPORTED: it is the one way to put a header of
// this client's choosing on the wire, and the delegation credential travels
// through it. A public one would be an exit the mechanical guard cannot
// see — a future caller could present a delegation credential without
// asking whether the deployment has the scheme.
//
// It exists for JumpServer's AI delegation scheme, whose credential must not
// travel together with the long-lived token. Two properties matter:
//
//   - it is NOT retried. A delegation credential is a single-use nonce, so a
//     retried request would be rejected as a replay — the retry would turn a
//     transient hiccup into a hard failure.
//   - the query string is sent byte for byte. The credential is bound to the
//     exact method, path, query and body, so re-encoding it would change the
//     binding and the request would come back as "request body mismatch".
func (c *Client) raw(ctx context.Context, method, path, query string, body []byte, headers map[string]string, timeout time.Duration) (int, []byte, error) {
	u := c.apiURL(path)
	if query != "" {
		u += "?" + query
	}

	var rdr io.Reader
	if len(body) > 0 {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	// A caller that needs a shorter life than the client's default gets one
	// here: the delegation credential lives 55s, and an HTTP client that
	// outlives it would report a timeout that looks like a server problem.
	hc := c.HTTP
	if timeout > 0 {
		cp := *c.HTTP
		cp.Timeout = timeout
		hc = &cp
	}

	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, raw, nil
}

// APIPath normalises a caller-supplied path to the form the bastion
// compares against.
//
// core checks `payload['path'] == request.path_info`, and path_info INCLUDES
// the /api/v1 prefix. Signing the friendly relative form made every request
// fail with "request mismatch" — while a hand-written probe that happened to
// use the absolute form worked, which is exactly how the two can disagree
// without either looking wrong.
//
// It is exported because the delegation scheme has to sign the same path the
// transport will send: two implementations of one rule is how they drift.
func APIPath(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if strings.HasPrefix(p, "/api/v1/") || p == "/api/v1" {
		return p
	}
	return "/api/v1" + p
}

// apiURL builds the absolute URL of an API path.
//
// The /api/v1 prefix is added when it is missing and left alone when it is
// already there, so a path may be written either way without producing
// /api/v1/api/v1/... — which is what happened when the delegation scheme
// signed the prefixed form and the token path signed the relative one.
func (c *Client) apiURL(path string) string {
	return c.BaseURL + APIPath(path)
}

// retryAfter reads the wait the server asked for.
//
// Only the seconds form is honoured; the HTTP-date form is rare enough on
// this bastion that guessing it would be worse than ignoring it.
func retryAfter(resp *http.Response) time.Duration {
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}
