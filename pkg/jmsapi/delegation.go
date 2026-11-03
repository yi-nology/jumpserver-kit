package jmsapi

// The Chat AI delegation scheme: a credential that authorises exactly one
// call, bound to that call, once, for under a minute.
//
// Why it lives here. A long-lived API token is all-or-nothing — anyone holding
// it can call anything the user can, for as long as it lives, and nothing in
// core distinguishes "a human's token" from "an agent's token". JumpServer
// ships a narrower scheme for AI callers, and it is live on this deployment
// (CHAT_AI_DELEGATION_SECRET is set, and the authentication class is registered
// globally in DEFAULT_AUTHENTICATION_CLASSES).
//
// Both planes need it, and the two planes may not import each other: the
// management plane calls the bastion as the delegated user, and the execution
// plane mints a CONNECTION TOKEN as the delegated user so a session on a
// machine carries that user's authority rather than the API token owner's.
// Two copies of the signing rules would drift, and the drift would show up as
// "request mismatch" — core's way of saying the two sides disagree about what
// was signed.
//
// A delegation credential is bound, and core verifies every binding. Measured
// 2026-10-15 against a live bastion, each of these was rejected:
//
//	missing X-JMS-ORG            -> "organization mismatch"
//	operation header != token    -> "operation mismatch"
//	different path               -> "request mismatch"
//	different query string       -> "request body mismatch"
//	different method             -> "request mismatch"
//	same token twice             -> "credential was already used"  (single-use nonce)
//
// So the credential authorises exactly one call: one method, one path, one
// query, one body, once, within 60 seconds. That is a different security
// property from a bearer token, not a different amount of access — it is worth
// having for operations you would rather not leave permanently reachable.
//
// What it does NOT do: it does not grant access the user lacks. The returned
// user is fed into the normal RBAC pipeline, and `allowed_operation_id` is only
// checked for consistency between the header and the token, not against the
// endpoint. Any access the caller already has, delegation cannot widen.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oekit/pkg/convert"
	"github.com/oekit/pkg/stringx"
)

const (
	// DelegationHeader is the header core reads the credential from.
	DelegationHeader = "X-JMS-AI-Delegation"
	// OperationHeader labels the action for core's audit trail. core only
	// checks that this matches the token, but a meaningful value is what makes
	// the audit entry readable later.
	OperationHeader = "X-JMS-AI-Operation"
	// OrgHeader is mandatory: without it the request context org defaults
	// elsewhere and core answers "organization mismatch".
	OrgHeader = "X-JMS-ORG"

	// DefaultDelegationIssuer and friends are the values a credential carries
	// when the deployment does not override them.
	DefaultDelegationIssuer   = "jumpserver-ai"
	DefaultDelegationAudience = "jumpserver-core"
	DefaultDelegationKeyID    = "v1"

	// DelegationTTL is how long a minted credential is good for. core rejects
	// TTLs over 60s (MAX_TTL in chat_ai/delegation.py), so this stays below it.
	DelegationTTL = 55 * time.Second
)

// DelegationConfig is everything needed to mint a credential.
type DelegationConfig struct {
	// Secret is the deployment's CHAT_AI_DELEGATION_SECRET.
	Secret []byte
	// KeyID, Issuer and Audience identify the credential to core.
	KeyID    string
	Issuer   string
	Audience string
	// OrgID and UserID say who the credential acts as. When they are
	// empty the identity is looked up and remembered.
	OrgID  string
	UserID string

	// identity is where a looked-up identity is remembered. It is a
	// pointer so that COPIES of this config share it: a fleet sweep opens
	// several sessions at the same time, and they must not race to fill it
	// in.
	identity *DelegationIdentity
}

// DelegationIdentity is the resolved identity, remembered.
//
// It is written once and read many times, from several goroutines, so it
// carries its own lock rather than relying on the caller's.
type DelegationIdentity struct {
	mu     sync.Mutex
	userID string
	orgID  string
}

// NewDelegationConfig returns a config with a shared identity holder.
//
// The holder is what makes the lookup happen once: every copy of the config
// shares it, so the second session on an asset does not look the identity up
// again.
func NewDelegationConfig(secret []byte, userID, orgID string) *DelegationConfig {
	return &DelegationConfig{
		Secret:   secret,
		UserID:   userID,
		OrgID:    orgID,
		identity: &DelegationIdentity{},
	}
}

// Identity returns the effective user and org, and whether they are known.
//
// The explicit ids win; then the remembered ones.
func (c DelegationConfig) Identity() (userID, orgID string, ok bool) {
	if c.UserID != "" && c.OrgID != "" {
		return c.UserID, c.OrgID, true
	}
	if c.identity == nil {
		return "", "", false
	}
	c.identity.mu.Lock()
	defer c.identity.mu.Unlock()
	if c.identity.userID != "" && c.identity.orgID != "" {
		return c.identity.userID, c.identity.orgID, true
	}
	return "", "", false
}

// Remember stores a looked-up identity.
func (c *DelegationConfig) Remember(userID, orgID string) {
	if c.identity == nil {
		c.UserID, c.OrgID = userID, orgID
		return
	}
	c.identity.mu.Lock()
	defer c.identity.mu.Unlock()
	if c.identity.userID == "" {
		c.identity.userID = userID
	}
	if c.identity.orgID == "" {
		c.identity.orgID = orgID
	}
}

// DelegationCall describes the single request a credential will be spent on.
type DelegationCall struct {
	Method string
	Path   string
	Query  string
	Body   []byte
	// OperationID labels the action for core's audit trail.
	OperationID string
}

// Available reports whether a delegation secret was configured, so callers can
// explain themselves instead of failing cryptically.
func (c DelegationConfig) Available() (bool, string) {
	if len(c.Secret) == 0 {
		return false, "no delegation secret configured"
	}
	if _, _, ok := c.Identity(); !ok {
		return false, "no user id configured for delegation"
	}
	return true, ""
}

// DelegationConfigured reports whether this process is configured for the
// delegation scheme: a secret, and an identity.
//
// ⚠️ It is the SECOND of the two questions, and it is deliberately separate
// from the first one (does the DEPLOYMENT have the scheme — see
// Client.State(ctx, CapDelegation)):
//
//   - the deployment not having it cannot be fixed by configuring anything,
//     and the operator has to know that;
//   - this process not being configured can be fixed, and the operator has to
//     know THAT too.
//
// One combined answer cannot say which of the two it is — and when they
// shared one, the callers wrote one sentence for both, and the sentence was
// wrong half the time.
func (c *Client) DelegationConfigured(cfg DelegationConfig) (bool, string) {
	return cfg.Available()
}

// requestBindingHash mirrors chat_ai.delegation.request_binding_hash exactly:
// sha256 over method, path, query and body joined by NUL. Any deviation here
// produces a token core rejects with "request body mismatch".
func requestBindingHash(method, path, query string, body []byte) string {
	h := sha256.New()
	h.Write([]byte(strings.ToUpper(method)))
	h.Write([]byte{0})
	h.Write([]byte(path))
	h.Write([]byte{0})
	h.Write([]byte(query))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// delegationPath normalises a caller-supplied path to the form core compares
// against.
//
// The rule itself is APIPath: the delegation credential is bound to the exact
// path the transport will send, so the two MUST agree — and two
// implementations of one rule is how they drift.
//
// core checks `payload['path'] == request.path_info`, and path_info INCLUDES
// the /api/v1 prefix. Signing the friendly relative form made every request
// fail with "request mismatch" — while a hand-written probe that happened to
// use the absolute form worked, which is exactly how the two can disagree
// without either looking wrong.
func delegationPath(p string) string {
	return APIPath(p)
}

// EnsureDelegationIdentity fills in the user and org the credential acts as.
//
// Deriving them beats asking the operator to copy two UUIDs out of the admin
// UI: the ids are already reachable with the token this process holds, and a
// wrong org id produces "organization mismatch" at call time rather than an
// obvious configuration error. Explicit env values still win, because a
// deliberate override should not be second-guessed.
func (c *Client) EnsureDelegationIdentity(ctx context.Context, cfg *DelegationConfig) error {
	return c.EnsureDelegationIdentityAs(ctx, cfg, "ai")
}

// DelegationUsername is the account a delegated credential is minted for.
//
// ⚠️ An empty name falls back to "ai" — the account the sessions have
// always run as. The fallback lives HERE, in ONE place, because the
// doctor has to report the same name the sessions will use: a doctor that
// said "" while the sessions actually ran as "ai" would report a fact that
// is not true, and the identity row is exactly the row an operator cannot
// work out from the rest of the report.
//
// ⚠️ The name is NOT a default for the configuration — `JMS_KOKO_USER` has
// no default, on purpose (a default would point one deployment's clients
// at somebody else's account). This is the fallback for a session that
// still has to act as *something* when the delegation secret is present
// but the account was never named.
func DelegationUsername(username string) string {
	if strings.TrimSpace(username) == "" {
		return "ai"
	}
	return username
}

// EnsureDelegationIdentityAs fills in the user and org the credential acts
// as, looking the user up by this username.
//
// The username is a parameter because the two planes have their own notion of
// who they act as: the management plane delegates as `ai` unless it is told
// otherwise, and the execution plane delegates as the account its sessions
// run as. Hard-coding one of them in the shared layer would make the other
// plane's sessions run as somebody else.
func (c *Client) EnsureDelegationIdentityAs(ctx context.Context, cfg *DelegationConfig, username string) error {
	if len(cfg.Secret) == 0 {
		// ⚠️ 说清楚**去哪找**：只说「没配」的话，运维只能去翻文档；
		// 而这条消息会出现在 --doctor 的告警行里 —— 那正是「人正在找原因」的时刻。
		return fmt.Errorf(
			"no delegation secret configured: set JMS_DELEGATION_SECRET, or write the value to one of %s (mode 0600)",
			strings.Join(DelegationSecretFiles(), ", "))
	}
	username = DelegationUsername(username)
	if _, _, ok := cfg.Identity(); ok {
		return nil
	}
	if cfg.identity == nil {
		// No shared holder: this config is a private copy, so there is
		// nothing to race with.
		userID, orgID, err := c.lookupIdentity(ctx, username)
		if err != nil {
			return err
		}
		cfg.UserID, cfg.OrgID = userID, orgID
		return nil
	}
	// The lookup happens under the shared holder's lock, so that several
	// sessions opened at the same time do not race to fill it in. A second
	// lookup is harmless — it is the same answer — but the RACE was not.
	//
	// Nothing outside this lock is written: the config's own fields are
	// shared by every session, so writing them here would be the very race
	// this holder exists to prevent.
	cfg.identity.mu.Lock()
	defer cfg.identity.mu.Unlock()
	if cfg.identity.userID != "" && cfg.identity.orgID != "" {
		return nil
	}
	userID, orgID, err := c.lookupIdentity(ctx, username)
	if err != nil {
		return err
	}
	cfg.identity.userID = userID
	cfg.identity.orgID = orgID
	return nil
}

// lookupIdentity finds the user and the org the credential acts as.
func (c *Client) lookupIdentity(ctx context.Context, username string) (string, string, error) {
	rows, err := c.ListQuery(ctx, ResUsers, url.Values{"username": {username}})
	if err != nil {
		return "", "", err
	}
	userID := ""
	for _, r := range rows {
		if id := convert.AnyToStr(r["id"]); id != "" {
			userID = id
			break
		}
	}
	if userID == "" {
		return "", "", fmt.Errorf("could not resolve a user id for %q; set JMS_DELEGATION_USER_ID", username)
	}
	orgs, err := c.List(ctx, ResOrgs)
	if err != nil {
		return "", "", err
	}
	orgID := ""
	for _, o := range orgs {
		if strings.EqualFold(convert.AnyToStr(o["name"]), "DEFAULT") {
			orgID = convert.AnyToStr(o["id"])
			break
		}
	}
	if orgID == "" && len(orgs) > 0 {
		orgID = convert.AnyToStr(orgs[0]["id"])
	}
	if orgID == "" {
		return "", "", fmt.Errorf("could not resolve an org id; set JMS_DELEGATION_ORG_ID")
	}
	return userID, orgID, nil
}

// MintDelegation produces the `payload.signature` token for one call.
func (c *Client) MintDelegation(cfg DelegationConfig, call DelegationCall) (string, error) {
	if ok, why := cfg.Available(); !ok {
		return "", fmt.Errorf("delegation unavailable: %s", why)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("nonce: %w", err)
	}
	now := time.Now()
	signedPath := delegationPath(call.Path)
	userID, orgID, _ := cfg.Identity()
	payload := map[string]any{
		"issuer":               firstNonEmpty(cfg.Issuer, DefaultDelegationIssuer),
		"audience":             firstNonEmpty(cfg.Audience, DefaultDelegationAudience),
		"key_id":               firstNonEmpty(cfg.KeyID, DefaultDelegationKeyID),
		"user_id":              userID,
		"org_id":               orgID,
		"allowed_operation_id": call.OperationID,
		"method":               strings.ToUpper(call.Method),
		"path":                 signedPath,
		"request_hash":         requestBindingHash(call.Method, signedPath, call.Query, call.Body),
		"nonce":                hex.EncodeToString(nonce),
		"issued_at":            now.Unix(),
		"expires_at":           now.Add(DelegationTTL).Unix(),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, cfg.Secret)
	mac.Write([]byte(encoded))
	return encoded + "." + hex.EncodeToString(mac.Sum(nil)), nil
}

// DelegationRequest performs one request authorised by a freshly minted,
// single-use credential. It returns the status and body without going through
// the token-based client, because the whole point is that this call does NOT
// carry the long-lived token.
func (c *Client) DelegationRequest(ctx context.Context, cfg DelegationConfig, call DelegationCall) (int, []byte, error) {
	token, err := c.MintDelegation(cfg, call)
	if err != nil {
		return 0, nil, err
	}
	return c.SendWithDelegation(ctx, token, cfg, call)
}

// SendWithDelegation performs a request with an ALREADY-minted credential.
//
// It exists so the boundary of that credential can be observed: handing the same
// token a different path, method, query or operation id has to fail, and that
// can only be checked by sending a token whose signature no longer matches the
// request. Minting a fresh token per attempt would prove nothing — every such
// attempt would be correctly signed and therefore correctly accepted.
//
// The request goes out through the shared transport, but WITHOUT the token
// header and WITHOUT the retry: a delegation credential is a single-use nonce,
// so a retried request would be rejected as a replay.
func (c *Client) SendWithDelegation(ctx context.Context, token string, cfg DelegationConfig, call DelegationCall) (int, []byte, error) {
	_, orgID, _ := cfg.Identity()
	headers := map[string]string{
		DelegationHeader: token,
		OperationHeader:  call.OperationID,
		// The org comes from the EFFECTIVE identity, not from the config's
		// own field: a resolved identity lives in the shared holder, and
		// sending an empty X-JMS-ORG is what makes core answer
		// "organization mismatch".
		OrgHeader: orgID,
	}
	// A delegation credential lives 55s; do not let the HTTP client outlive it
	// and then report a timeout that looks like a server problem.
	return c.raw(ctx, call.Method, call.Path, call.Query, call.Body,
		headers, DelegationTTL+15*time.Second)
}

// LoadDelegationSecret resolves the secret without ever printing it.
//
// Order: explicit environment variable, then a 0600 file. The file is the
// recommended home for it — the value is a bastion-wide root of trust for AI
// callers, and putting it in an MCP config file would spread it to every
// process that can read that directory.
func LoadDelegationSecret() ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv("JMS_DELEGATION_SECRET")); v != "" {
		return []byte(v), nil
	}
	for _, p := range DelegationSecretFiles() {
		b, err := os.ReadFile(p)
		if err == nil {
			if v := strings.TrimSpace(string(b)); v != "" {
				return []byte(v), nil
			}
		}
	}
	return nil, fmt.Errorf(
		"delegation secret not found: set JMS_DELEGATION_SECRET, or write the value to one of %s (mode 0600)",
		strings.Join(DelegationSecretFiles(), ", "))
}

// DelegationSecretFiles lists where the secret may live.
//
// The list is derived rather than hard-coded in one place so that the
// management plane and the execution plane look in the SAME places: a secret
// that one of them can find and the other cannot is a deployment that works
// for half the tools and fails for the other half.
func DelegationSecretFiles() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".config", "jumpserver-mcp", "delegation.key"),
		filepath.Join(home, ".local", "etc", "jumpserver-mcp", "delegation.key"),
	}
}

// firstNonEmpty returns v when it is set, and the fallback otherwise.
//
// The order matters, and used to be the other way round — which made the
// configured issuer and audience unreachable: the fallback was never empty,
// so it always won.
func firstNonEmpty(v, fallback string) string {
	return stringx.TakeOne(v, fallback)
}
