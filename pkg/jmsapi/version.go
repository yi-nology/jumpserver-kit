package jmsapi

// The JumpServer version this client is talking to.
//
// Why a version at all, when the two versions look almost the same.
//
// They DO look almost the same, and that is the finding, not an assumption:
// every endpoint in the table above (api.go) exists at the SAME path in v4 as
// in v5, the authentication header is the same ("Authorization: Token <key>" —
// v4's PrivateTokenAuthentication is DRF's TokenAuthentication), the
// connection-token body is the same ({asset, account, protocol,
// connect_method}, with the account given as the ACCOUNT'S UUID — v4 resolves
// it through `is_uuid(alias)` and looks it up by id, and a regular account's
// alias IS its id), and the response shapes agree (the asset detail carries
// `accounts`, the account record carries id/name/username/is_active/privileged,
// `platform` is a nested object, the asset tree carries `full_value`).
//
// All of that was checked two ways: against the upstream v4.10.20-lts
// source (the URL registrations in apps/jumpserver/urls.py and each app's
// api_urls.py, the auth classes in apps/authentication/backends/drf.py, the
// connection-token model in apps/authentication/models/connection_token.py,
// and the serializers in apps/assets/serializers/asset/common.py) — AND
// against a LIVE v4.10.20 bastion (2026-10-31), where the whole endpoint
// table answered, the probe below said "v4", the connection token was minted
// with the account's UUID, and a command ran on a real asset through koko.
//
// ⚠️ The live run also CORRECTED two things the source reading had got
// wrong, and both are recorded where the code depends on them:
// the list endpoints answer with a BARE ARRAY on v4 too (not the standard
// envelope — the protocol layer reads both, so nothing broke, but the note
// that said otherwise was wrong), and perm_account_invalid on v4 does not
// mean "the account field is wrong" — it also means "nobody was granted the
// asset".
//
// So the ONE thing the version decides is the CHAT AI DELEGATION SCHEME, which
// is v5-only: v4 has no chat_ai application at all, no X-JMS-AI-Delegation
// authentication class, and no chat-ai API prefix. That is not a small
// difference — it is the difference between a session that carries the
// DELEGATED user's authority and one that carries the API token owner's
// (an administrator on this deployment). On v4 the narrower identity is not
// available, and pretending otherwise would be a lie about who a session runs
// as.
//
// The version is therefore not a "features" switch but a "what is true about
// the deployment" fact, and it is carried HERE — in the protocol layer —
// because both planes need it and neither may depend on the other.
//
// How the version is established:
//
//   - configured (JUMPSERVER_VERSION): the operator says which one it is.
//     Explicit beats guessed: the operator may know something the probe cannot
//     see (a deployment behind a proxy that hides the API prefix).
//   - detected: otherwise, the client asks the deployment once, at the first
//     call that needs the answer, and remembers it.
//
// The probe is one GET. Its answer is not "the version string" but the
// PRESENCE of the chat-ai API prefix, which v5 has and v4 does not. A
// deployment that cannot be reached does not get a version — it gets the
// configured one, and the doctor says the version could not be established.
// Guessing there would mean: on a v4 box, silently sending delegation
// credentials that v4 does not understand, and on a v5 box, silently dropping
// the delegation that keeps the sessions narrow.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/yi-nology/jumpserver-kit/model/jms"
	"github.com/yi-nology/jumpserver-kit/pkg/errs"
)

// Version is a JumpServer generation.
type Version string

const (
	// VersionV4 is JumpServer v4 (the 4.10 LTS line).
	VersionV4 Version = "v4"
	// VersionV5 is JumpServer v5.
	VersionV5 Version = "v5"
	// versionAuto is the CONFIGURED spelling of "work it out". It is not a
	// version: it is the absence of one.
	versionAuto Version = "auto"
)

// parseVersion reads a configured version.
//
// "auto" — and the empty string — mean "not configured": the deployment is
// asked instead. Treating an unset setting as v5 would silently pick a
// version on the operator's behalf, and picking the wrong one is not a
// cosmetic mistake: on v4 it means the delegation scheme is attempted
// against a deployment that has none.
//
// ⚠️ It is unexported: the CONFIGURATION layer validates the value with a
// fail-closed `options` tag, so nothing outside this package has a reason
// to parse it — and a public parser is a second way to spell the same rule.
func parseVersion(s string) (Version, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case string(VersionV4):
		return VersionV4, nil
	case string(VersionV5):
		return VersionV5, nil
	case "", string(versionAuto):
		return "", fmt.Errorf("no JumpServer version configured (expected %s or %s)",
			VersionV4, VersionV5)
	}
	return "", fmt.Errorf("unknown JumpServer version %q (expected %s or %s)",
		s, VersionV4, VersionV5)
}

// String renders the version.
func (v Version) String() string { return string(v) }

// DetectVersion asks the deployment which version it is.
//
// The signal is the presence of the chat-ai API prefix: v5 registers
// /api/v1/chat-ai/ (it holds the runtime store the AI callers use) and v4 does
// not register that prefix at all — v4's apps/jumpserver/urls.py has no
// chat-ai entry.
//
// ⚠️ The question is asked with TWO paths, and the answer is the DIFFERENCE
// between them:
//
//   - the chat-ai runtime store: a route that exists on v5 and not on v4;
//   - a route that exists on neither.
//
// ⚠️ WHY TWO, and why not read the status code: **v4's "no such route"
// handler is broken.** It answers 500 — its own exception handler crashes
// while rendering the 404 page — so on v4 EVERY unknown path under /api/v1/
// looks the same. Measured on a live v4.10.20 (2026-10-31):
//
//	GET /api/v1/chat-ai/runtime-store/    -> 500
//	GET /api/v1/chat-ai/definitely-not-here/ -> 500
//
// ⇒ "the route is not there" CANNOT be read off the status code.
//
// ⇒ So the question is not "what status did the chat-ai path answer" but
// "does the chat-ai path behave like a path that is not there":
//
//   - the SAME answer as the known-missing path => the route is not there
//     => the delegation scheme is not there => v4 (and also a v5 whose
//     chat_ai app is not installed — which is the same fact);
//   - a DIFFERENT answer => the route is there => v5.
//
// ⚠️ Measured on BOTH ends (2026-10-30 / 2026-10-31):
//
//	v5 bastion: chat-ai/runtime-store/ -> 401, chat-ai/definitely-not-here/ -> 404
//	v4 bastion: chat-ai/runtime-store/ -> 500, chat-ai/definitely-not-here/ -> 500
//
// ⇒ v5: different ⇒ the route is there. v4: the same => it is not.
//
// The 401 on v5 is not a mistake: v5's runtime-store view authenticates with
// an AccessKey SIGNATURE (`SignatureAuthentication` + `IsServiceAccount`), so
// it does not accept the PrivateToken this client carries — and it still does
// not answer like a path that is not there, which is the whole point.
//
// ⚠️ And if BOTH probes fail the same way because the deployment is simply
// broken, the answer is "the same" => the scheme is read as ABSENT. That is
// the direction this repository wants: without the scheme every session runs
// with the API credential's authority (wider), rather than presenting a
// credential the deployment cannot read (slower, and a 401 on every session).
// The doctor says which it was.
//
// The probe goes through the ordinary authenticated transport, so it needs a
// credential — and on v4 a deployment that requires the probe's path to
// exist is exactly what we are asking about.
func (c *Client) detectVersion(ctx context.Context) (Version, error) {
	real, realErr := c.statusOf(ctx, string(ResChatAI))
	missing, missingErr := c.statusOf(ctx, string(ResProbeMissing))
	if realErr != nil && missingErr != nil {
		return "", fmt.Errorf("could not tell which version the bastion runs: %w", realErr)
	}
	if realErr == nil && missingErr == nil && real == missing {
		// The chat-ai route behaves exactly like a route nobody has.
		return VersionV4, nil
	}
	if realErr != nil {
		return "", fmt.Errorf("could not tell which version the bastion runs: %w", realErr)
	}
	if missingErr != nil {
		return "", fmt.Errorf("could not tell which version the bastion runs: %w", missingErr)
	}
	return VersionV5, nil
}

// statusOf asks for one path and reports the status it answered with.
//
// The error is returned as well, because a transport failure is different
// from a status: the first says "could not ask", the second says "asked, and
// here is the answer".
func (c *Client) statusOf(ctx context.Context, path string) (int, error) {
	err := c.Do(ctx, "GET", path, nil, nil, nil)
	if err == nil {
		return http.StatusOK, nil
	}
	var apiErr *errs.APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status, nil
	}
	return 0, err
}

// ResolveVersion decides which version this client is talking to.
//
// Profile resolves what the deployment HAS, and remembers it.
//
// Two ways to get there, and the configured one is cheaper:
//
//   - the operator said which release it is (JUMPSERVER_VERSION): the
//     capability set FOLLOWS from the difference list — NO probe, no
//     request, and no way to get it wrong;
//   - otherwise the deployment is asked, once.
//
// ⚠️ The profile is what the CODE asks about. The version is only what the
// operator configures and what the doctor reports — a release is a fact
// about the deployment, a capability is a fact about what can be done here,
// and only the second is a thing a caller can act on.
// profileFailureTTL is how long a failed detection is remembered.
//
// ⚠️ The failure must NOT be remembered forever: a long-running process
// would keep believing the wrong thing for the rest of its life (on a v4
// deployment, that means every session presents a delegation credential,
// gets a 401, and walks the slow terminal path).
//
// ⚠️ And it must not be re-probed on EVERY call either: the probe is a
// network call with retries, so a bastion whose probe path is broken — but
// whose API is fine — would cost every session open a full probe.
//
// ⇒ A short window: an outage does not outlive it, and one broken path does
// not cost a probe per call.
const profileFailureTTL = 30 * time.Second

func (c *Client) Profile(ctx context.Context) Profile {
	c.profileMu.Lock()
	if c.profileResolved {
		p := c.profile
		c.profileMu.Unlock()
		return p
	}
	configured := c.versionSetting
	failedAt := c.profileFailedAt
	c.profileMu.Unlock()

	if configured != "" && !strings.EqualFold(configured, string(versionAuto)) {
		v, err := parseVersion(configured)
		c.profileMu.Lock()
		defer c.profileMu.Unlock()
		if err != nil {
			c.versionErr = err
			c.profile = unknownProfile()
			c.profileResolved = true
			return c.profile
		}
		c.profile = profileOf(v)
		c.profileResolved = true
		return c.profile
	}

	// A recent failure is reused rather than re-probed — for the window
	// only, so an outage does not outlive it.
	if !failedAt.IsZero() && time.Since(failedAt) < profileFailureTTL {
		c.profileMu.Lock()
		p := c.profile
		c.profileMu.Unlock()
		return p
	}

	// ⚠️ The probe is a NETWORK CALL, so it happens OUTSIDE the lock.
	//
	// Holding the lock across it would make every concurrent caller wait
	// for it — and the wait would be uninterruptible: a sync.Mutex's
	// waiters cannot be cancelled by the context. With the default 90s
	// timeout and three retries, one hung probe would hold the lock for
	// minutes, and a fleet sweep (which asks the question once per
	// session) would queue behind it.
	v, err := c.detectOnce(ctx)
	c.profileMu.Lock()
	defer c.profileMu.Unlock()
	if err != nil {
		c.versionErr = err
		c.profile = unknownProfile()
		// ⚠️ The failure is remembered only for the window (see
		// profileFailureTTL) ⇒ the next call after the window probes
		// again, and an outage cannot outlive it.
		c.profileFailedAt = time.Now()
		return c.profile
	}
	c.profile = profileOf(v)
	c.profileResolved = true
	c.profileFailedAt = time.Time{}
	return c.profile
}

// State reports what is known about the capability.
//
// It is the three-valued FACT, and it is the question the REPORTING side
// asks. ⚠️ There is deliberately no boolean twin of it on the client: a
// boolean would have to fold "does not have it" and "did not find out" into
// one answer, and the reporting side would then state a fact it has not
// established.
//
// ⇒ The two decisions are asked as their own questions: Present (known to
// have it) and MayPresent (not known to lack it).
func (c *Client) State(ctx context.Context, cap Capability) CapabilityState {
	return c.Profile(ctx).State(cap)
}

// MayPresent reports whether this capability's credential may be presented.
//
// It is the question the EXECUTION side asks: "may I try to present this?".
// The difference from Present() is the unknown case, and it is spelled out in
// capability.go.
func (c *Client) MayPresent(ctx context.Context, cap Capability) bool {
	return c.Profile(ctx).MayPresent(cap)
}

// DetectedVersion reports what the deployment looks like, independently of the
// configured setting.
//
// It is what the doctor compares the configured version against: a setting
// that disagrees with the deployment is worth saying out loud, because the
// two disagreeing has consequences (on v4, delegation does not exist).
//
// A successful detection is remembered; a failed one is not, so a bastion
// that was unreachable a moment ago is asked again.
func (c *Client) DetectedVersion(ctx context.Context) (Version, error) {
	return c.detectOnce(ctx)
}

// detectOnce probes the deployment at most once per client.
//
// The probe happens OUTSIDE the lock, so two callers that arrive together
// may both probe: a duplicate probe is one request, while holding the lock
// across a network call would make the second caller wait for the first
// one's timeout. Only a SUCCESSFUL detection is remembered — a bastion that
// was unreachable a moment ago is asked again.
func (c *Client) detectOnce(ctx context.Context) (Version, error) {
	c.detectMu.Lock()
	known := c.detected
	c.detectMu.Unlock()
	if known != "" {
		return known, nil
	}
	detected, err := c.detectVersion(ctx)
	if err != nil {
		return "", err
	}
	c.detectMu.Lock()
	defer c.detectMu.Unlock()
	if c.detected == "" {
		c.detected = detected
	}
	return c.detected, nil
}

// VersionReport is what a doctor needs to say about the deployment.
//
// It carries the two answers that used to be fetched separately — what the
// operator configured and what the deployment actually is — and it is
// assembled with ONE probe.
//
// ⚠️ Why one: asking twice would probe twice, and on a bastion that is
// failing that is two timeouts per doctor run. And why it lives here rather
// than in the two doctors: the rule "probe once, and probe only when the
// comparison needs it" is a rule about the PROTOCOL, and two copies of it
// are two chances to drift.
type VersionReport struct {
	// ConfiguredSetting is the version the operator set, or "" when the
	// deployment is to be asked.
	ConfiguredSetting string

	// Effective is the release the client acts on. It is the detected one
	// when the deployment could be asked, and the configured one
	// otherwise.
	Effective Version

	// Detected is what the deployment says it is, when it could be asked.
	Detected Version

	// DetectedKnown says whether the deployment could be asked at all.
	DetectedKnown bool

	// Err is why it could not be asked.
	Err error
}

// ReportVersion assembles the report.
//
// The probe happens only when it is needed: with the version configured, the
// deployment has to be asked separately (the profile came from the setting,
// not from the deployment — that is the comparison); with it on "auto", the
// profile's own detection IS the detection, and asking again would be a
// second probe for the same answer.
func (c *Client) ReportVersion(ctx context.Context) VersionReport {
	profile := c.Profile(ctx)
	effective, known := profile.Version()
	rep := VersionReport{
		ConfiguredSetting: c.versionSetting,
		Effective:         effective,
		Detected:          effective,
		DetectedKnown:     known,
	}
	if c.VersionConfigured() {
		detected, err := c.DetectedVersion(ctx)
		rep.Detected = detected
		rep.DetectedKnown = err == nil
		// ⚠️ The profile's own error wins: a configured version that
		// does not parse is a SETTING problem, and the probe's error
		// (if any) would hide it. ⇒ The operator would be told the
		// deployment "looks like v5" and never that their setting is
		// invalid.
		if rep.Err == nil {
			rep.Err = err
		}
		return rep
	}
	if !known {
		rep.Err = c.profileError()
	}
	return rep
}

// profileError returns why the profile could not be resolved, if it could
// not. It is nil when the version was configured or detected.
func (c *Client) profileError() error {
	c.profileMu.Lock()
	defer c.profileMu.Unlock()
	return c.versionErr
}

// VersionConfigured reports whether the version was set by the operator rather
// than detected.
func (c *Client) VersionConfigured() bool {
	return c.versionSetting != "" && !strings.EqualFold(c.versionSetting, string(versionAuto))
}

// Configured reports whether the REPORT says the version was set by the
// operator rather than detected.
//
// ⚠️ It is on the report because the report is what the doctors read, and
// the question "was it configured or detected?" is the question the report
// exists to answer. ⇒ A caller must not have to reach for the client to
// ask it — that is how the two doctors ended up with two copies of the
// same decision.
func (r VersionReport) Configured() bool {
	return r.ConfiguredSetting != "" && !strings.EqualFold(r.ConfiguredSetting, string(versionAuto))
}

// UnknownPolicy says what a plane DOES with a capability it could not
// establish.
//
// ⚠️ It is a parameter because the two planes genuinely differ, and one
// sentence for both would be a lie in one of them:
//
//   - the EXECUTION plane presents the credential anyway: the sessions stay
//     narrow, and a deployment that lacks the scheme falls back to the slow
//     terminal path (slower, but working);
//   - the MANAGEMENT plane's delegation tools refuse: there is nothing to
//     mint a credential for, and a 401 on that path reads as "the
//     credential is wrong".
//
// ⇒ Each doctor says what ITS OWN plane does.
type UnknownPolicy int

const (
	// UnknownPresented is the execution plane's policy.
	UnknownPresented UnknownPolicy = iota
	// UnknownRefused is the management plane's policy.
	UnknownRefused
)

// unknownClause renders the policy half of the "could not be asked" sentence.
func unknownClause(policy UnknownPolicy) string {
	switch policy {
	case UnknownRefused:
		return "it is treated as unavailable here: the delegation tools refuse it, " +
			"because there is nothing to mint a credential for"
	default:
		return "it is treated as available, so a credential is presented " +
			"(the sessions stay narrow, but a deployment without the scheme would " +
			"fall back to the slow terminal path)"
	}
}

// VersionRow is what a doctor says about the deployment's release and the
// delegation scheme.
//
// ⚠️ It carries the SHARED status vocabulary (model/jms.Status) so that the
// two doctors do not each invent a level of their own.
type VersionRow struct {
	// Status is ok or warn.
	Status jms.Status

	// Message is the sentence.
	Message string

	// Advice is what to do about it ("" when there is nothing to do).
	Advice string
}

// VersionRowFor assembles the row.
//
// ⚠️ It used to be written TWICE — once per doctor — and the two copies had
// already drifted: one grew a parenthetical about the slow path, the other
// grew an advice column, and BOTH said "it is treated as available" while
// the management plane's delegation tools in fact REFUSE an unknown scheme
// ⇒ the management plane's doctor misdescribed its own plane.
//
// ⇒ The judgement AND the sentences live here, once. What each doctor adds
// is only the shape of its own report (the management plane has a separate
// advice column; the execution plane has one string), never the wording.
func VersionRowFor(rep VersionReport, state CapabilityState, policy UnknownPolicy) VersionRow {
	name := "the delegation scheme"
	if decl, ok := declOf(CapDelegation); ok {
		name = "the " + decl.Name
	}
	switch {
	case rep.Err != nil:
		return VersionRow{
			Status:  jms.Status_warn,
			Message: fmt.Sprintf("the deployment could not be asked about %s (%v); %s", name, rep.Err, unknownClause(policy)),
			Advice:  "check that JUMPSERVER_URL points at the bastion, or set JUMPSERVER_VERSION explicitly",
		}
	case rep.Configured() && rep.DetectedKnown && rep.Detected != rep.Effective:
		return VersionRow{
			Status: jms.Status_warn,
			Message: fmt.Sprintf("JUMPSERVER_VERSION says %s but the deployment looks like %s; the delegation scheme is %s there",
				rep.Effective, rep.Detected, state),
			Advice: fmt.Sprintf("set JUMPSERVER_VERSION=%s", rep.Detected),
		}
	default:
		how := "detected"
		if rep.Configured() {
			how = "configured"
		}
		return VersionRow{
			Status:  jms.Status_ok,
			Message: fmt.Sprintf("%s (%s), delegation scheme: %s", rep.Effective, how, state),
		}
	}
}
