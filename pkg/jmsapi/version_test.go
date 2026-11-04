package jmsapi

// The version, and what it decides.
//
// The facts under test were checked against the upstream v4.10.20-lts source
// (apps/jumpserver/urls.py mounts a chat-ai/ prefix on v5 and does not on v4;
// there is no chat_ai application in v4's tree at all). What is NOT checked
// here is any behaviour of a real v4 deployment: there is no v4 bastion to
// point these at, so these tests pin the DECISION the client makes, not the
// deployment's answer. The live check lives in internal/repository/livetest,
// and it is gated.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The answers the two probe paths gave on LIVE bastions (2026-10-31).
//
// ⚠️ They are the measured numbers, not invented ones, because the probe's
// whole logic is "do these two answers differ?":
//
//	v5: chat-ai/runtime-store/ -> 401, a path that exists on neither -> 404
//	v4: chat-ai/runtime-store/ -> 500, a path that exists on neither -> 500
//
// ⇒ On v4 the two answers are the SAME, and that is the finding: v4's
// "no such route" handler is broken, so every unknown path answers 500.
const (
	// v5ChatStatus is what v5's chat-ai runtime store answered.
	v5ChatStatus = http.StatusUnauthorized
	// v5MissingStatus is what v5 answered for a path that exists nowhere.
	v5MissingStatus = http.StatusNotFound
	// v4ChatStatus is what v4 answered for the chat-ai path — the same as
	// for every other unknown path.
	v4ChatStatus = http.StatusInternalServerError
	// v4MissingStatus is what v4 answered for a path that exists nowhere.
	v4MissingStatus = http.StatusInternalServerError
)

// probeCounts records how often each half of the probe was asked.
//
// ⚠️ Two counters, because the probe asks TWO paths: a counter over "the
// probe ran" would be ambiguous about which half it ran.
type probeCounts struct {
	chat    int
	missing int
}

// versionBastion answers the probe the way a given deployment would.
//
// ⚠️ The fake answers BOTH halves of the probe, because the detection is
// the COMPARISON between them: the chat-ai runtime store (a route v5 has
// and v4 does not) and a path that exists on no deployment at all.
//
// ⚠️ A fake that answers the chat-ai path with "404 = not there" and
// everything else with 200 would model a deployment that does not exist:
// on v4 the chat-ai path answers 500, exactly like the missing one.
func versionBastion(t *testing.T, chatStatus, missingStatus int) (*Client, *probeCounts) {
	t.Helper()
	counts := &probeCounts{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1" + string(ResChatAI):
			counts.chat++
			w.WriteHeader(chatStatus)
			_, _ = w.Write([]byte(`{"detail":"Not found."}`))
		case "/api/v1" + string(ResProbeMissing):
			counts.missing++
			w.WriteHeader(missingStatus)
			_, _ = w.Write([]byte(`{"detail":"Not found."}`))
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return New(Options{BaseURL: srv.URL, Token: "t", HTTPClient: srv.Client()}), counts
}

// v4Bastion is a fake that answers the way a v4 deployment does.
func v4Bastion(t *testing.T) (*Client, *probeCounts) {
	return versionBastion(t, v4ChatStatus, v4MissingStatus)
}

// v5Bastion is a fake that answers the way a v5 deployment does.
func v5Bastion(t *testing.T) (*Client, *probeCounts) {
	return versionBastion(t, v5ChatStatus, v5MissingStatus)
}

// The chat-ai path answering EXACTLY like a path nobody has means the route
// is not registered — which is v4 (and also a v5 whose chat_ai application is
// not installed: the same fact).
//
// ⚠️ It is a comparison, not a status code: on v4 the chat-ai path answers
// 500, and reading "500" as "v5, the route exists" would be wrong.
func TestTheChatAIPathAnsweringLikeAMissingPathMeansV4(t *testing.T) {
	c, _ := v4Bastion(t)
	v, err := c.detectVersion(context.Background())
	if err != nil {
		t.Fatalf("detectVersion: %v", err)
	}
	if v != VersionV4 {
		t.Errorf("version = %q, want %q", v, VersionV4)
	}
}

// A chat-ai path that answers DIFFERENTLY is a route that exists — v5.
//
// A 401 or a 405 says the route is there, which is the whole question; it
// says nothing about the version otherwise.
func TestTheChatAIPathAnsweringDifferentlyMeansV5(t *testing.T) {
	for _, chat := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusMethodNotAllowed} {
		c, _ := versionBastion(t, chat, v5MissingStatus)
		v, err := c.detectVersion(context.Background())
		if err != nil {
			t.Fatalf("detectVersion (%d): %v", chat, err)
		}
		if v != VersionV5 {
			t.Errorf("chat status %d: version = %q, want %q", chat, v, VersionV5)
		}
	}
}

// The probe asks TWO paths, and both are asked.
//
// ⚠️ A probe that asked only one would be a probe that reads a status
// code, and on v4 that status code is 500 for EVERY unknown path — so the
// single-path probe could never tell v4 from a broken v5.
//
// ⚠️ The counters count REQUESTS, not rounds: a 5xx is retried, and v4
// answers 5xx, so one round of the probe is several requests. ⇒ What is
// asserted here is that both halves were asked at all.
func TestTheProbeAsksBothPaths(t *testing.T) {
	c, counts := v5Bastion(t)
	if _, err := c.detectVersion(context.Background()); err != nil {
		t.Fatalf("detectVersion: %v", err)
	}
	if counts.chat == 0 {
		t.Error("the probe never asked the chat-ai path")
	}
	if counts.missing == 0 {
		t.Error("the probe never asked the path that exists on neither")
	}
}

// A bastion that cannot be reached does not get a version. Guessing here
// would mean: on a v4 box, sending delegation credentials that v4 does not
// understand, and on a v5 box, silently dropping the delegation that keeps
// the sessions narrow.
func TestAnUnreachableDeploymentHasNoVersion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close() // nothing is listening any more
	c := New(Options{BaseURL: base, Token: "t"})
	if _, err := c.detectVersion(context.Background()); err == nil {
		t.Fatal("an unreachable deployment must not get a version")
	}
}

// The CONFIGURED version wins over the probe.
//
// Explicit beats guessed: the operator may know something the probe cannot
// see — a deployment behind a proxy that hides the API prefix, say.
func TestTheConfiguredVersionWinsOverTheProbe(t *testing.T) {
	c, counts := v4Bastion(t)
	c.versionSetting = string(VersionV5)
	if v := profileVersion(c); v != VersionV5 {
		t.Errorf("version = %q, want %q", v, VersionV5)
	}
	if counts.chat != 0 || counts.missing != 0 {
		t.Errorf("the deployment was probed (%d/%d) even though the version was configured",
			counts.chat, counts.missing)
	}
}

// An unset version is detected, and the detection is remembered: the
// decision is made on a hot path, and a probe per call would put an extra
// round trip in front of every session.
//
// ⚠️ The assertion is that the counters STOP GROWING, not that they equal
// a number: a 5xx is retried, and v4 answers 5xx, so one round of the
// probe is already several requests. ⇒ What matters is that the LATER
// calls did not probe again.
func TestTheVersionIsDetectedOnceAndRemembered(t *testing.T) {
	c, counts := v4Bastion(t)
	if v := profileVersion(c); v != VersionV4 {
		t.Fatalf("version = %q, want %q", v, VersionV4)
	}
	first := *counts
	for i := 0; i < 3; i++ {
		if v := profileVersion(c); v != VersionV4 {
			t.Fatalf("version = %q, want %q", v, VersionV4)
		}
	}
	if *counts != first {
		t.Errorf("the deployment was probed again after the detection was remembered (%v -> %v)",
			first, *counts)
	}
}

// The one thing the version decides: whether the Chat AI delegation scheme
// exists. v4 has no chat_ai application, no X-JMS-AI-Delegation
// authentication class and no chat-ai prefix — so a session there cannot be
// delegated, and it runs with the API credential's authority instead.
func TestOnlyV4HasNoDelegationScheme(t *testing.T) {
	if capabilitiesOf(VersionV4)[CapDelegation] {
		t.Error("v4 must not claim the delegation scheme")
	}
	if !capabilitiesOf(VersionV5)[CapDelegation] {
		t.Error("v5 has the delegation scheme")
	}
}

// The CAPABILITY decides whether delegation may be used at all, and its cost
// says what the consequence is — because on a deployment without the scheme
// the operator can do nothing about it, and the sessions run wider.
//
// ⚠️ The wording lives in ONE place (the capability declaration), because it
// used to be written out separately in the two doctors, the delegation tools
// and the execution plane — and it drifted.
func TestTheDelegationCostNamesTheConsequence(t *testing.T) {
	c, _ := v4Bastion(t)
	c.versionSetting = string(VersionV4)
	if state := c.State(context.Background(), CapDelegation); state != CapabilityAbsent {
		t.Fatalf("state = %v, want absent", state)
	}
	cost := CostOf(CapDelegation)
	for _, want := range []string{"authority", "delegated"} {
		if !strings.Contains(cost, want) {
			t.Errorf("the cost %q does not mention %q", cost, want)
		}
	}
}

// A v5 deployment WITH the scheme but no secret is a CONFIGURATION problem,
// and it is a DIFFERENT question from the capability one — an operator has to
// be able to tell them apart, and one combined answer could not.
func TestTheTwoDelegationQuestionsAreSeparate(t *testing.T) {
	c, _ := v5Bastion(t)
	c.versionSetting = string(VersionV5)
	if state := c.State(context.Background(), CapDelegation); state != CapabilityPresent {
		t.Fatalf("state = %v, want present", state)
	}
	// The capability is there; the CONFIGURATION is not.
	ok, why := c.DelegationConfigured(DelegationConfig{})
	if ok {
		t.Fatal("a delegation without a secret is not configured")
	}
	if strings.Contains(why, "no Chat AI delegation scheme") {
		t.Errorf("the reason %q blames the deployment, but the scheme is there", why)
	}
}

// profileVersion reads the release out of the client's profile.
//
// The profile is what the code asks about; the release is what it reports.
func profileVersion(c *Client) Version {
	v, _ := c.Profile(context.Background()).Version()
	return v
}

// TestAnUnknownCapabilityMayStillBePresented pins the security default of
// the EXECUTION side.
//
// ⚠️ This is the decision that decides whether a session runs with the
// API credential's authority (an administrator's) or with a delegated
// user's — so it is pinned by a test, not by a comment.
//
// When the deployment could not be asked, the capability MAY be presented:
// the two ways to be wrong are "wider but working" and "narrow but broken",
// and the first is the worse one. ⇒ the credential is presented, the
// session stays narrow, and a deployment that does not have the scheme
// falls back to the slow terminal path (slow, but working).
//
// ⚠️ But it is NOT "present": the fact is still unknown, and a caller that
// must not act on an unconfirmed fact asks Present() — which is false
// here. ⇒ The two questions are separate, and this test pins BOTH.
func TestAnUnknownCapabilityMayStillBePresented(t *testing.T) {
	// Nothing is listening on that port ⇒ the probe cannot complete ⇒ the
	// profile is UNKNOWN.
	c := New(Options{
		BaseURL: "http://127.0.0.1:1",
		Credential: Credential{
			Username: "alice", Password: "s3cret",
		},
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
	})
	profile := c.Profile(context.Background())
	if profile.State(CapDelegation) != CapabilityUnknown {
		t.Fatalf("state = %v, want unknown", profile.State(CapDelegation))
	}
	if !profile.MayPresent(CapDelegation) {
		t.Error("an unknown capability must be presentable: the session has to stay narrow")
	}
	if profile.Present(CapDelegation) {
		t.Error("an unknown capability is NOT known to be present: the fact is still unknown")
	}
	if !c.MayPresent(context.Background(), CapDelegation) {
		t.Error("the same through the client's question")
	}
}

// TestTheThreeStatesAreThreeStates pins the fact layer.
//
// ⚠️ The failure this guards against is real: a doctor once told an operator
// that a deployment had no delegation scheme when the probe had merely
// failed. ⇒ The absent and the unknown must never be the same answer.
func TestTheThreeStatesAreThreeStates(t *testing.T) {
	absent := profileOf(VersionV4)
	present := profileOf(VersionV5)
	unknown := unknownProfile()

	if got := absent.State(CapDelegation); got != CapabilityAbsent {
		t.Errorf("v4 state = %v, want absent", got)
	}
	if got := present.State(CapDelegation); got != CapabilityPresent {
		t.Errorf("v5 state = %v, want present", got)
	}
	if got := unknown.State(CapDelegation); got != CapabilityUnknown {
		t.Errorf("unknown state = %v, want unknown", got)
	}

	// The two decisions differ only in the unknown case.
	for _, tc := range []struct {
		name        string
		profile     Profile
		wantPresent bool
		wantMay     bool
	}{
		{"absent", absent, false, false},
		{"present", present, true, true},
		{"unknown", unknown, false, true},
	} {
		if got := tc.profile.Present(CapDelegation); got != tc.wantPresent {
			t.Errorf("%s: Present = %v, want %v", tc.name, got, tc.wantPresent)
		}
		if got := tc.profile.MayPresent(CapDelegation); got != tc.wantMay {
			t.Errorf("%s: MayPresent = %v, want %v", tc.name, got, tc.wantMay)
		}
	}
}

// TestTheWordingNamesTheCapability checks that the sentences about a
// capability name it.
//
// ⚠️ The wording used to be written out at each call site — four places,
// two spellings — and the doctors and the delegation tools drifted apart.
// ⇒ The sentences are built from the declaration's ONE name, and this test
// pins that they do name it.
func TestTheWordingNamesTheCapability(t *testing.T) {
	name := "Chat AI delegation scheme"
	for _, tc := range []struct {
		state CapabilityState
		want  string
	}{
		{CapabilityAbsent, "this deployment has no " + name},
		{CapabilityUnknown, "it could not be established whether this deployment has the " + name},
	} {
		reason := Reason(CapDelegation, tc.state)
		if !strings.Contains(reason, tc.want) {
			t.Errorf("the reason %q does not contain %q", reason, tc.want)
		}
		if advice := Advice(CapDelegation, tc.state); advice == "" {
			t.Errorf("the %s state has no advice", tc.state)
		}
		if explain := Explain(CapDelegation, tc.state); !strings.Contains(explain, tc.want) {
			t.Errorf("the explanation %q does not contain %q", explain, tc.want)
		}
	}
	// Nothing to say about a capability that is there.
	if r := Reason(CapDelegation, CapabilityPresent); r != "" {
		t.Errorf("a present capability has a reason: %q", r)
	}
	if a := Advice(CapDelegation, CapabilityPresent); a != "" {
		t.Errorf("a present capability has advice: %q", a)
	}
}

// TestTheProbeDoesNotHoldTheProfileLock is the guard on the lock's SCOPE.
//
// The probe is a network call. Holding the client's lock across it would
// make every concurrent caller wait for it — and a sync.Mutex's waiters
// cannot be cancelled by the context, so one hung probe would stall every
// session open behind it.
//
// ⚠️ The assertion is not "the second call returned quickly" (that is a
// timing race): it is "the lock was FREE while the probe was in flight".
// That is the property that matters, and it is checked directly.
func TestTheProbeDoesNotHoldTheProfileLock(t *testing.T) {
	inProbe := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1"+string(ResChatAI) {
			close(inProbe)
			<-release
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"detail":"nope"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c := New(Options{BaseURL: srv.URL, Token: "t", HTTPClient: srv.Client()})

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = c.Profile(context.Background())
	}()

	select {
	case <-inProbe:
	case <-time.After(5 * time.Second):
		t.Fatal("the probe never reached the bastion")
	}

	// The probe is in flight. The profile lock must be free.
	acquired := make(chan struct{})
	go func() {
		_ = c.profileError() // takes profileMu
		close(acquired)
	}()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Error("the profile lock was held across the probe: every concurrent caller " +
			"waits for it, and the wait cannot be cancelled")
	}
	close(release)
	<-done
}
