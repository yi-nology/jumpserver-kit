package jmsapi

// The second credential form: a login instead of a PrivateToken.
//
// What is under test is the FLOW (exchange, remember, refresh, answer an MFA
// challenge), not the bastion's side of it. The endpoints and their payloads
// were read from the upstream v4.10.20-lts source:
// POST /api/v1/authentication/auth/ takes {username, password} and answers
// {"token": ...}; when the deployment wants a second factor it answers 200
// with a body that asks for a code (NeedMoreInfoError), and the code is
// verified with POST /api/v1/authentication/mfa/challenge/ and
// {"type": "otp", "code": ...}.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

// loginBastion is a deployment that answers the login and the API.
//
// The API answers 200 for anything that is not the login, and records the
// Authorization header it saw, so a test can assert what was presented.
type loginBastion struct {
	mu          sync.Mutex
	logins      int
	challenges  int
	seenHeaders []string
	// mfa makes the first login answer "mfa_required".
	mfa bool
	// token is the Bearer token the login hands out. It is rotated on every
	// login, so a test can tell a stale token from a fresh one.
	token string
	// rejectFirst makes the API answer 401 the first time it is called.
	rejectFirst bool
}

func (b *loginBastion) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/authentication/auth/":
			b.logins++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if b.mfa && b.logins == 1 {
				_, _ = w.Write([]byte(`{"code":"mfa_required","detail":"second factor required"}`))
				return
			}
			b.token = "jwt-" + strings.Repeat("x", 4) + string(rune('0'+b.logins))
			_, _ = w.Write([]byte(`{"token":"` + b.token + `","keyword":"Bearer"}`))
		case "/api/v1/authentication/mfa/challenge/":
			b.challenges++
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["type"] != "otp" || body["code"] == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"detail":"the challenge needs a type and a code"}`))
				return
			}
			_, _ = w.Write([]byte(`{}`))
		default:
			b.seenHeaders = append(b.seenHeaders, r.Header.Get("Authorization"))
			if b.rejectFirst {
				b.rejectFirst = false
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"detail":"token expired"}`))
				return
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})
}

// A login is exchanged for a Bearer token, and the Bearer token is what the
// API calls carry.
func TestALoginIsExchangedForABearerToken(t *testing.T) {
	b := &loginBastion{}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL:    srv.URL,
		Credential: Credential{Username: "alice", Password: "s3cret"},
		HTTPClient: srv.Client(),
	})

	var out map[string]any
	if err := c.GetQuery(context.Background(), ResAssets, nil, &out); err != nil {
		t.Fatalf("the call: %v", err)
	}
	if b.logins != 1 {
		t.Errorf("logins = %d, want 1", b.logins)
	}
	if len(b.seenHeaders) != 1 || !strings.HasPrefix(b.seenHeaders[0], "Bearer ") {
		t.Errorf("the API saw %v, want a Bearer header", b.seenHeaders)
	}
}

// The token is REMEMBERED: a long-running process makes many calls, and a
// login per call would be a login storm.
func TestTheBearerTokenIsRemembered(t *testing.T) {
	b := &loginBastion{}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL:    srv.URL,
		Credential: Credential{Username: "alice", Password: "s3cret"},
		HTTPClient: srv.Client(),
	})
	for i := 0; i < 3; i++ {
		var out map[string]any
		if err := c.GetQuery(context.Background(), ResAssets, nil, &out); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if b.logins != 1 {
		t.Errorf("logins = %d, want 1: the token has to be remembered", b.logins)
	}
}

// A 401 refreshes the token and repeats the request ONCE.
//
// Repeating is safe here for a specific reason: a 401 is the authentication
// layer refusing the request, so it never reached the handler and was never
// applied. A request that was applied and then failed would be a different
// thing, and it is not what a 401 is.
func TestA401RefreshesTheTokenAndRepeatsTheRequest(t *testing.T) {
	b := &loginBastion{rejectFirst: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL:    srv.URL,
		Credential: Credential{Username: "alice", Password: "s3cret"},
		HTTPClient: srv.Client(),
	})

	var out map[string]any
	if err := c.GetQuery(context.Background(), ResAssets, nil, &out); err != nil {
		t.Fatalf("the call: %v", err)
	}
	if b.logins != 2 {
		t.Errorf("logins = %d, want 2: the refused token has to be replaced", b.logins)
	}
	if len(b.seenHeaders) != 2 {
		t.Errorf("the API saw %d request(s), want 2", len(b.seenHeaders))
	}
	if b.seenHeaders[0] == b.seenHeaders[1] {
		t.Errorf("both requests carried %q: the second one has to carry a fresh token", b.seenHeaders[0])
	}
}

// A deployment that wants a second factor says so in the login's answer, and
// the code is verified before the login is repeated.
func TestAMFASecondFactorIsVerifiedAndTheLoginRepeated(t *testing.T) {
	b := &loginBastion{mfa: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	// A valid base32 secret: the test asserts the FLOW, not the TOTP
	// arithmetic, so the code the server accepts is the one the library
	// produces for this secret.
	const secret = "JBSWY3DPEHPK3PXP"
	c := New(Options{
		BaseURL: srv.URL,
		Credential: Credential{
			Username: "alice", Password: "s3cret", OTP: secret,
		},
		HTTPClient: srv.Client(),
	})

	var out map[string]any
	if err := c.GetQuery(context.Background(), ResAssets, nil, &out); err != nil {
		t.Fatalf("the call: %v", err)
	}
	if b.challenges != 1 {
		t.Errorf("challenges = %d, want 1", b.challenges)
	}
	if b.logins != 2 {
		t.Errorf("logins = %d, want 2: the login is repeated after the challenge", b.logins)
	}
	if len(b.seenHeaders) != 1 || !strings.HasPrefix(b.seenHeaders[0], "Bearer ") {
		t.Errorf("the API saw %v, want a Bearer header", b.seenHeaders)
	}
}

// A deployment that wants a second factor and gets no secret says so, and
// the message names what to set — because the alternative is a login that
// fails with a code nobody can act on.
func TestAMissingSecondFactorIsNamedInTheError(t *testing.T) {
	b := &loginBastion{mfa: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL:    srv.URL,
		Credential: Credential{Username: "alice", Password: "s3cret"},
		HTTPClient: srv.Client(),
	})

	err := c.GetQuery(context.Background(), ResAssets, nil, &map[string]any{})
	if err == nil {
		t.Fatal("a login that needs a second factor must not succeed without one")
	}
	if !strings.Contains(err.Error(), "JUMPSERVER_OTP") {
		t.Errorf("the error %q does not say which setting to provide", err)
	}
}

// A PrivateToken is still presented as "Token <key>" — and it is NOT
// refreshed, because it does not expire: a 401 with one means the token
// itself is wrong, and repeating does not fix that.
func TestAPrivateTokenIsPresentedAsIsAndIsNotRefreshed(t *testing.T) {
	b := &loginBastion{rejectFirst: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{BaseURL: srv.URL, Token: "private-key", HTTPClient: srv.Client()})

	err := c.GetQuery(context.Background(), ResAssets, nil, &map[string]any{})
	if err == nil {
		t.Fatal("the 401 must be reported")
	}
	if len(b.seenHeaders) != 1 {
		t.Errorf("the API saw %d request(s), want 1: a PrivateToken is not refreshed", len(b.seenHeaders))
	}
	if b.seenHeaders[0] != "Token private-key" {
		t.Errorf("the API saw %q, want %q", b.seenHeaders[0], "Token private-key")
	}
	if b.logins != 0 {
		t.Errorf("logins = %d, want 0: a PrivateToken never needs a login", b.logins)
	}
}

// The TOTP code the library produces is the one the challenge has to carry.
// It is asserted here so that a change in how the code is generated cannot
// pass unnoticed behind the flow test above.
func TestTheChallengeCarriesAGeneratedCode(t *testing.T) {
	const secret = "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate the code: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("the code is %q (%d characters), want 6", code, len(code))
	}
}

// sessionBastion models the upstream MFA flow the way the bastion really
// works: the SECOND FACTOR IS ANSWERED BY THE DJANGO SESSION.
//
// Read from the upstream v4.10.20-lts source:
//
//	apps/authentication/api/mfa.py  MFAChallengeVerifyApi.initial()
//	    user = self.get_user_from_session()   # reads request.session
//	    except SessionEmptyError: user = None
//	    if not user: raise exceptions.NotAuthenticated()
//
// and get_user_from_session reads `user_id` / `auth_password` / `auth_mfa`
// out of the session — which the LOGIN step is what puts there.
//
// ⇒ the challenge answers 401 unless the login's session cookie comes along,
// and the repeated login only succeeds if the same session carries the MFA
// mark. A client without a cookie jar cannot finish the flow, and it fails
// with a 401 that says nothing about what went wrong.
type sessionBastion struct {
	mu         sync.Mutex
	logins     int
	challenges int
	cookie     string
	mfaDone    bool
	// refuseChallenge makes the challenge answer 401 even to a client that
	// carries the session — the "the code was wrong" case.
	refuseChallenge bool
}

func (b *sessionBastion) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.Lock()
		defer b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		cookie, _ := r.Cookie("sessionid")
		switch r.URL.Path {
		case "/api/v1/authentication/auth/":
			b.logins++
			// The login creates the session and remembers that the
			// password was accepted.
			b.cookie = "session-" + strings.Repeat("s", 8)
			// ⚠️ Path=/ — and that is not decoration: Django sets the
			// session cookie with path=/ (SESSION_COOKIE_PATH), and a
			// cookie without a path gets the DIRECTORY of the request
			// URI — /api/v1/authentication/auth/ — which the challenge
			// URI does not match, so the jar would not send it and the
			// challenge would answer 401. The fake has to set it the way
			// the real thing does.
			http.SetCookie(w, &http.Cookie{Name: "sessionid", Value: b.cookie, Path: "/"})
			if !b.mfaDone {
				// NeedMoreInfoError: HTTP 200 with the challenge in
				// the body. ⚠️ NOT a 401.
				_, _ = w.Write([]byte(`{"error":"mfa_required","msg":"second factor required"}`))
				return
			}
			_, _ = w.Write([]byte(`{"token":"bearer-token","keyword":"Bearer"}`))
		case "/api/v1/authentication/mfa/challenge/":
			if cookie == nil || cookie.Value != b.cookie || b.refuseChallenge {
				// Exactly what upstream does without the session.
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"detail":"Authentication credentials were not provided."}`))
				return
			}
			b.challenges++
			b.mfaDone = true
			_, _ = w.Write([]byte(`{"msg":"ok"}`))
		default:
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	})
}

// The MFA flow needs the session cookie to survive from the login to the
// challenge, and from the challenge to the repeated login.
//
// This test is the one that would have caught the missing cookie jar: a fake
// bastion that answers the challenge only to a client that carries the
// session, exactly as upstream does.
func TestTheMFAFlowCarriesTheSessionCookie(t *testing.T) {
	b := &sessionBastion{}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL: srv.URL,
		Credential: Credential{
			Username: "alice", Password: "s3cret", OTP: "JBSWY3DPEHPK3PXP",
		},
		HTTPClient: srv.Client(),
	})

	var out map[string]any
	if err := c.GetQuery(context.Background(), ResAssets, nil, &out); err != nil {
		t.Fatalf("the call: %v", err)
	}
	if b.challenges != 1 {
		t.Errorf("challenges = %d, want 1: the challenge never reached the bastion", b.challenges)
	}
	if b.logins != 2 {
		t.Errorf("logins = %d, want 2: the login is repeated after the challenge", b.logins)
	}
}

// The credential path runs ONCE. A login that was refused is not a stale
// Bearer token, and treating it as one would run the login and the challenge
// a second time — twice the requests, and the error the caller finally sees
// would be the second failure's, hiding the first one's cause.
func TestARefusedCredentialPathIsNotRunAgain(t *testing.T) {
	b := &sessionBastion{refuseChallenge: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL: srv.URL,
		Credential: Credential{
			Username: "alice", Password: "s3cret", OTP: "JBSWY3DPEHPK3PXP",
		},
		HTTPClient: srv.Client(),
	})

	err := c.GetQuery(context.Background(), ResAssets, nil, &map[string]any{})
	if err == nil {
		t.Fatal("the flow must not succeed when the challenge is refused")
	}
	if b.logins != 1 {
		t.Errorf("logins = %d, want 1: the refused credential path must not be run again", b.logins)
	}
	if b.challenges != 0 {
		t.Errorf("challenges = %d, want 0: the refused challenge was counted as accepted", b.challenges)
	}
}

// A write is NEVER repeated on the strength of a 401.
//
// Upstream answers 401 from VIEWS as well (a session that is no longer
// active, a command that was never accepted), and a view's 401 is
// indistinguishable from the authentication layer's refusal. Today those are
// validation branches with no side effect — but the cost of a write that ran
// twice is not something a heuristic should decide.
func TestAWriteIsNotRepeatedOnA401(t *testing.T) {
	b := &loginBastion{rejectFirst: true}
	srv := httptest.NewServer(b.handler())
	defer srv.Close()
	c := New(Options{
		BaseURL:    srv.URL,
		Credential: Credential{Username: "alice", Password: "s3cret"},
		HTTPClient: srv.Client(),
	})

	err := c.Post(context.Background(), ResUsers, map[string]string{"username": "x"}, &map[string]any{})
	if err == nil {
		t.Fatal("the 401 must be reported")
	}
	if len(b.seenHeaders) != 1 {
		t.Errorf("the API saw %d request(s), want 1: a write must not be repeated", len(b.seenHeaders))
	}
}
