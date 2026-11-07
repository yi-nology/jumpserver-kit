package jmsapi

// The redirect policy, pinned. The client refuses to follow redirects; these
// tests pin what "refuse" means for each shape a Location can take.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A same-host redirect is handed back as the raw 302 — the caller sees the
// status and the Location and decides, the client does not walk.
func TestASameHostRedirectComesBackAsA302(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/there" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("arrived"))
			return
		}
		http.Redirect(w, r, "/there", http.StatusFound)
	}))
	defer ts.Close()

	c := New(Options{BaseURL: ts.URL})
	resp, err := c.HTTP.Get(ts.URL + "/start") //nolint:noctx // test
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("status = %d, want the raw 302 (the client must not follow)", resp.StatusCode)
	}
}

// A redirect that leaves the bastion's host is an ERROR naming the target —
// not a response the caller could parse as data. (The cookie jar is the
// reason: net/http strips Authorization cross-host, but the jar would
// follow, and a credential-bearing client should not wander.)
func TestACrossHostRedirectIsRefusedWithAnError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://203.0.113.7/elsewhere", http.StatusFound)
	}))
	defer ts.Close()

	c := New(Options{BaseURL: ts.URL})
	_, err := c.HTTP.Get(ts.URL + "/start") //nolint:noctx // test
	if err == nil {
		t.Fatal("a redirect away from the bastion host was followed")
	}
	if !strings.Contains(err.Error(), "203.0.113.7") {
		t.Errorf("the error must name the target: %v", err)
	}
}

// A non-http(s) scheme is refused the same way — a Location of the form
// //otherhost/path (scheme-relative) or a bare otherhost/path must not
// become the dialer's problem.
func TestASchemeRelativeRedirectIsRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "//203.0.113.9/x")
		w.WriteHeader(http.StatusFound)
	}))
	defer ts.Close()

	c := New(Options{BaseURL: ts.URL})
	resp, err := c.HTTP.Get(ts.URL + "/start") //nolint:noctx // test
	if err == nil {
		// net/http may resolve the scheme-relative Location against the
		// request URL before CheckRedirect sees it — then it is a
		// cross-host target and MUST error; if it survives unresolved,
		// the raw 302 is also an acceptable refusal shape.
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("status = %d, want 302", resp.StatusCode)
		}
		return
	}
	if !strings.Contains(err.Error(), "refusing a redirect") {
		t.Errorf("unexpected error shape: %v", err)
	}
}

// An ordinary 200 is untouched by all of this — the refusal lives only on
// the redirect path.
func TestANormalAnswerPassesThrough(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	c := New(Options{BaseURL: ts.URL})
	resp, err := c.HTTP.Get(ts.URL + "/") //nolint:noctx // test
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}
