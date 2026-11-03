package jmsapi

// The delegation identity, looked up under concurrency.
//
// The lookup is a write, and a fleet sweep opens several sessions at the
// same time. Before the shared holder existed, each of them wrote the same
// two fields of the same config, and the race detector had it.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeBastion answers the two lookups the identity needs.
func fakeBastion(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/users/users/":
			_, _ = w.Write([]byte(`{"count":1,"results":[{"id":"user-ai","username":"ai"}]}`))
		case r.URL.Path == "/api/v1/orgs/orgs/":
			_, _ = w.Write([]byte(`{"count":1,"results":[{"id":"org-default","name":"DEFAULT"}]}`))
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(srv.Close)
	return New(Options{BaseURL: srv.URL, Token: "t", HTTPClient: srv.Client()})
}

// TestTheDelegationIdentityIsResolvedOnceUnderConcurrency is the guard on
// the race.
//
// Run it with -race: the bug it guards was a data race, not a wrong answer,
// so only the detector sees it.
func TestTheDelegationIdentityIsResolvedOnceUnderConcurrency(t *testing.T) {
	c := fakeBastion(t)
	cfg := NewDelegationConfig([]byte("secret"), "", "")

	const callers = 12
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.EnsureDelegationIdentityAs(context.Background(), cfg, "ai"); err != nil {
				t.Errorf("resolve the identity: %v", err)
			}
		}()
	}
	wg.Wait()

	userID, orgID, ok := cfg.Identity()
	if !ok {
		t.Fatal("the identity was never resolved")
	}
	if userID != "user-ai" || orgID != "org-default" {
		t.Errorf("the identity is %q/%q, want user-ai/org-default", userID, orgID)
	}
	// And the identity is now known WITHOUT the config's own fields being
	// written: those fields are shared by every session, and writing them
	// from several goroutines was the race this holder exists to prevent.
	if cfg.UserID != "" || cfg.OrgID != "" {
		t.Errorf("the shared config's fields were written: %q/%q", cfg.UserID, cfg.OrgID)
	}
	if userID, orgID, _ := cfg.Identity(); userID != "user-ai" || orgID != "org-default" {
		t.Errorf("the effective identity is %q/%q, want user-ai/org-default", userID, orgID)
	}
}

// The configured issuer and audience must win over the defaults. The
// arguments were the other way round, which made them unreachable.
func TestTheConfiguredIssuerAndAudienceAreUsed(t *testing.T) {
	c := fakeBastion(t)
	cfg := NewDelegationConfig([]byte("secret"), "user-ai", "org-default")
	cfg.Issuer = "my-issuer"
	cfg.Audience = "my-audience"
	cfg.KeyID = "my-key"

	token, err := c.MintDelegation(*cfg, DelegationCall{
		Method: "GET", Path: "/assets/assets/", OperationID: "assets.view_asset",
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	raw, err := base64RawURLDecode(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload["issuer"] != "my-issuer" {
		t.Errorf("issuer = %v, want my-issuer", payload["issuer"])
	}
	if payload["audience"] != "my-audience" {
		t.Errorf("audience = %v, want my-audience", payload["audience"])
	}
	if payload["key_id"] != "my-key" {
		t.Errorf("key_id = %v, want my-key", payload["key_id"])
	}
	if payload["user_id"] != "user-ai" || payload["org_id"] != "org-default" {
		t.Errorf("the payload carries %v/%v, want user-ai/org-default",
			payload["user_id"], payload["org_id"])
	}
}

// base64RawURLDecode decodes the payload half of a minted credential.
func base64RawURLDecode(token string) ([]byte, error) {
	encoded, _, ok := strings.Cut(token, ".")
	if !ok {
		return nil, fmt.Errorf("the credential is not in the expected shape")
	}
	return base64.RawURLEncoding.DecodeString(encoded)
}
