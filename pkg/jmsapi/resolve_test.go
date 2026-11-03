package jmsapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The listing cache keeps the last known listing when the bastion cannot be
// reached, and that is the right thing to serve — but "missing from it" then
// means "missing as of <when it was fetched>", not "does not exist".
//
// Reported as ErrAssetNotFound it would do two wrong things at once: claim a
// machine does not exist when the truth is that the bastion is unreachable,
// and skip the terminal fallback (the one path that does not need the API).

// listingBastion serves one asset listing and can be switched to fail.
func listingBastion(t *testing.T, up *atomic.Bool) *Client {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":1,"results":[` +
			`{"id":"uuid-1","name":"box-a","address":"10.0.0.1"}]}`))
	})
	return testClient(t, h)
}

func TestAMissingReferenceInAFreshListingIsAMissingAsset(t *testing.T) {
	// The bastion answers, so the listing is fresh and its word is final:
	// the reference is wrong, and that is what the caller is told.
	var up atomic.Bool
	up.Store(true)
	c := listingBastion(t, &up)

	r := c.NewAssetResolver(5 * time.Minute)
	out, err := r.Resolve(context.Background(), c, []string{"10.0.0.1"})
	if err != nil {
		t.Fatalf("resolve of an existing asset: %v", err)
	}
	if len(out) != 1 || out[0].Address != "10.0.0.1" {
		t.Fatalf("resolve returned %+v, want the one asset", out)
	}

	_, err = r.Resolve(context.Background(), c, []string{"10.0.0.9"})
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("a missing reference in a FRESH listing must be ErrAssetNotFound, got %v", err)
	}
	if errors.Is(err, ErrListingStale) {
		t.Fatalf("a fresh listing is not stale: %v", err)
	}
}

func TestAMissingReferenceInAStaleListingIsNotAMissingAsset(t *testing.T) {
	// The bastion goes away while the listing sits in the cache. The cache
	// serves it anyway (a blip must not empty the cache), so the listing is
	// now older than its TTL — and a reference missing from it says nothing
	// about whether the asset exists.
	var up atomic.Bool
	up.Store(true)
	c := listingBastion(t, &up)

	// A TTL of a few milliseconds: the listing expires almost at once.
	r := c.NewAssetResolver(5 * time.Millisecond)
	ctx := context.Background()

	if _, err := r.Resolve(ctx, c, []string{"10.0.0.1"}); err != nil {
		t.Fatalf("resolve of an existing asset: %v", err)
	}

	// The bastion goes away, and the listing goes stale.
	up.Store(false)
	time.Sleep(30 * time.Millisecond)

	_, err := r.Resolve(ctx, c, []string{"10.0.0.9"})
	if err == nil {
		t.Fatal("a missing reference must still be an error")
	}
	if errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("a missing reference in a STALE listing must not be reported as a missing asset: %v", err)
	}
	if !errors.Is(err, ErrListingStale) {
		t.Fatalf("want ErrListingStale, got %v", err)
	}
	// ⚠️ The wording must not carry the "no such asset" text: that is
	// exactly the claim that is NOT known — the machine may well be there,
	// the bastion simply could not be reached to say. Splice the original
	// text in and a bastion outage turns into "that machine does not
	// exist", on a question the caller cannot check for itself.
	if strings.Contains(err.Error(), "no such asset") {
		t.Errorf("the stale-listing error claims the asset does not exist: %v", err)
	}
	if !strings.Contains(err.Error(), "last known listing") {
		t.Errorf("the stale-listing error does not say what it means: %v", err)
	}
}

func TestAnUnreachableBastionWithNoCachedListingStillReportsTheFailure(t *testing.T) {
	// Nothing was ever cached, so there is no stale listing to serve: the
	// failure must reach the caller as itself, not as a missing asset.
	var up atomic.Bool
	up.Store(false)
	c := listingBastion(t, &up)

	r := c.NewAssetResolver(5 * time.Minute)
	_, err := r.Resolve(context.Background(), c, []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("an unreachable bastion must be an error")
	}
	if errors.Is(err, ErrAssetNotFound) || errors.Is(err, ErrListingStale) {
		t.Fatalf("an unreachable bastion must not be reported as a missing asset: %v", err)
	}
}

// An EMPTY listing is not a STALE one.
//
// The two have opposite meanings: "stale" says the bastion could not be
// reached and the machine may well be there; "empty" says the bastion
// answered and it has no such asset. Getting that backwards turns "the
// bastion has no assets" into "the bastion is unreachable" — and the
// caller, who cannot check it for itself, is sent looking in the wrong
// place.
//
// This is the state production actually reaches: the listing's Source
// always stamps a fetch time, so an asset list with no rows is a FRESH
// listing with no rows.
func TestAnEmptyListingIsNotAStaleOne(t *testing.T) {
	// The bastion answers, and it has no assets at all.
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":0,"results":[]}`))
	}))
	defer empty.Close()
	ec := New(Options{BaseURL: empty.URL, Token: "t", HTTPClient: empty.Client()})

	r := ec.NewAssetResolver(5 * time.Minute)
	_, err := r.Resolve(context.Background(), ec, []string{"10.0.0.1"})
	if err == nil {
		t.Fatal("a missing reference must be an error")
	}
	if errors.Is(err, ErrListingStale) {
		t.Fatalf("an EMPTY listing must not be reported as a stale one: %v", err)
	}
	if !errors.Is(err, ErrAssetNotFound) {
		t.Fatalf("want ErrAssetNotFound, got %v", err)
	}
}

// A resolver with no lifetime must not cache.
//
// The cache's own zero TTL means "never expires" — the OPPOSITE of what a
// ttl of zero asks for. Setting it anyway would pin the listing forever,
// and the staleness judgement (which is what keeps an unreachable bastion
// from being reported as "no such asset") would never fire.
func TestAResolverWithNoLifetimeDoesNotCache(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"count":1,"results":[` +
			`{"id":"uuid-1","name":"box-a","address":"10.0.0.1"}]}`))
	}))
	defer srv.Close()
	c := New(Options{BaseURL: srv.URL, Token: "t", HTTPClient: srv.Client()})

	r := c.NewAssetResolver(0)
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if _, err := r.Resolve(ctx, c, []string{"10.0.0.1"}); err != nil {
			t.Fatalf("resolve %d: %v", i, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("the listing was fetched %d times, want 2: a resolver with no lifetime must not cache", got)
	}
}
