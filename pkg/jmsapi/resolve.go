package jmsapi

// Resolving an asset, and the accounts on it.
//
// Why this is protocol-level and not one plane's business: both planes ask the
// same question about the same records. The management plane resolves a
// reference to create or edit an asset; the execution plane resolves one to
// mint a CONNECTION TOKEN, because that token's body carries the asset's UUID
// and the account's UUID. Two implementations of "which asset did the caller
// mean" would drift, and the drift would show up as "this asset exists but
// the session says there is no such asset" — a contradiction the caller
// cannot act on.
//
// The rule the resolution follows: an EXACT match on the address, the name or
// the UUID. A prefix never silently attaches the agent to the wrong machine,
// so a near miss is reported as a near miss, with the candidates listed.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/oekit/pkg/slicex"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/oekit/concurrency/singleflight"
	"github.com/oekit/pkg/cache"
	"github.com/oekit/pkg/convert"
)

// AssetRef is a resolved asset: the three things a caller may have used to
// name it, plus the id the API needs.
type AssetRef struct {
	ID      string
	Name    string
	Address string
	// Platform is the platform name ("Linux", "Gateway", ...). It is here
	// because a caller that resolved an asset usually wants to know what it
	// found, and because the management plane's answers carry it.
	Platform string
}

// AccountRef is an account on an asset.
//
// The Username is the login name on the host; the Name is the bastion's label
// for the record. They are usually the same and are NOT always: a dynamic
// account is named "Dynamic user" and logs in as whoever is asking.
type AccountRef struct {
	ID         string
	Name       string
	Username   string
	Active     bool
	Privileged bool
}

// ErrAssetNotFound says a reference names no asset on the bastion.
//
// It is its own error because it decides something: a reference that names
// nothing is a problem with the REQUEST, and the TUI fallback would answer
// exactly the same way. An API that cannot be reached is a problem with the
// MECHANISM, and that is the case the fallback exists for. The two must not
// be filed together, or a mistyped asset name costs ten seconds of walking
// a terminal to learn what the API already said.
var ErrAssetNotFound = errors.New("no such asset")

// ErrListingStale says the reference was not found in the LAST KNOWN listing,
// because the listing could not be refreshed.
//
// It is deliberately NOT ErrAssetNotFound, and the difference decides what the
// caller does next:
//
//   - "no such asset" is a problem with the REQUEST — the terminal path would
//     answer exactly the same way, so walking the terminal to find that out
//     costs ten seconds to learn what the API already said;
//   - "the listing could not be refreshed" is a problem with the MECHANISM —
//     the bastion could not be reached, and the terminal path does not need
//     the API at all.
//
// Filing the two together turns a bastion outage into "that machine does not
// exist" — a false answer, on a question the caller cannot check, and it skips
// the fallback that exists for exactly that case.
var ErrListingStale = errors.New("the asset listing could not be refreshed")

// listing is the cached asset listing together with the moment it was fetched.
//
// The moment is what makes the two cases tellable apart. The cache serves a
// STALE listing when the bastion cannot be reached, and a reference that is
// missing from a stale listing does not mean the reference is wrong — it means
// the listing could not be refreshed. Without the timestamp the two cannot be
// told apart, and the answer to "is there such an asset?" becomes a guess.
type listing struct {
	rows      []json.RawMessage
	fetchedAt time.Time
}

// AssetResolver resolves asset references, remembering the listing for a
// while.
//
// Why it exists: resolving a reference means listing the estate. A fleet
// sweep opens one session per host, and each session resolves the asset it
// was given — so without a cache a twenty-host sweep fetches twenty
// listings of every asset on the bastion, and spends more time listing
// assets than running commands.
//
// The listing is cached for a short while. Short enough that a machine
// registered a minute ago shows up soon; long enough that one sweep pays
// for it once.
//
// It is deliberately NOT used by the management plane: that plane creates
// assets and then resolves them, and a cached listing would report a
// just-created asset as missing.
type AssetResolver struct {
	listing  *cache.LocalCache[listing]
	accounts *cache.LocalCache[[]AccountRef]
	flight   *singleflight.Flight[listing]
	// ttl is the cache's lifetime. It is kept because it is also the line
	// between "this listing is fresh" and "this listing is stale": a listing
	// older than the TTL is one the cache had to keep past its expiry, which
	// only happens when the refresh failed.
	ttl time.Duration
}

// NewAssetResolver returns a resolver that keeps the listing for ttl.
//
// A ttl of zero or less means "do not cache": every resolution fetches the
// listing again.
//
// ⚠️ The cache's own zero TTL means the OPPOSITE ("never expires"), so the
// cache is not merely mis-set at ttl<=0 — it would sit there forever, and
// the staleness judgement below (which is what keeps an unreachable bastion
// from being reported as "no such asset") would never fire. So the cache is
// bypassed outright when there is no lifetime to give it.
func (c *Client) NewAssetResolver(ttl time.Duration) *AssetResolver {
	r := &AssetResolver{flight: singleflight.New[listing](), ttl: ttl}
	if ttl <= 0 {
		return r
	}
	r.listing = cache.NewLocalCache[listing](cache.LocalConfig[listing]{
		TTL: ttl,
		// A blip must not empty the cache: the last known good listing
		// is better than no listing at all.
		//
		// ⚠️ The consequence: while the bastion stays unreachable the
		// cache keeps serving that listing, so "the bastion is down"
		// arrives as a STALE listing rather than as an error. Resolve
		// tells the two apart by the listing's age — see ErrListingStale.
		StaleIfError: true,
		Source: func(ctx context.Context, _ string) (*listing, error) {
			rows, err := c.assetRows(ctx)
			if err != nil {
				return nil, err
			}
			return &listing{rows: rows, fetchedAt: time.Now()}, nil
		},
	})
	r.accounts = cache.NewLocalCache[[]AccountRef](cache.LocalConfig[[]AccountRef]{
		TTL: ttl,
		// ⚠️ NO StaleIfError here, and the reason is the IDENTITY: this
		// list decides WHO the session runs as. A stale list can name an
		// account that has since been disabled or demoted, and the
		// session would then run as the wrong — possibly privileged —
		// one. "A session that silently runs as root when the caller
		// expected an ordinary account is the worse surprise."
		//
		// The listing above may be served stale, because a stale list of
		// ASSETS is harmless: it only says which machines exist, and
		// Resolve tells the caller when it is reading an old one
		// (ErrListingStale). An account list is a decision, not an
		// observation.
		Source: func(ctx context.Context, assetID string) (*[]AccountRef, error) {
			accts, err := c.AssetAccounts(ctx, assetID)
			if err != nil {
				return nil, err
			}
			return &accts, nil
		},
	})
	return r
}

// Resolve finds the assets the references name.
func (r *AssetResolver) Resolve(ctx context.Context, c *Client, refs []string) ([]AssetRef, error) {
	li, err := r.listingRows(ctx, c)
	if err != nil {
		return nil, err
	}
	if li == nil {
		return nil, nil
	}
	out, err := matchAssets(li.rows, refs)
	if err == nil {
		return out, nil
	}
	// A reference missing from a STALE listing is not a missing asset: the
	// listing could not be refreshed, so "missing" only means "missing as of
	// <when it was fetched>". Reported as ErrAssetNotFound it would both
	// claim a machine does not exist when the truth is that the bastion
	// could not be reached, and skip the terminal fallback — the one path
	// that does not need the API at all.
	if errors.Is(err, ErrAssetNotFound) && r.stale(li) {
		// The wording must NOT carry the "no such asset" text: that is
		// exactly the claim that is not known — the listing could not be
		// refreshed, so the machine may well be there. Splice it in and
		// a bastion outage turns into "that machine does not exist", on a
		// question the caller cannot check for itself.
		return nil, fmt.Errorf("%w: %s was not in the last known listing (fetched %s ago)",
			ErrListingStale, strings.Join(refs, ", "), time.Since(li.fetchedAt).Round(time.Second))
	}
	return nil, err
}

// stale reports whether the listing is older than the cache's lifetime.
//
// That age is only reachable when a refresh failed: a listing younger than the
// TTL was served straight out of a successful fetch.
func (r *AssetResolver) stale(li *listing) bool {
	if li == nil || r.ttl <= 0 {
		return false
	}
	return time.Since(li.fetchedAt) > r.ttl
}

// listingRows returns the cached listing, refilling it at most once even
// when several callers miss at the same time.
//
// The cache does not hold a lock while it refills, so without this a sweep of
// eight hosts would fetch the whole estate eight times.
//
// A resolver with no lifetime (ttl <= 0) has no cache at all — see
// NewAssetResolver — so it fetches every time.
func (r *AssetResolver) listingRows(ctx context.Context, c *Client) (*listing, error) {
	if r.ttl <= 0 {
		rows, err := c.assetRows(ctx)
		if err != nil {
			return nil, err
		}
		return &listing{rows: rows, fetchedAt: time.Now()}, nil
	}
	rows, err := r.flight.Do(ctx, "assets", func(ctx context.Context) (listing, error) {
		cached, err := r.listing.GetOrLoad(ctx, "all")
		if err != nil {
			return listing{}, err
		}
		if cached == nil {
			// ⚠️ Unreachable through the normal path, and that is worth
			// saying: the Source always returns a listing WITH a fetch
			// time, so an asset list with no rows is a FRESH listing with
			// no rows — and that is reported as "no such asset", which is
			// the truth (the bastion answered, and it has no such asset).
			//
			// The cache can only hand back a nil value if it holds a null
			// marker, i.e. if the Source once returned nothing. If that
			// ever happens, this listing has no fetch time, and "since
			// the zero value" reads as "years old" — a stale listing, and
			// from there a story about the bastion being unreachable that
			// nothing supports. So it is served as the stale thing it
			// would look like, and the caller is told the truth: the
			// listing could not be refreshed.
			return listing{}, fmt.Errorf("%w: the asset listing came back empty",
				ErrListingStale)
		}
		return *cached, nil
	})
	if err != nil {
		return nil, err
	}
	return &rows, nil
}

// AssetAccountsOf returns the accounts of an asset, remembering them.
//
// The account list is fetched on every session open otherwise, and a fleet
// sweep opens one session per host — so the list is fetched once per host
// per TTL instead of once per attempt.
func (r *AssetResolver) AssetAccountsOf(ctx context.Context, c *Client, assetID string) ([]AccountRef, error) {
	if r.ttl <= 0 {
		// No cache, no lifetime: every call reads the accounts afresh.
		return c.AssetAccounts(ctx, assetID)
	}
	accounts, err := r.accounts.GetOrLoad(ctx, assetID)
	if err != nil {
		return nil, err
	}
	if accounts == nil {
		return nil, nil
	}
	return *accounts, nil
}

// ResolveAssets finds every referenced asset in one page fetch.
//
// The references may be addresses, names or UUIDs, and the order of the
// result follows the order of the references, not the order of the bastion's
// listing — a caller that asked for three assets wants three answers back in
// the order it asked.
func (c *Client) ResolveAssets(ctx context.Context, refs []string) ([]AssetRef, error) {
	rows, err := c.assetRows(ctx)
	if err != nil {
		return nil, err
	}
	return matchAssets(rows, refs)
}

// matchAssets picks the referenced assets out of the listing.
func matchAssets(rows []json.RawMessage, refs []string) ([]AssetRef, error) {
	if len(refs) == 0 {
		return nil, nil
	}
	wanted := slicex.Map(refs, func(r string) string {
		return strings.ToLower(strings.TrimSpace(r))
	})

	// One pass over the bastion's rows, remembering every match: a reference
	// may name an asset in two ways, and the first hit wins.
	found := map[string]AssetRef{}
	for _, row := range rows {
		var a map[string]any
		if err := json.Unmarshal(row, &a); err != nil {
			continue
		}
		ref := AssetRef{
			ID:       convert.AnyToStr(a["id"]),
			Name:     convert.AnyToStr(a["name"]),
			Address:  convert.AnyToStr(a["address"]),
			Platform: fmt.Sprint(Nested(a, "platform", "name")),
		}
		for _, k := range []string{ref.Address, ref.Name, ref.ID} {
			if k == "" {
				continue
			}
			key := strings.ToLower(k)
			for _, w := range wanted {
				if key == w {
					if _, ok := found[w]; !ok {
						found[w] = ref
					}
				}
			}
		}
	}

	out := make([]AssetRef, 0, len(refs))
	var missing []string
	for _, w := range wanted {
		if w == "" {
			continue
		}
		ref, ok := found[w]
		if !ok {
			missing = append(missing, w)
			continue
		}
		out = append(out, ref)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		msgs := slicex.Map(missing, func(m string) string { return nearMiss(m, rows) })
		return out, fmt.Errorf("%w: %s", ErrAssetNotFound, strings.Join(msgs, "; "))
	}
	return out, nil
}

// ResolveAsset finds one asset by address, name or UUID.
func (c *Client) ResolveAsset(ctx context.Context, ref string) (AssetRef, error) {
	out, err := c.ResolveAssets(ctx, []string{ref})
	if err != nil {
		return AssetRef{}, err
	}
	if len(out) == 0 {
		return AssetRef{}, fmt.Errorf("%q matches no asset", ref)
	}
	return out[0], nil
}

// assetRows reads every asset the caller can see.
func (c *Client) assetRows(ctx context.Context) ([]json.RawMessage, error) {
	var raw json.RawMessage
	if err := c.Do(ctx, "GET", string(ResAssets), url.Values{"page_size": {"500"}}, nil, &raw); err != nil {
		return nil, err
	}
	return List(raw)
}

// nearMiss explains a reference that matched nothing.
//
// Matching is exact on purpose, so a prefix never silently attaches the agent
// to the wrong machine. But "no such asset" is a misleading answer for
// something that clearly resembles a real asset, so the candidates it failed
// to match are offered instead.
func nearMiss(ref string, rows []json.RawMessage) string {
	low := strings.ToLower(ref)
	var near []string
	for _, row := range rows {
		var a map[string]any
		if err := json.Unmarshal(row, &a); err != nil {
			continue
		}
		name, addr := convert.AnyToStr(a["name"]), convert.AnyToStr(a["address"])
		if strings.Contains(strings.ToLower(name), low) ||
			strings.Contains(strings.ToLower(addr), low) {
			near = append(near, fmt.Sprintf("%s (%s)", name, addr))
		}
	}
	if len(near) == 0 {
		return fmt.Sprintf("%q (no such asset)", ref)
	}
	if len(near) > 6 {
		near = near[:6]
	}
	sort.Strings(near)
	return fmt.Sprintf("%q matches no asset exactly; did you mean %s?", ref, strings.Join(near, ", "))
}

// AssetAccounts lists the accounts registered on an asset.
//
// It reads the asset's DETAIL, not the listing: the listing carries a count
// (accounts_amount) and the detail carries the accounts themselves, including
// the UUIDs that a connection token needs.
func (c *Client) AssetAccounts(ctx context.Context, assetID string) ([]AccountRef, error) {
	var a map[string]any
	if err := c.Get(ctx, ResAssets, assetID, &a); err != nil {
		return nil, err
	}
	var out []AccountRef
	for _, x := range AsSlice(a["accounts"]) {
		m, ok := x.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, AccountRef{
			ID:         convert.AnyToStr(m["id"]),
			Name:       convert.AnyToStr(m["name"]),
			Username:   convert.AnyToStr(m["username"]),
			Active:     fieldBoolOr(m["is_active"], true),
			Privileged: fieldBoolOr(m["privileged"], false),
		})
	}
	return out, nil
}

// fieldBoolOr reads a boolean field, falling back to a default when the field
// is absent or is not a boolean.
//
// The default matters: an account record without an explicit is_active is
// active (that is how the bastion treats it), and one without an explicit
// privileged flag is not privileged — the safe direction for the second.
func fieldBoolOr(v any, fallback bool) bool {
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}
