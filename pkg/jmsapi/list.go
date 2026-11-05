package jmsapi

// The pagination convention.
//
// The bastion's global setting leaves pagination wrapping off, so a list
// endpoint may answer with a bare array no matter how many rows it holds.
// A caller that asks for "all of them" therefore has to walk it.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/oekit/pkg/convert"
)

// ListAll reads every row of a list endpoint.
//
// It walks the collection in pages, because the API has pagination wrapping
// disabled globally and a list can be far longer than one response. Two
// details make the difference between "all rows" and "the first page, silently":
//
//   - a caller may already have written a query onto the path. Appending a
//     second '?' produces a URL whose later parameters are swallowed into the
//     first parameter's value, and the endpoint then answers with a different
//     (often empty) result set — so the query is merged, not appended.
//   - an endpoint that ignores offset would otherwise be paged forever, so a
//     row that has already been seen ends the walk.
func (c *Client) ListAll(ctx context.Context, path string) ([]map[string]any, error) {
	return c.listAll(ctx, path, nil)
}

// ListAllQuery reads every row of a list endpoint, narrowed by a query.
//
// It is ListAll with the filter given separately, which is the shape a caller
// usually has: the parameters are values, not a string to be concatenated
// onto a path.
func (c *Client) ListAllQuery(ctx context.Context, path string, query url.Values) ([]map[string]any, error) {
	return c.listAll(ctx, path, query)
}

// ListAllCounted reads every row of a list endpoint and reports the total
// the SERVER says the collection holds.
//
// ⚠️ Why the total matters: the walk stops when a page comes back SHORTER
// than the page size it asked for -- and that is only a correct stop when
// the server honoured the size. A server that CLAMPS the size (the bastion
// caps a page at MAX_PAGE_SIZE, and a deployment may configure that lower)
// answers with a full page of its own smaller size, the walk reads it as
// "the end", and the rows beyond it are never read.
//
// ⇒ A caller that filters LOCALLY must know whether it saw everything: it
// filters what it read, and if what it read was a window, the answer is
// "what happened in the window", not "what happened". Without the server's
// own count there is no way to tell the two apart.
//
// The count is the one the server reported for the FILTERED collection, so
// it is the number the local filter is measured against.
func (c *Client) ListAllCounted(ctx context.Context, path string, query url.Values) ([]map[string]any, int, error) {
	return c.listAllCounted(ctx, path, query)
}

func (c *Client) listAllCounted(ctx context.Context, path string, extra url.Values) ([]map[string]any, int, error) {
	const page = 1000
	var out []map[string]any
	seen := map[string]bool{}
	serverTotal := 0

	base, existing := path, ""
	if i := strings.Index(path, "?"); i >= 0 {
		base, existing = path[:i], path[i+1:]
	}
	prefix := url.Values{}
	if existing != "" {
		if parsed, err := url.ParseQuery(existing); err == nil {
			prefix = parsed
		}
	}
	for k, vs := range extra {
		prefix[k] = vs
	}
	for offset := 0; ; offset += page {
		q := url.Values{}
		for k, vs := range prefix {
			q[k] = vs
		}
		q.Set("page_size", convert.AnyToStr(page))
		q.Set("limit", convert.AnyToStr(page))
		if offset > 0 {
			q.Set("offset", convert.AnyToStr(offset))
		}
		var raw json.RawMessage
		if err := c.Do(ctx, "GET", base, q, nil, &raw); err != nil {
			if offset == 0 {
				q2 := url.Values{}
				for k, vs := range prefix {
					q2[k] = vs
				}
				q2.Set("page_size", convert.AnyToStr(page))
				if err := c.Do(ctx, "GET", base, q2, nil, &raw); err != nil {
					return nil, 0, err
				}
			} else {
				// A page deep in the walk failed: the rows already read are
				// a WINDOW, not the collection, and returning them as "all
				// rows" is the silently-incomplete answer this file exists
				// to prevent. The error travels with the partial count so
				// the caller can say how much was seen.
				return out, serverTotal, fmt.Errorf("page at offset %d: %w", offset, err)
			}
		}
		rows, err := List(raw)
		if err != nil {
			if offset == 0 && len(out) == 0 {
				return nil, 0, err
			}
			return out, serverTotal, fmt.Errorf("page at offset %d: %w", offset, err)
		}
		// The server's own count is the total of the collection it was
		// asked about, not of this page.
		if n := EnvelopeCount(raw); n > 0 {
			serverTotal = n
		}
		for _, r := range rows {
			var m map[string]any
			if json.Unmarshal(r, &m) != nil {
				continue
			}
			// A row that has already been seen means the endpoint is not
			// paging (or is paging past its end): stop rather than loop.
			if id, ok := m["id"].(string); ok && id != "" {
				if seen[id] {
					return out, serverTotal, nil
				}
				seen[id] = true
			}
			out = append(out, m)
		}
		// Stop when the server says there is nothing more: the count is the
		// collection's size and every row of it has been read.
		if serverTotal > 0 && len(out) >= serverTotal {
			return out, serverTotal, nil
		}
		if len(rows) < page {
			break
		}
	}
	return out, serverTotal, nil
}

func (c *Client) listAll(ctx context.Context, path string, extra url.Values) ([]map[string]any, error) {
	const page = 1000
	var out []map[string]any
	seen := map[string]bool{}

	base, existing := path, ""
	if i := strings.Index(path, "?"); i >= 0 {
		base, existing = path[:i], path[i+1:]
	}
	prefix := url.Values{}
	if existing != "" {
		if parsed, err := url.ParseQuery(existing); err == nil {
			prefix = parsed
		}
	}
	for k, vs := range extra {
		prefix[k] = vs
	}
	for offset := 0; ; offset += page {
		q := url.Values{}
		for k, vs := range prefix {
			q[k] = vs
		}
		q.Set("page_size", convert.AnyToStr(page))
		q.Set("limit", convert.AnyToStr(page))
		if offset > 0 {
			q.Set("offset", convert.AnyToStr(offset))
		}
		var raw json.RawMessage
		if err := c.Do(ctx, "GET", base, q, nil, &raw); err != nil {
			// An endpoint that rejects limit/offset still answers without them;
			// falling back keeps those collections readable rather than empty.
			if offset == 0 {
				q2 := url.Values{}
				for k, vs := range prefix {
					q2[k] = vs
				}
				q2.Set("page_size", convert.AnyToStr(page))
				if err := c.Do(ctx, "GET", base, q2, nil, &raw); err != nil {
					return nil, err
				}
			} else {
				// Mid-walk failure: partial rows are a window, not the
				// collection — say so instead of returning them as "all".
				return out, fmt.Errorf("page at offset %d: %w", offset, err)
			}
		}
		rows, err := List(raw)
		if err != nil {
			if offset == 0 && len(out) == 0 {
				return nil, err
			}
			return out, fmt.Errorf("page at offset %d: %w", offset, err)
		}
		for _, r := range rows {
			var m map[string]any
			if json.Unmarshal(r, &m) != nil {
				continue
			}
			// Guard against an endpoint that ignores offset and would otherwise
			// loop forever re-sending page 1.
			if id, ok := m["id"].(string); ok && id != "" {
				if seen[id] {
					return out, nil
				}
				seen[id] = true
			}
			out = append(out, m)
		}
		if len(rows) < page {
			break
		}
	}
	return out, nil
}

// ListIntoPath is ListAll with the destination pre-allocated for the caller.
//
// The gateway takes resources, not paths; this is the escape hatch for the
// few places that build a path themselves.
func (c *Client) ListIntoPath(ctx context.Context, path string, out *[]map[string]any) error {
	rows, err := c.ListAll(ctx, path)
	if err != nil {
		return err
	}
	*out = rows
	return nil
}
