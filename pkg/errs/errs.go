// Package errs gives the server one vocabulary for failures.
//
// A failed tool call reaches the caller as a sentence, but behind that
// sentence there is a decision the machine has to make on its own: is this
// worth retrying? "HTTP 503" and "HTTP 403" both read as ERROR, yet only one
// of them can be retried with any chance of a different outcome.
//
// The taxonomy comes from guardx/toolfail, which draws the line that
// matters: retryable (a retry can produce a different outcome) and safe to
// resubmit (the server never saw the request, so a resend cannot duplicate
// a side effect) are two orthogonal dimensions. A timeout is retryable but
// NOT safe to resubmit — the server may well have executed it.
//
// This package classifies errors into that taxonomy so the HTTP client can
// retry the right ones and leave the rest alone.
package errs

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oagentkit/guardx/invoke"
	"github.com/oagentkit/guardx/toolfail"
)

// APIError is a call to the JumpServer API that came back with a status the
// server does not accept.
//
// The wording of Error() is the wording this service has always used
// ("HTTP 403 from /assets/assets/: body"), because operators grep for it.
type APIError struct {
	Status int
	Method string
	Path   string
	Body   string
	// RetryAfter is the wait the server asked for (Retry-After header), 0 when
	// it did not ask.
	RetryAfter time.Duration
}

// Error implements error.
func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d from %s: %s", e.Status, e.Path, e.Body)
}

// Class returns the failure class of err.
//
// An APIError is classified by its status code, because that is the most
// specific thing known about the failure. Anything else is handed to
// toolfail, which knows its own sentinels and self-reporting errors.
func Class(err error) toolfail.Class {
	if err == nil {
		return toolfail.ClassUnknown
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return classForStatus(apiErr.Status)
	}
	return toolfail.Classify(err)
}

// classForStatus maps an HTTP status onto a failure class.
func classForStatus(status int) toolfail.Class {
	switch {
	case status == http.StatusTooManyRequests:
		return toolfail.ClassRateLimited
	case status == http.StatusUnauthorized:
		return toolfail.ClassAuthentication
	case status == http.StatusForbidden:
		return toolfail.ClassPermissionDenied
	case status == http.StatusNotFound:
		return toolfail.ClassNotFound
	case status >= 400 && status < 500:
		return toolfail.ClassInvalidArgument
	case status >= 500:
		return toolfail.ClassTransient
	default:
		return toolfail.ClassUnknown
	}
}

// Policy returns the retry policy that applies to err.
func Policy(err error) toolfail.Policy {
	return toolfail.PolicyOf(Class(err))
}

// GateDenial returns the gate's own denial when err IS one.
//
// It is the ONE place this question is answered: pkg/reg reads it to give
// the caller the gate's own sentence, and pkg/audit reads it to keep the
// gate's stop out of the "what broke" column. Two packages, one judge.
//
// ⚠️ The type is matched EXACTLY, not with errors.As: the chain returns
// the gate's denial as it is, and a tool error that happens to WRAP one is
// a different thing — it must not be read as the gate's wording (that
// would tell the caller "the gate stopped it" when the gate let it through
// and the tool broke).
func GateDenial(err error) (*invoke.DenyError, bool) {
	deny, ok := err.(*invoke.DenyError)
	return deny, ok
}

// RetryAfter returns the wait the server asked for, if it asked for one.
//
// Only the classes whose policy surfaces a delay carry one — a 429 with a
// Retry-After header, typically. Everything else returns 0.
func RetryAfter(err error) (time.Duration, bool) {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return 0, false
	}
	if apiErr.RetryAfter > 0 {
		return apiErr.RetryAfter, true
	}
	return 0, false
}
