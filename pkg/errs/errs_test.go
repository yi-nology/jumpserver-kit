package errs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/oagentkit/guardx/invoke"
)

// The gate's stop must be recognised by its EXACT type: a tool error that
// happens to wrap a denial is a different thing — reading it as the gate's
// own would tell the caller "the gate stopped it" when the gate let it
// through and the tool broke.
func TestGateDenialMatchesTheExactType(t *testing.T) {
	deny := &invoke.DenyError{Stage: "confirm", Tool: "jmsx_exec", Reason: "set confirm=true"}
	if got, ok := GateDenial(deny); !ok || got.Reason != "set confirm=true" {
		t.Errorf("GateDenial(deny) = (%v, %v), want the denial itself", got, ok)
	}
	if _, ok := GateDenial(fmt.Errorf("the tool broke: %w", deny)); ok {
		t.Error("a WRAPPED denial must not read as the gate's own stop")
	}
	if _, ok := GateDenial(errors.New("ordinary failure")); ok {
		t.Error("an ordinary error must not read as the gate's stop")
	}
	if _, ok := GateDenial(nil); ok {
		t.Error("nil must not read as the gate's stop")
	}
}
