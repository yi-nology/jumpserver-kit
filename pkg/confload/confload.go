// Package confload is the one owner of the two services' configuration
// bootstrap: the three-stage settings read, the face-pair discipline, and
// the secret files a login may fall back to.
//
// Both services used to carry their own copy of all three, and the copies
// were byte for byte identical — which is exactly the state a copy is in
// just before it drifts. One text lives here now; a wording change is a
// change in one place.
//
// ⚠️ This package is deliberately NOT about WHAT a service reads (each
// service's settings struct is its own); it is about the mechanical part
// every read shares.
package confload

import (
	"fmt"

	"github.com/oekit/core/config"

	"github.com/yi-nology/jumpserver-kit/pkg/jmsapi"
)

// FromEnv reads a settings struct from the environment in the three
// standard stages, wrapping each failure with the stage that failed.
//
// A configuration that cannot be read is an error, not a set of defaults:
// running with the wrong settings (an unknown backend, a port that is not a
// number) is worse than not running, and "which stage broke" is the first
// question the operator asks.
func FromEnv(s any) error {
	if err := config.ApplyEnv(s); err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}
	if err := config.FillDefaults(s); err != nil {
		return fmt.Errorf("apply configuration defaults: %w", err)
	}
	if err := config.ValidateTags(s); err != nil {
		return fmt.Errorf("validate configuration: %w", err)
	}
	return nil
}

// HTTPFaceNeedsToken enforces the HTTP face's pair discipline: an address
// without its bearer token is refused at start-up.
//
// ⚠️ No "auth off": the HTTP surface answers tool calls on the operator's
// machines, so it needs a token. The refusal sentence names both ways out
// because the person reading it is wiring a server up.
func HTTPFaceNeedsToken(addr, token string) error {
	if addr != "" && token == "" {
		return fmt.Errorf("JMS_HTTP_ADDR is set but JMS_HTTP_TOKEN is not: the HTTP surface answers " +
			"tool calls, so it needs a bearer token. Generate one (openssl rand -hex 32) and set " +
			"JMS_HTTP_TOKEN, or unset JMS_HTTP_ADDR to stay on stdio only")
	}
	return nil
}

// RPCFaceNeedsToken enforces the RPC face's pair discipline, which is the
// same idea one face over: a listening port with no per-call token answers
// to whoever can reach it, and there is no auth-off mode.
func RPCFaceNeedsToken(addr, token string) error {
	if addr != "" && token == "" {
		return fmt.Errorf("JMS_RPC_ADDR is set but JMS_RPC_TOKEN is not: the RPC face answers " +
			"tool calls to whoever can reach the port, and there is no auth-off mode")
	}
	return nil
}

// LoginSecrets reads the two secrets that may live in files rather than
// the environment: the login password and the OTP secret.
//
// The password is read only when there is no token and a login name IS
// given — the token wins, because it does not expire and a long-running
// process should not have to keep a login alive. The OTP secret is
// optional: a deployment without MFA never asks for one, so its absence is
// not an error.
//
// The refusal sentence is the one copy of "the username is set but the
// password is missing": an operator who has to hunt for which file was
// looked at should not also have to wonder which wording they have.
func LoginSecrets(token, username, otp string) (password, otpOut string, err error) {
	if token == "" && username != "" {
		pw, e := jmsapi.LoadPassword()
		if e != nil {
			return "", "", fmt.Errorf("JUMPSERVER_USERNAME is set but the password is missing: %w", e)
		}
		password = pw
	}
	if otp == "" {
		if o, e := jmsapi.LoadOTPSecret(); e == nil {
			otpOut = o
		}
	}
	return password, otpOut, nil
}
