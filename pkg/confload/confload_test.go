package confload

import (
	"strings"
	"testing"
)

// The pair disciplines are pure: an address without its token is refused,
// and each refusal names both env vars and both ways out — an operator
// wiring a server up should not have to guess which knob was meant.
func TestTheFacesRefuseAnAddressWithoutItsToken(t *testing.T) {
	if err := HTTPFaceNeedsToken("", ""); err != nil {
		t.Errorf("no HTTP face configured, but got a refusal: %v", err)
	}
	if err := HTTPFaceNeedsToken("127.0.0.1:8080", "secret"); err != nil {
		t.Errorf("a fully configured HTTP face was refused: %v", err)
	}
	err := HTTPFaceNeedsToken("127.0.0.1:8080", "")
	if err == nil {
		t.Fatal("an HTTP address without its token was accepted: there is no auth-off mode")
	}
	for _, want := range []string{"JMS_HTTP_ADDR", "JMS_HTTP_TOKEN", "openssl rand -hex 32"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}

	if err := RPCFaceNeedsToken("", ""); err != nil {
		t.Errorf("no RPC face configured, but got a refusal: %v", err)
	}
	err = RPCFaceNeedsToken("127.0.0.1:9090", "")
	if err == nil {
		t.Fatal("an RPC address without its token was accepted")
	}
	for _, want := range []string{"JMS_RPC_ADDR", "JMS_RPC_TOKEN", "no auth-off mode"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// A struct with no env vars set loads through all three stages: the happy
// path is a nil error, and the defaults stage is what fills what the
// environment left empty.
func TestFromEnvLoadsASettingsStruct(t *testing.T) {
	type settings struct {
		Name  string `env:"JMSX_TEST_CONFLOAD_NAME"`
		Count int    `env:"JMSX_TEST_CONFLOAD_COUNT" default:"3"`
	}
	s := &settings{}
	if err := FromEnv(s); err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	if s.Count != 3 {
		t.Errorf("Count = %d, want the declared default 3", s.Count)
	}
}
