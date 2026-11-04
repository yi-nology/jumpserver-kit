package httpapi

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// The serve lifecycle is shared by both services. These tests hold up the
// two promises the services' entry points lean on: Start hands back the
// address it actually got (a caller asking for :0 needs the real port),
// and `serve http` refuses to run without one instead of quietly doing
// something else.
func TestStartHandsBackTheRealAddressAndServes(t *testing.T) {
	var records []reg.Record
	_, r := testServer(t, &records)
	srv, addr, err := Start(r, ServeOptions{Options: Options{Token: "sekrit"}, Addr: "127.0.0.1:0", Stderr: io.Discard})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()
	if strings.HasSuffix(addr, ":0") {
		t.Fatalf("拿回来的还是 :0（%q）—— 问 :0 的人要的是真端口", addr)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/api/v1/tools")
	if err != nil {
		t.Fatalf("服务起来了但没人应答：%v", err)
	}
	resp.Body.Close()
}

func TestServeHTTPWithoutAnAddressRefuses(t *testing.T) {
	var records []reg.Record
	_, r := testServer(t, &records)
	err := Run(context.Background(), r, ServeOptions{Stderr: io.Discard}, []string{"http"})
	if err == nil || !strings.Contains(err.Error(), "JMS_HTTP_ADDR") {
		t.Fatalf("serve http 不给地址就该拒，并说清 JMS_HTTP_ADDR；拿到：%v", err)
	}
	// The EXAMPLE address is the service's own documented port, passed in:
	// shared code that hard-coded one plane's port (8731) pointed
	// operators of the other plane (which documents 8732) at the wrong
	// face — the two probes on one machine would then fight over the
	// port, or worse, talk to the other plane's HTTP face.
	err = Run(context.Background(), r,
		ServeOptions{Stderr: io.Discard, ExampleAddr: "127.0.0.1:8732"}, []string{"http"})
	if err == nil || !strings.Contains(err.Error(), "127.0.0.1:8732") {
		t.Fatalf("缺地址的提示该带上服务自己的示例端口（ExampleAddr）；拿到：%v", err)
	}
}
