package httpapi

import (
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
