// This file holds the HTTP face's server pieces the faces lifecycle
// composes on: Start (bind + serve in the background + the news line)
// and ServeOptions (the address, the auth, the news writer).
//
// ⚠️ The lifecycle itself — which face(s) run, signals, the shutdown
// budget, the subcommand dispatch — lives in pkg/faces now. It moved
// here from the services (two copies had drifted), then out again when
// the RPC face arrived: one owner, three faces.
package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oekit/concurrency/async"

	"github.com/yi-nology/jumpserver-kit/pkg/reg"
)

// ServeOptions is what the serve lifecycle needs beyond the registry: the
// address the HTTP face listens on, and where its news goes.
type ServeOptions struct {
	Options
	// Addr is the TCP address the HTTP face listens on (the configured
	// JMS_HTTP_ADDR). Empty means no HTTP face here: `serve` runs stdio
	// only, and `serve http` refuses to run at all.
	Addr string
	// Stderr is where the lifecycle writes its one line of news
	// ("listening on ...") and the HTTP face's failures. It is a writer,
	// not a logger: this package has no opinion about logging.
	Stderr io.Writer
	// ExampleAddr is the address the `serve http` refusal names when no
	// Addr was configured: each service's own documented port, not this
	// package's guess. The two planes document different ports (the
	// management one 8731, the execution one 8732), and a shared hint that
	// hard-coded either pointed operators of the other plane at the wrong
	// face. Empty omits the example.
	ExampleAddr string
}

// Start brings the HTTP face up on opts.Addr and returns the server,
// already serving in the background, plus the address it is on (a caller
// that asked for :0 needs the real port back).
func Start(r *reg.Registry, opts ServeOptions) (*http.Server, string, error) {
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	surf, err := New(r, opts.Options)
	if err != nil {
		return nil, "", err
	}
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, "", fmt.Errorf("listen on %s: %w", opts.Addr, err)
	}
	srv := &http.Server{Handler: surf.Handler()}
	// ⚠️ async.GoSafe，不是裸 `go func()`：裸 goroutine 没有 recover，
	// 里面的 panic 会把整个进程带走（连同留痕的写盘）—— 仓里的
	// TestNoBareGoroutines 会拦裸 goroutine。
	async.GoSafe(func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(opts.Stderr, "http: %v\n", err)
		}
	})
	fmt.Fprintf(opts.Stderr, "listening on http://%s  (REST /api/v1/…, MCP /mcp)\n", ln.Addr())
	return srv, ln.Addr().String(), nil
}

// serveUntilSignal is `serve http`: the face until the process is asked
// to stop, then a graceful shutdown with a 5-second deadline.
func serveUntilSignal(ctx context.Context, r *reg.Registry, opts ServeOptions) error {
	if opts.Addr == "" {
		hint := "serve http needs an address to listen on — JMS_HTTP_ADDR"
		if e := opts.ExampleAddr; e != "" {
			hint += ", e.g. " + e
		}
		return errors.New(hint)
	}
	srv, _, err := Start(r, opts)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	return nil
}
