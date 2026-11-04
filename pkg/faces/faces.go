// Package faces is the ONE owner of the serve lifecycle.
package faces

//
// The subcommand is data: "" runs stdio MCP with optional rides;
// "http"/"rpc" run one face each; "all" runs HTTP+RPC as a resident
// daemon (NO stdio — nothing is on the other end of the pipe).
//
// The daemon modes compose on oekit/bootstrap (signals, per-resource
// shutdown budget) and oekit/kitex.RunServer (kitex lifecycle). The
// stdio mode keeps the shape the MCP runtime owns: r.Serve on the pipe.
//
// The two services used to carry their own copy of this lifecycle and
// it drifted; the one copy lived in pkg/httpapi. All copies are gone.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/oekit/bootstrap"
	"github.com/oekit/concurrency/async"
	oekitkitex "github.com/oekit/kitex"

	"github.com/yi-nology/jumpserver-kit/pkg/httpapi"
	"github.com/yi-nology/jumpserver-kit/pkg/reg"
	"github.com/yi-nology/jumpserver-kit/pkg/rpcapi"
)

// Options is the launch request: which faces are configured, and where
// the process writes its news.
type Options struct {
	// HTTP carries the REST/MCP-HTTP face's address and auth when the
	// caller configured one; nil (or an empty Addr) means no HTTP face.
	HTTP *httpapi.ServeOptions
	// RPC carries the kitex face's address and token likewise.
	RPC *rpcapi.ServeOptions
	// Stderr is where the lifecycle writes its news and failures.
	Stderr io.Writer
}

// mode is what Run decided to do with the subcommand.
type mode int

const (
	modeStdio mode = iota
	modeHTTP
	modeRPC
	modeAll
)

// plan turns the subcommand into a mode, refusing combinations the
// configuration cannot serve. Pure function — the dispatch table lives
// here so a mode that answers differently from its neighbour is a test
// failure, not a deployment surprise.
func plan(opts Options, args []string) (mode, error) {
	if len(args) == 0 {
		return modeStdio, nil
	}
	switch args[0] {
	case "http":
		if opts.HTTP == nil || opts.HTTP.Addr == "" {
			return 0, errors.New("serve http needs an address to listen on — JMS_HTTP_ADDR" + exampleHint(opts.HTTP))
		}
		return modeHTTP, nil
	case "rpc":
		if opts.RPC == nil || opts.RPC.Addr == "" {
			return 0, errors.New("serve rpc needs an address to listen on — JMS_RPC_ADDR")
		}
		return modeRPC, nil
	case "all":
		hasHTTP := opts.HTTP != nil && opts.HTTP.Addr != ""
		hasRPC := opts.RPC != nil && opts.RPC.Addr != ""
		if !hasHTTP && !hasRPC {
			return 0, errors.New("serve all needs a face to serve: set JMS_HTTP_ADDR and/or JMS_RPC_ADDR")
		}
		return modeAll, nil
	default:
		return 0, fmt.Errorf("unknown serve mode %q (want: nothing for stdio, or http | rpc | all)", args[0])
	}
}

// exampleHint restores the service's own documented example port to the
// http refusal (parity with the pre-faces wording).
func exampleHint(h *httpapi.ServeOptions) string {
	if h == nil || h.ExampleAddr == "" {
		return ""
	}
	return ", e.g. " + h.ExampleAddr
}

// Run is the serve subcommand's whole lifecycle, minus the service's own
// wiring (config, client, registry, trail — those stay in the service).
// It returns nil on a clean stop; the caller maps errors to its exit code.
func Run(ctx context.Context, r *reg.Registry, opts Options, args []string) error {
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	m, err := plan(opts, args)
	if err != nil {
		return err
	}
	if m == modeStdio {
		return runStdio(ctx, r, opts)
	}
	return runDaemon(ctx, r, opts, m)
}

// runStdio serves MCP over stdio until the transport closes, with any
// configured face riding along on the SAME registry. A ride whose bind
// fails fails the process — the operator asked for that face, and a
// process that is up without it would be a silent degradation.
func runStdio(ctx context.Context, r *reg.Registry, opts Options) error {
	if opts.HTTP != nil && opts.HTTP.Addr != "" {
		srv, _, err := httpapi.Start(r, withStderr(*opts.HTTP, opts.Stderr))
		if err != nil {
			return err
		}
		defer srv.Close()
	}
	if opts.RPC != nil && opts.RPC.Addr != "" {
		face, err := rpcapi.New(r, withStderrRPC(*opts.RPC, opts.Stderr))
		if err != nil {
			return err
		}
		defer func() { _ = face.Stop() }()
		face.RunBackground()
	}
	if err := r.Serve(ctx); err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// runDaemon serves the requested face(s) as a resident process: signals
// and the shutdown budget belong to oekit/bootstrap; the kitex face's
// lifecycle belongs to oekit/kitex.RunServer. The caller's context can
// stop the daemon too (a test, or a supervisor that wants a clean stop
// without a signal).
func runDaemon(ctx context.Context, r *reg.Registry, opts Options, m mode) error {
	name := "serve"
	if opts.HTTP != nil {
		name = "serve-http"
	}
	b, err := bootstrap.New(
		bootstrap.WithServiceName(name),
		bootstrap.WithShutdownTimeout(5*time.Second),
	)
	if err != nil {
		return err
	}
	err = b.Run(func(app *bootstrap.App) error {
		// The caller's context stops the daemon: a cancelled ctx
		// requests shutdown, and bootstrap runs its close sequence.
		async.GoSafe(func() {
			<-ctx.Done()
			app.RequestShutdown()
		})
		if (m == modeHTTP || m == modeAll) && opts.HTTP != nil && opts.HTTP.Addr != "" {
			srv, _, err := httpapi.Start(r, withStderr(*opts.HTTP, opts.Stderr))
			if err != nil {
				return err
			}
			app.AddResource("http", func(_ context.Context) error {
				return srv.Shutdown(context.Background())
			})
		}
		if (m == modeRPC || m == modeAll) && opts.RPC != nil && opts.RPC.Addr != "" {
			face, err := rpcapi.New(r, withStderrRPC(*opts.RPC, opts.Stderr))
			if err != nil {
				return err
			}
			oekitkitex.RunServer(app, name, face.Svr())
		}
		<-app.Context().Done()
		return nil
	})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}

// withStderr / withStderrRPC: the face's news goes where the process's
// news goes, unless the face was given its own writer. Copies first —
// mutating the caller's config is how settings leak between runs.
func withStderr(o httpapi.ServeOptions, w io.Writer) httpapi.ServeOptions {
	if o.Stderr == nil {
		o.Stderr = w
	}
	return o
}

func withStderrRPC(o rpcapi.ServeOptions, w io.Writer) rpcapi.ServeOptions {
	if o.Stderr == nil {
		o.Stderr = w
	}
	return o
}
