package backend

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
)

// APIPort is the port a backend serves its API on. Configure records the
// setting and every start settles the port the new process is told, while
// the backend's API calls read it from other goroutines: the health monitor,
// policy applies, the fleet heartbeat.
//
// A port the configuration gives is used as it is. Without one, a backend
// listening beyond loopback keeps its fixed default, since whatever reaches
// it there has to know the port, and a loopback one is given a free port at
// each start, so agents sharing a host network do not collide on the
// defaults.
type APIPort struct {
	// configured and fixed are written by Configure and read by ForStart,
	// which the supervisor never runs at the same time for one backend.
	configured bool
	fixed      string
	current    atomic.Pointer[string]
}

// Configure records the port setting: port as the configuration gives it,
// empty when it gives none, for a backend listening on host, with fallback
// its fixed default. A picked port is left as it is: the backend's process
// may still be serving on it, until the next start picks another.
func (p *APIPort) Configure(port, host, fallback string) {
	p.configured = true
	p.fixed = port
	if p.fixed == "" && !LoopbackHost(host) {
		p.fixed = fallback
	}
	if p.fixed != "" {
		fixed := p.fixed
		p.current.Store(&fixed)
	}
}

// ForStart returns the port the process about to start is told, which the
// API calls use from then on: the fixed port, or one free on every address
// host resolves to, picked anew at each start since the last one may have
// been taken since.
func (p *APIPort) ForStart(ctx context.Context, host string) (string, error) {
	if !p.configured {
		return "", errors.New("the API port is not configured")
	}
	port := p.fixed
	if port == "" {
		var err error
		if port, err = PickListenPort(ctx, host); err != nil {
			return "", err
		}
	}
	p.current.Store(&port)
	return port, nil
}

// Get returns the port the API calls use: the fixed port, or the one the
// last start picked, and empty before the first start picks one.
func (p *APIPort) Get() string {
	if port := p.current.Load(); port != nil {
		return *port
	}
	return ""
}

// LoopbackHost reports whether host names only this machine: localhost, or
// a loopback IP literal.
func LoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// freePortAttempts bounds the picks PickListenPort makes: a port free on the
// first address a host resolves to can be held on another.
const freePortAttempts = 5

// PickListenPort returns a port free on every address host resolves to,
// bound and released the way ReserveListenAddr probes one. Whatever is told
// to listen there binds it after the release, so another process can take it
// meanwhile, and StartProcess's probe then refuses the start.
//
// It is a variable so a backend's test can hand its start the port a server
// standing in for the process listens on.
var PickListenPort = pickListenPort

// reserveFreePort is the reservation a pick makes; a variable so a test can
// stand in for a port held on another address. It is not ReserveListenAddr,
// which tests stub to let a start probe an address their server holds.
var reserveFreePort = reserveListenAddr

func pickListenPort(ctx context.Context, host string) (string, error) {
	var err error
	for range freePortAttempts {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		var addr string
		if addr, err = reserveFreePort(ctx, net.JoinHostPort(host, "0")); err == nil {
			_, port, splitErr := net.SplitHostPort(addr)
			return port, splitErr
		}
	}
	return "", err
}
