package secretsmgr

import (
	"context"
	"io"
	"log/slog"
)

// TestPoller is a pollingBase with a programmable fetch, for the tests of
// package secretsmgr_test that run it with a real policy manager.
type TestPoller struct{ *pollingBase }

// NewTestPoller returns a TestPoller reading secrets with fetch.
func NewTestPoller(fetch func(string) (string, error)) *TestPoller {
	b := &pollingBase{}
	b.init(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), "vault", fetch)
	return &TestPoller{b}
}

// Start does nothing: the test polls by hand.
func (p *TestPoller) Start(context.Context) error { return nil }

// Poll runs one scheduled poll.
func (p *TestPoller) Poll() { p.pollSecrets() }
