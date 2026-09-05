package policy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/targets"
)

const (
	// probeConcurrency bounds probes in flight. A datagram-based sweep can afford
	// far more, but each gNMI probe holds a TLS handshake, so this is lower.
	probeConcurrency = 64

	// dialingMarker is the only substring that distinguishes "nothing answered"
	// from "something answered badly" within codes.Unavailable. grpc-go carries
	// it on connection-refused, NXDOMAIN, unreachable and missing-port, and on
	// nothing else — a TLS handshake failure has already reached a peer.
	dialingMarker = "transport: Error while dialing"

	// jitterThreshold is the number of admitted targets above which the first
	// dial is spread; jitterWindow is what it is spread across.
	jitterThreshold = 8
	jitterWindow    = 30 * time.Second
)

// sweep expands this policy's targets, probes the ones that stand for more than
// a single address, and starts a target loop for each that answered.
//
// It runs in its own goroutine rather than inside StartPolicy for two reasons.
// The agent's policy POST times out after 10s and a /24 sweep takes longer, so a
// synchronous probe would mark a working policy FailedToApply and then 409 on
// every retry. And StartPolicy holds the manager lock, which GetPolicyStatuses
// also takes — the agent health-checks /status every 10s with a 2s budget and
// restarts the backend when it times out, so probing under that lock would
// restart-loop the whole process on any policy update.
func (r *Runner) sweep() {
	defer r.wg.Done()

	r.sweepOnce()

	interval := r.policy.Config.ResolvedRescanInterval()
	if interval == 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-ticker.C:
			r.sweepOnce()
		}
	}
}

// sweepOnce probes what this policy is not already subscribed to and starts a
// loop for each newcomer. It never touches a live subscription: a device that
// answered an earlier sweep is not re-probed, so a rescan cannot disturb it.
func (r *Runner) sweepOnce() {
	admitted, outcome, err := r.admitTargets()
	switch {
	case err != nil && isCanceled(err):
		// A policy DELETE cancels mid-sweep. That is the expected end of a sweep,
		// not a failure, and logging it at Error would put a red line in the log
		// on every ordinary policy removal.
		r.logger.Debug("sweep canceled", "policy", r.name)
		return
	case err != nil:
		// Report and keep going. There is no path to failing the policy itself:
		// the 201 has already returned and a runner holds no manager reference.
		// Exiting here would also kill rescan and leave the policy permanently
		// dead.
		r.logger.Error("sweep failed; no targets started",
			"policy", r.name, "error", err)
		return
	}

	r.logger.Debug("sweep", "policy", r.name, "summary", outcome.summary(),
		"unverified_credential_targets", r.unverifiedCredentialTargets())

	// Spread the first dial once a sweep admits more than a handful. Every
	// target dials immediately, so 200 admitted targets means 200 simultaneous
	// TLS handshakes, then 200 initial syncs landing together on the one shared
	// collector. The spread is deterministic rather than random: it guarantees
	// the gap instead of sampling for it.
	var gap time.Duration
	if len(admitted) > jitterThreshold {
		gap = jitterWindow / time.Duration(len(admitted))
	}

	for i, t := range admitted {
		// Marked before the goroutine starts, since this is what unsubscribed
		// filters a rescan on: a target admitted here must not be probed again.
		r.mu.Lock()
		r.subscribed[t.Host] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go func(t config.Target, d time.Duration) {
			defer r.wg.Done()
			r.subscribeAfter(t, d)
		}(t, time.Duration(i)*gap)
	}
}

// unsubscribed drops candidates this policy already has a loop for, before any
// probe is sent. Filtering afterwards would re-probe every live device on every
// rescan tick, which is the one thing a rescan must not do.
func (r *Runner) unsubscribed(in []candidate) []candidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := in[:0:0]
	for _, c := range in {
		if _, ok := r.subscribed[c.target.Host]; ok {
			continue
		}
		out = append(out, c)
	}
	return out
}

// admitTargets expands, dedupes, and probes, returning the targets worth
// subscribing to.
func (r *Runner) admitTargets() ([]config.Target, sweepOutcome, error) {
	expanded, err := r.expandTargets()
	if err != nil {
		return nil, sweepOutcome{}, err
	}
	out := sweepOutcome{scanned: len(expanded)}
	expanded = r.unsubscribed(expanded)
	out.subscribed = out.scanned - len(expanded)
	if len(expanded) == 0 {
		return nil, out, nil
	}

	// Probe concurrently: a dead address costs the full probeTimeout, so a /22
	// probed one at a time would take the better part of an hour.
	verdicts := make([]probeResult, len(expanded))
	probed := make([]bool, len(expanded))
	sem := make(chan struct{}, probeConcurrency)
	var wg sync.WaitGroup

	for i, c := range expanded {
		if c.explicit {
			continue
		}
		// Select on cancellation between items, not just at the start. Stop
		// blocks on this sweep, so without this a DELETE would wait for the
		// whole range.
		select {
		case sem <- struct{}{}:
		case <-r.ctx.Done():
			wg.Wait()
			return nil, sweepOutcome{}, r.ctx.Err()
		}
		wg.Add(1)
		go func(i int, t config.Target) {
			defer wg.Done()
			defer func() { <-sem }()
			verdicts[i] = r.probe(t)
			probed[i] = true
		}(i, c.target)
	}
	wg.Wait()

	if r.ctx.Err() != nil {
		return nil, sweepOutcome{}, r.ctx.Err()
	}

	var admitted []config.Target
	var rejected int
	var firstReason error

	for i, c := range expanded {
		if c.explicit {
			// The operator named this device. Dropping it because it happens to
			// be rebooting would regress the retry-forever behaviour a named
			// host has always had. Counted apart from the probed addresses: it
			// was never asked, so it cannot be reported as having answered.
			admitted = append(admitted, c.target)
			out.explicit++
			continue
		}
		if !probed[i] {
			continue
		}
		// Shutdown is decided by r.ctx above, never by a peer's status. Reading
		// codes.Canceled as "the policy is going away" let one device abandon the
		// whole sweep, discarding every address the other probes had admitted.
		if admits(verdicts[i]) {
			admitted = append(admitted, c.target)
			continue
		}
		rejected++
		if firstReason == nil {
			firstReason = verdicts[i].err
		}
	}

	out.admitted = len(admitted) - out.explicit
	out.rejected = rejected
	out.exampleReason = reasonText(firstReason)

	if rejected > 0 {
		// One line, not one per address: an operator who scanned a sparse /24
		// does not need 251 warnings, but must never be told a count without
		// being told why.
		r.logger.Info("target sweep complete",
			"policy", r.name,
			"admitted", out.admitted,
			"rejected", rejected,
			"example_reason", out.exampleReason)
	}
	return admitted, out, nil
}

// sweepOutcome is what one sweep did, rendered into the single Debug line the
// sweep logs when it ends.
//
// explicit is kept apart from admitted because the two are not the same claim. A
// named host is started without being probed, so folding it into admitted
// reported it as having answered — an unreachable single-host policy read as
// "1 of 1 probed address(es) answered" when nothing was probed at all.
type sweepOutcome struct {
	scanned       int // addresses this policy expands to
	subscribed    int // already had a target loop, so not re-probed
	explicit      int // named by the operator, started without a probe
	admitted      int // probed, answered, and got a loop
	rejected      int // probed and did not answer
	exampleReason string
}

// probed is derived from the verdicts rather than from scanned minus subscribed,
// which counted the addresses that skipped the probe.
func (o sweepOutcome) probed() int { return o.admitted + o.rejected }

// started is how many loops this sweep launched, however they were justified.
func (o sweepOutcome) started() int { return o.explicit + o.admitted }

// total is how many targets this policy is subscribed to once the sweep
// finishes. It is what the summary leads with, rather than the number newly
// started: a rescan tick that finds nothing new is the normal state of a healthy
// policy, and leading with 0 there would read as a policy that had stopped
// discovering anything.
func (o sweepOutcome) total() int { return o.subscribed + o.started() }

func (o sweepOutcome) summary() string {
	s := fmt.Sprintf("%d subscribed", o.total())
	if o.probed() == 0 && o.explicit == 0 {
		return s + "; no unsubscribed addresses left to probe"
	}
	if o.probed() > 0 {
		s += fmt.Sprintf("; %d of %d probed address(es) answered", o.admitted, o.probed())
	}
	if o.explicit > 0 {
		s += fmt.Sprintf("; %d named target(s) started without probing", o.explicit)
	}
	if o.rejected > 0 {
		s += fmt.Sprintf("; %d did not answer, e.g. %s", o.rejected, o.exampleReason)
	}
	return s
}

// hasRangedTarget reports whether any target stands for more than one address,
// which is what makes a sweep worth running.
func (r *Runner) hasRangedTarget() bool {
	for _, t := range r.policy.Scope.Targets {
		bare, _, _ := splitEffectivePort(t.Host, t.Port)
		if !targets.IsSingleEndpoint(bare) {
			return true
		}
	}
	return false
}

// unverifiedCredentialTargets counts the ranged targets that carry a password
// without TLS authenticating the server. Validation refuses these unless the
// policy opts in, so a non-zero count here means the operator opted in.
func (r *Runner) unverifiedCredentialTargets() int {
	n := 0
	for _, t := range r.policy.Scope.Targets {
		if t.ResolvedPassword() == "" {
			continue
		}
		tls := t.ResolvedTLS()
		if !tls.SkipVerify && !tls.Insecure {
			continue
		}
		bare, _, _ := splitEffectivePort(t.Host, t.Port)
		if targets.IsSingleEndpoint(bare) {
			continue
		}
		n++
	}
	return n
}

// candidate pairs an expanded target with whether the operator wrote it
// literally. An explicit entry skips the probe and wins any dedupe.
type candidate struct {
	target   config.Target
	explicit bool
}

func (r *Runner) expandTargets() ([]candidate, error) {
	var out []candidate
	seen := map[string]int{}
	var dropped, pinned int
	var firstDropped string

	for _, t := range r.policy.Scope.Targets {
		addrs, err := targets.Expand(t.Host)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t.Host, err)
		}
		// An id survives only when the operator wrote the single address
		// itself. Any CIDR or range form, /32 and 10.0.0.5-5 included, drops
		// it — one device id cannot describe a range, and a /32 is still range
		// syntax.
		literal := len(addrs) == 1 && addrs[0] == t.Host

		for _, addr := range addrs {
			derived := t
			derived.Host = addr
			derived.Port = resolvedPort(t.Port)
			if !literal {
				derived.ID = ""
			}

			key := dedupeKey(derived.Host)
			if at, dup := seen[key]; dup {
				// An explicit entry beats one produced by an expansion, so a
				// device pinned inside a subnet keeps its own settings — in
				// either order, since the two entries can be written either way
				// round.
				switch {
				case literal && !out[at].explicit:
					out[at] = candidate{target: derived, explicit: true}
				case out[at].explicit && !literal:
					// Pinning a device inside a subnet is the documented way to
					// give it its own credentials. It is not a mistake, and with
					// rescan on, warning would repeat it on every tick forever.
					pinned++
				default:
					// Counted, not logged per address. Overlapping ranges produce
					// one duplicate per shared address, so a policy with a few
					// equivalent subnets emitted tens of thousands of lines per
					// sweep — and with rescan on, per tick.
					dropped++
					if firstDropped == "" {
						firstDropped = derived.Host
					}
				}
				continue
			}
			seen[key] = len(out)
			out = append(out, candidate{target: derived, explicit: literal})
		}
	}

	if dropped > 0 {
		r.logger.Warn("dropping duplicate targets produced by expansion",
			"policy", r.name, "count", dropped, "example_host", firstDropped)
	}
	if pinned > 0 {
		r.logger.Debug("expansion skipped addresses pinned by their own target entries",
			"policy", r.name, "count", pinned)
	}
	return out, nil
}

// dedupeKey collapses two spellings of one device. The key is the canonical host
// alone, because a policy subscribes to a device once: everything below keys on
// the bare host, from the runner's subscribed map to the collector's loop, so a
// pinned entry inside a range wins the address and keeps its own port and
// credentials rather than becoming a second endpoint beside the derived one.
func dedupeKey(host string) string {
	return canonicalHost(host)
}

// probe asks one address whether anything is listening.
//
// It carries no identity of any kind. gnmic attaches username and password as
// gRPC metadata on every RPC including Capabilities, so a credentialed sweep
// would spray the campus password across every address in the range — and with a
// scope-level skip_verify, at anything that answers.
//
// The client certificate is withheld for the same reason, one step weaker: a
// probe is not an authenticated conversation, so presenting the agent's client
// identity to every address in a range gives it away to whatever is listening
// there. Admission never needs it. A device that requires mTLS and gets no
// client cert answers "tls: certificate required", which is a peer answering and
// is admitted — measured against a real mTLS server, not assumed.
//
// The server-side settings do go: without the CA and skip_verify the probe
// cannot complete a handshake it is otherwise entitled to complete.
func (r *Runner) probe(t config.Target) probeResult {
	ctx, cancel := context.WithTimeout(r.ctx, r.policy.Config.ResolvedProbeTimeout())
	defer cancel()

	tls := t.ResolvedTLS()
	sess, err := r.dialer.Dial(ctx, gnmi.TargetSpec{
		Host:       ensurePort(t.Host, resolvedPort(t.Port)),
		SkipVerify: tls.SkipVerify,
		Insecure:   tls.Insecure,
		Origin:     t.ResolvedOrigin(),
		CAFile:     tls.CAFile,
	})
	if err != nil {
		// A Dial error is usually a configuration fault — an unreadable CA file,
		// a malformed cert — so it fails identically for every address and lands
		// as N rejections sharing one reason. That is the useful shape: the run's
		// example_reason then names the file, rather than reporting an empty
		// subnet with no explanation.
		return probeResult{err: err}
	}
	// gnmic dials without WithBlock, so this session is live even for a dead
	// address and will reconnect in the background until closed.
	defer func() { _ = sess.Close() }()

	_, capErr := sess.Capabilities(ctx)
	// Whether OUR context ended this is the only reliable way to tell silence
	// from an answer. A gRPC code cannot: a server may send DeadlineExceeded or
	// Canceled itself, which means a peer replied, and those are the same codes
	// grpc-go produces locally when the probe's own deadline fires.
	return probeResult{err: capErr, localStop: ctx.Err() != nil}
}

// probeResult is one address's answer, plus whether the probe's own context is
// what ended the call.
type probeResult struct {
	err error
	// localStop is true when the probe's context expired or was canceled, so
	// nothing came back from the peer at all.
	localStop bool
}

// admits reports whether a probe result means something is listening.
//
// This is a deny-list, and deliberately so. An allow-list of "good" codes was
// tried and got it wrong in both directions: it missed real handshake failures
// (an mTLS device probed without a client cert, a campus of self-signed certs),
// and it denied real peer responses like ResourceExhausted from a device whose
// gNMI agent was still warming up. Only silence is absence.
//
// It also fails in the safe direction. If grpc-go ever changes the string below,
// the gate degrades to admitting everything — which is the retry-forever
// behaviour this backend had before the sweep existed — rather than to admitting
// nothing, which would report a healthy campus as empty.
func admits(res probeResult) bool {
	if res.err == nil {
		// Answered. Checked before localStop, because a deadline that fires just
		// after a successful reply must not retract it.
		return true
	}
	if res.localStop {
		// Our own deadline or cancellation ended the call, so nothing came back:
		// a dropped packet, or a peer that accepted the TCP connection and then
		// said nothing. This is the only branch that means silence, and it is
		// decided by the local context rather than by a status code — a server
		// can send DeadlineExceeded or Canceled itself, and those arrive with the
		// same codes grpc-go produces locally.
		return false
	}
	st, ok := status.FromError(res.err)
	if !ok {
		// Not a gRPC status at all: a dial or TLS configuration fault.
		return false
	}
	// Refused and "TLS handshake failed" share codes.Unavailable and differ only
	// in message. A handshake failure means a peer answered.
	if st.Code() == codes.Unavailable && strings.Contains(st.Message(), dialingMarker) {
		return false
	}
	// Anything else reached a peer, including a server-sent DeadlineExceeded or
	// Canceled.
	return true
}

// isCanceled reports whether an error is this runner's own cancellation, as
// happens on Stop and on a policy DELETE.
//
// It is applied only to errors admitTargets produces from r.ctx, never to a
// probe result. A peer is free to answer with codes.Canceled, and treating that
// as a local shutdown abandoned the sweep.
func isCanceled(err error) bool {
	return errors.Is(err, context.Canceled)
}

func reasonText(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := status.FromError(err); ok {
		return st.Message()
	}
	return err.Error()
}
