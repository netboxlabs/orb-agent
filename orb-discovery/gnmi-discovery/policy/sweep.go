package policy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/targets"
)

const (
	// probeConcurrency bounds probes in flight. snmp uses min(256, n), but each
	// gNMI probe holds a TLS handshake rather than a datagram, so this is lower.
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
	run := r.runStore.CreateSweepRun(r.name, r.originalHosts())

	admitted, outcome, err := r.admitTargets()
	if err != nil {
		// Report and keep going. There is no path to failing the policy itself:
		// PolicyData.State is set only from the ApplyPolicy HTTP result, the 201
		// has already returned, and a runner holds no manager reference. Exiting
		// here would also kill rescan and leave the policy permanently dead.
		r.logger.Error("sweep failed; no targets started",
			"policy", r.name, "error", err)
		r.runStore.FinishSweepRun(r.name, run.ID, RunStatusFailed, err.Error(), 0)
		return
	}

	status, reason := RunStatusCompleted, outcome.summary()
	if outcome.subscribed == 0 && outcome.admitted == 0 {
		// The operator gave a range and nothing in it answered. That is the
		// implementable form of "the policy failed": a run they can see, rather
		// than a silent policy that reports healthy and discovers nothing.
		status = RunStatusFailed
	}
	r.runStore.FinishSweepRun(r.name, run.ID, status, reason, outcome.admitted)

	// Spread the first dial once a sweep admits more than a handful. Every loop
	// dials immediately, so 200 admitted targets means 200 simultaneous TLS
	// handshakes, then 200 initial syncs landing together, then 200 concurrent
	// ingests through the one shared Diode client. The spread is deterministic
	// rather than random: it guarantees the gap instead of sampling for it.
	var gap time.Duration
	if len(admitted) > jitterThreshold {
		gap = jitterWindow / time.Duration(len(admitted))
	}

	for i, t := range admitted {
		// The state entry must exist before the loop starts, or setState is a
		// silent no-op and the target's first error is lost.
		r.mu.Lock()
		r.states[t.Host] = &targetState{}
		r.subscribed[t.Host] = struct{}{}
		r.mu.Unlock()
		r.wg.Add(1)
		go r.targetLoop(t, time.Duration(i)*gap)
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
	verdicts := make([]error, len(expanded))
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
			// host has always had.
			admitted = append(admitted, c.target)
			continue
		}
		if !probed[i] {
			continue
		}
		err := verdicts[i]
		switch {
		case isCanceled(err):
			return nil, sweepOutcome{}, err
		case admits(err):
			admitted = append(admitted, c.target)
		default:
			rejected++
			if firstReason == nil {
				firstReason = err
			}
		}
	}

	out.admitted = len(admitted)
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

// sweepOutcome is what the sweep run reports. Run has only EntityCount and
// Reason to say it with, so the counts are rendered into the reason text.
type sweepOutcome struct {
	scanned       int // addresses this policy expands to
	subscribed    int // already had a target loop, so not re-probed
	admitted      int // answered this sweep and got a loop
	rejected      int // probed and did not answer
	exampleReason string
}

func (o sweepOutcome) summary() string {
	if o.scanned == o.subscribed && o.scanned > 0 {
		return fmt.Sprintf("%d target(s) already subscribed; nothing new to probe", o.subscribed)
	}
	s := fmt.Sprintf("%d of %d address(es) answered", o.admitted, o.scanned-o.subscribed)
	if o.subscribed > 0 {
		s += fmt.Sprintf("; %d already subscribed", o.subscribed)
	}
	if o.rejected > 0 {
		s += fmt.Sprintf("; %d did not answer, e.g. %s", o.rejected, o.exampleReason)
	}
	return s
}

// originalHosts returns the host strings the operator wrote, so the sweep run
// names the CIDR itself rather than a synthesized pseudo-host.
func (r *Runner) originalHosts() []string {
	hosts := make([]string, 0, len(r.policy.Scope.Targets))
	for _, t := range r.policy.Scope.Targets {
		hosts = append(hosts, t.Host)
	}
	return hosts
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

	for _, t := range r.policy.Scope.Targets {
		addrs, err := targets.Expand(t.Host)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", t.Host, err)
		}
		// snmp's rule, matched exactly: a netbox_id survives only when the
		// operator wrote the single address itself. Any CIDR or range form,
		// /32 and 10.0.0.5-5 included, drops it — one NetBox device id cannot
		// describe a range, and a /32 is still range syntax.
		literal := len(addrs) == 1 && addrs[0] == t.Host

		for _, addr := range addrs {
			derived := t
			derived.Host = ensurePort(addr, resolvedPort(t.Port))
			if !literal {
				derived.NetboxID = nil
			}

			key := dedupeKey(derived.Host)
			if at, dup := seen[key]; dup {
				// An explicit entry beats one produced by an expansion, so a
				// device pinned inside a subnet keeps its own settings.
				if literal && !out[at].explicit {
					out[at] = candidate{target: derived, explicit: true}
					continue
				}
				r.logger.Warn("dropping duplicate target produced by expansion",
					"policy", r.name, "host", derived.Host)
				continue
			}
			seen[key] = len(out)
			out = append(out, candidate{target: derived, explicit: literal})
		}
	}
	return out, nil
}

// dedupeKey collapses two spellings of one endpoint. A hostname keeps its own
// text: Expand never resolves DNS, so a name and an address cannot be known to
// be the same device.
func dedupeKey(host string) string {
	if h, port, err := net.SplitHostPort(host); err == nil {
		if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
			return ip.String() + ":" + port
		}
		return strings.ToLower(h) + ":" + port
	}
	return strings.ToLower(host)
}

// probe asks one address whether anything is listening.
//
// It sends no credentials. gnmic attaches them as gRPC metadata on every RPC
// including Capabilities, so a credentialed sweep would spray the campus
// password across every address in the range — and with a scope-level
// skip_verify, at anything that answers.
func (r *Runner) probe(t config.Target) error {
	ctx, cancel := context.WithTimeout(r.ctx, r.policy.Config.ResolvedProbeTimeout())
	defer cancel()

	tls := t.ResolvedTLS()
	sess, err := r.dialer.Dial(ctx, gnmi.TargetSpec{
		Host:       t.Host,
		SkipVerify: tls.SkipVerify,
		Insecure:   tls.Insecure,
		Origin:     t.ResolvedOrigin(),
		CAFile:     tls.CAFile,
		CertFile:   tls.CertFile,
		KeyFile:    tls.KeyFile,
	})
	if err != nil {
		// A Dial error is a configuration fault, not a verdict: it fails
		// identically for every address, so it is reported once by the caller
		// rather than counted as N rejections.
		return err
	}
	// gnmic dials without WithBlock, so this session is live even for a dead
	// address and will reconnect in the background until closed.
	defer func() { _ = sess.Close() }()

	_, capErr := sess.Capabilities(ctx)
	return capErr
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
func admits(err error) bool {
	if err == nil {
		return true
	}
	if isCanceled(err) {
		return false
	}
	st, ok := status.FromError(err)
	if !ok {
		return false
	}
	switch st.Code() {
	case codes.DeadlineExceeded:
		// Nothing came back: a dropped packet, or a peer that accepted the TCP
		// connection and then said nothing.
		return false
	case codes.Unavailable:
		// Refused and "TLS handshake failed" share this code and differ only in
		// message. A handshake failure means a peer answered.
		return !strings.Contains(st.Message(), dialingMarker)
	default:
		// Any other code can only come from a server-sent status or an
		// HTTP-status mapping, so a peer spoke.
		return true
	}
}

// isCanceled reports whether a probe ended because the sweep was torn down, as
// happens on Stop and on a rescan tick. Those are not rejections and must not be
// counted as any.
func isCanceled(err error) bool {
	if errors.Is(err, context.Canceled) {
		return true
	}
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.Canceled
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
