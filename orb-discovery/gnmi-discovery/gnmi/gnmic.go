package gnmi

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	gpath "github.com/openconfig/gnmi/path"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
	gapi "github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/gnmic/pkg/api/target"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// subscriptionName prefixes the gnmic-side name of each subscription. Every
// Subscribe takes a name of its own: gnmic stops a subscription by name when
// an attempt ends, and with one shared name the end of a refused attempt
// could stop the next rung's stream.
const subscriptionName = "default"

// GnmicDialer implements Dialer using the gnmic library.
type GnmicDialer struct{}

// Dial creates a gnmic-backed Session connected to the given target.
func (d *GnmicDialer) Dial(ctx context.Context, spec TargetSpec) (Session, error) {
	opts := []gapi.TargetOption{
		gapi.Name("gnmi-discovery"),
		gapi.Address(spec.Host),
	}
	if spec.Username != "" {
		opts = append(opts, gapi.Username(spec.Username))
	}
	if spec.Password != "" {
		opts = append(opts, gapi.Password(spec.Password))
	}

	// TLS is the default (secure by default): explicit CA/cert/key supply
	// verification/mTLS material; skip_verify keeps TLS but does not verify the
	// target cert (honored INDEPENDENTLY of that material, e.g. mTLS against a
	// self-signed device cert). Plaintext requires an EXPLICIT insecure opt-in.
	// With none of these set, gnmic establishes TLS using the system root CAs.
	if spec.CAFile != "" {
		opts = append(opts, gapi.TLSCA(spec.CAFile))
	}
	if spec.CertFile != "" {
		opts = append(opts, gapi.TLSCert(spec.CertFile))
	}
	if spec.KeyFile != "" {
		opts = append(opts, gapi.TLSKey(spec.KeyFile))
	}
	if spec.SkipVerify {
		opts = append(opts, gapi.SkipVerify(true))
	}
	if spec.Insecure {
		opts = append(opts, gapi.Insecure(true))
	}

	tg, err := gapi.NewTarget(opts...)
	if err != nil {
		return nil, fmt.Errorf("gnmi dial: create target: %w", err)
	}
	if err := tg.CreateGNMIClient(ctx); err != nil {
		return nil, fmt.Errorf("gnmi dial: create client: %w", err)
	}
	return &gnmicSession{tg: tg, origin: spec.Origin, setupTimeout: spec.SetupTimeout}, nil
}

// withOrigin prefixes a gNMI request path with the session's origin
// ("openconfig:/...") so strict OpenConfig targets (e.g. Nokia SR Linux) resolve
// it against the OpenConfig schema rather than their native one. An empty origin
// yields the bare path (origin-less). gapi.Path (path.ParsePath) parses the
// "<origin>:<path>" form; request paths use [key=*] wildcards so no literal ':'
// in a key value collides with the origin separator.
func withOrigin(origin, path string) string {
	if origin == "" {
		return path
	}
	return origin + ":" + path
}

// gnmicSession wraps a gnmic Target and implements Session.
type gnmicSession struct {
	tg *target.Target
	// subName is the gnmic name of the active subscription, and subs counts
	// the Subscribes that named one.
	subName string
	subs    int
	// subCancel cancels the context driving the active SubscribeChan producer
	// goroutine. It is set by Subscribe and invoked by Close so the producer
	// always observes cancellation, even while it is blocked in gnmic's
	// internal retry-timer wait (which only selects on this context).
	subCancel context.CancelFunc
	// encoding is the request encoding negotiated from the target's advertised
	// Capabilities (set by Capabilities()); empty until then, defaulting to
	// json_ietf via enc(). Used for Get, where a leaf-path request yields a flat
	// scalar regardless of encoding.
	encoding string
	// subEncoding is the request encoding for Subscribe (set by Capabilities());
	// empty until then. It prefers PROTO because targets that serialize a STREAM
	// subscription as JSON_IETF (e.g. Nokia SR Linux) emit the subscribed leaf as
	// a nested JSON object rooted at its parent *container* path, with a
	// module-qualified first element (".../system/state" = {"hostname":"srl1"},
	// elem "openconfig-system:system") — which our flat-leaf model can't match.
	// PROTO yields one flat scalar update per leaf at its full path, exactly what
	// the model expects. Falls back to enc() via subEnc() when PROTO is absent.
	subEncoding string
	// origin is the gNMI request-path origin (e.g. "openconfig"); "" = origin-less.
	origin string
	// setupTimeout bounds the subscription-path probe; SetupTimeout when zero.
	setupTimeout time.Duration

	// mu guards the probe results below, which the subscription producer
	// prunes when it retries without the unverified paths.
	mu sync.Mutex
	// accepted caches the subscribe paths the target accepts; nil until a
	// probe reaches a verdict on every path.
	accepted []string
	// notFound are the accepted paths the target answered NotFound for.
	notFound []string
	// inconclusive are the paths the last probe kept because it got no answer.
	inconclusive []string
	// pinned are paths a refused subscription is never retried without.
	pinned []string
}

// acceptedPaths returns the subset of paths the target accepts, so one
// unsupported path can't make a strict target reject the whole atomic
// subscription. Fast path: a single multi-path Get; if it succeeds, every path
// is valid. Otherwise each path is probed alone:
//   - answered, or NotFound (modelled but empty so far): kept;
//   - a transient error: kept without a verdict, and nothing is cached, so the
//     next Subscribe on this session probes again;
//   - any other error: pruned.
//
// The probe runs under one probeDeadline and never fails the subscription. The
// per-path Gets run probeConcurrency at a time, each under its own deadline, so
// a slow device is asked about every path and one hung path cannot use up the
// phase. If it prunes everything, the full set is used, so it is never worse
// than no probe.
func (s *gnmicSession) acceptedPaths(ctx context.Context, paths []string) []string {
	s.mu.Lock()
	cached := s.accepted
	s.mu.Unlock()
	if cached != nil {
		return cached
	}
	pctx, cancel := context.WithTimeout(ctx, s.probeDeadline())
	defer cancel()
	if err := s.probeGet(pctx, paths); err == nil {
		s.setProbe(paths, nil, nil)
		return paths
	}
	errs := make([]error, len(paths))
	runBounded(len(paths), probeConcurrency, func(i int) {
		errs[i] = s.probeGet(pctx, paths[i:i+1])
	})
	ok := make([]string, 0, len(paths))
	var notFound, inconclusive []string
	for i, p := range paths {
		err := errs[i]
		switch {
		case err == nil:
			ok = append(ok, p)
		case status.Code(err) == codes.NotFound:
			ok = append(ok, p)
			notFound = append(notFound, p)
		case Transient(err):
			ok = append(ok, p)
			inconclusive = append(inconclusive, p)
		}
	}
	if len(ok) == 0 {
		ok = paths
	}
	s.setProbe(ok, notFound, inconclusive)
	return ok
}

// probeConcurrency is how many path probes run at once.
const probeConcurrency = 8

// probeGet is one probe Get, under a third of the probe's deadline so one hung
// path cannot use up the phase.
func (s *gnmicSession) probeGet(ctx context.Context, paths []string) error {
	gctx, cancel := context.WithTimeout(ctx, s.probeDeadline()/3)
	defer cancel()
	_, err := s.getPaths(gctx, paths)
	return err
}

// runBounded calls fn(0..n-1) from at most workers goroutines and waits.
func runBounded(n, workers int, fn func(i int)) {
	idx := make(chan int)
	var wg sync.WaitGroup
	for range min(n, workers) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idx {
				fn(i)
			}
		}()
	}
	for i := range n {
		idx <- i
	}
	close(idx)
	wg.Wait()
}

// setProbe records a probe's result, caching it when every path got a verdict.
func (s *gnmicSession) setProbe(accepted, notFound, inconclusive []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.notFound = notFound
	s.inconclusive = inconclusive
	if len(inconclusive) == 0 {
		s.accepted = accepted
	}
}

// probeDeadline is how long the subscription-path probe may take.
func (s *gnmicSession) probeDeadline() time.Duration {
	if s.setupTimeout > 0 {
		return s.setupTimeout
	}
	return SetupTimeout
}

// InconclusivePaths returns the paths the last probe kept without an answer.
func (s *gnmicSession) InconclusivePaths() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.inconclusive)
}

// PinPaths names paths a refused subscription is never retried without.
func (s *gnmicSession) PinPaths(paths ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pinned = append(s.pinned, paths...)
}

// retryCandidates returns the paths of a subscription a refusal may be blamed
// on: those the target answered NotFound for, other than pinned ones. A path
// whose probe got no answer is not blamed; nothing is known about it.
func (s *gnmicSession) retryCandidates(paths []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, p := range paths {
		if slices.Contains(s.notFound, p) && !slices.Contains(s.pinned, p) {
			out = append(out, p)
		}
	}
	return out
}

// pruneNotFound drops paths from this session's probe results.
func (s *gnmicSession) pruneNotFound(paths []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	drop := func(p string) bool { return slices.Contains(paths, p) }
	if s.accepted != nil {
		s.accepted = slices.DeleteFunc(slices.Clone(s.accepted), drop)
	}
	s.notFound = slices.DeleteFunc(slices.Clone(s.notFound), drop)
}

// enc returns the negotiated request encoding, defaulting to json_ietf when
// Capabilities has not run or advertised nothing usable.
func (s *gnmicSession) enc() string {
	if s.encoding != "" {
		return s.encoding
	}
	return "json_ietf"
}

// negotiateEncoding picks the request encoding from the target's advertised
// Capabilities encodings: prefer JSON_IETF (OpenConfig's canonical encoding),
// fall back to JSON (e.g. NX-OS advertises JSON only), else default to json_ietf
// as a best effort. decodeTypedValue handles both JSON_IETF and JSON responses,
// so either negotiated value yields the same decoded shape downstream.
func negotiateEncoding(advertised []string) string {
	hasJSON := false
	for _, e := range advertised {
		switch strings.ToUpper(strings.TrimSpace(e)) {
		case "JSON_IETF":
			return "json_ietf"
		case "JSON":
			hasJSON = true
		}
	}
	if hasJSON {
		return "json"
	}
	return "json_ietf"
}

// subEnc returns the negotiated Subscribe encoding, falling back to the Get
// encoding (enc()) when Capabilities has not run or advertised no PROTO support.
func (s *gnmicSession) subEnc() string {
	if s.subEncoding != "" {
		return s.subEncoding
	}
	return s.enc()
}

// negotiateSubEncoding picks the Subscribe encoding: prefer PROTO when the target
// advertises it, because a STREAM subscription serialized as JSON_IETF emits each
// leaf as a nested object at its parent container path (with a module-qualified
// first element) rather than as a flat leaf update — see the subEncoding field
// doc. PROTO gives one flat scalar per leaf at its full path, which our model
// consumes directly. When PROTO is not advertised, fall back to the Get encoding
// (JSON_IETF/JSON) negotiated for this target.
func negotiateSubEncoding(advertised []string) string {
	for _, e := range advertised {
		if strings.EqualFold(strings.TrimSpace(e), "PROTO") {
			return "proto"
		}
	}
	return negotiateEncoding(advertised)
}

// Capabilities runs the gNMI Capabilities RPC and returns a normalized result.
func (s *gnmicSession) Capabilities(ctx context.Context) (*CapabilitiesResult, error) {
	resp, err := s.tg.Capabilities(ctx)
	if err != nil {
		return nil, fmt.Errorf("gnmi capabilities: %w", err)
	}
	result := mapCapabilities(resp)
	// Negotiate the request encoding from what the target advertises so a
	// JSON-only target (e.g. NX-OS) isn't sent a JSON_IETF request it rejects.
	s.encoding = negotiateEncoding(result.Encodings)
	s.subEncoding = negotiateSubEncoding(result.Encodings)
	return result, nil
}

// StopSubscribe tears down the active subscription (cancels the producer
// goroutine + its gRPC stream and clears the gnmic-side subscription) without
// closing the session. Subscribe calls it before opening a new stream, and the
// runner calls it when switching from a SAMPLE/ON_CHANGE stream to a Get poll on
// the same connection so the prior subscription doesn't keep retrying in the
// background. Idempotent; a no-op when no subscription is active.
func (s *gnmicSession) StopSubscribe() {
	if s.subCancel != nil {
		s.subCancel()
		s.subCancel = nil
	}
	if s.subName != "" {
		s.tg.StopSubscription(s.subName)
	}
}

// Subscribe opens a gNMI STREAM subscription.
//
// We use tg.SubscribeChan (not SubscribeStreamChan): it returns buffered
// (cap-1) channels of *target.SubscribeResponse / *target.TargetError, and its
// producer goroutine's sends and retry-timer wait all select on the context we
// pass, so the producer exits cleanly once that context is cancelled. We derive
// that context from the caller's ctx and store its cancel on the session so
// Close() can stop the producer (and its gRPC connection) even when it is
// blocked mid-retry. This avoids the goroutine/connection leak that
// SubscribeStreamChan caused on reconnect (its producer looped forever on a
// bare `goto SUBSC` and only watched the parent ctx).
//
// Callers MUST call Session.Close() when the stream ends; the runner satisfies
// this via `defer sess.Close()` in runOnce.
func (s *gnmicSession) Subscribe(ctx context.Context, mode Mode, paths []string, sampleIntervalMs int) (<-chan Notification, <-chan error, error) {
	// Tear down any prior subscription on this session FIRST — before building or
	// validating the new request — so a build error can never leak the previous
	// producer goroutine + gRPC stream. The auto-fallback ladder in the runner
	// calls Subscribe twice on the same session (on_change, then sample on
	// downgrade); cancelling subCancel is the only thing that unblocks a producer
	// parked in gnmic's retry-timer wait. Cancel funcs are idempotent, so a later
	// Close() calling subCancel again is harmless. StopSubscription is a no-op for
	// an unknown name, so it is safe before any prior subscribe.
	s.StopSubscribe()

	// A gNMI SubscribeRequest is ATOMIC: a strict target (e.g. Nokia SR Linux)
	// rejects the WHOLE multi-path subscription if any one path is unsupported
	// (an optional subtree like switched-vlan), which would sink discovery of the
	// supported paths too. Prune to the accepted paths first so one bad subtree
	// can't take down the rest.
	paths = s.acceptedPaths(ctx, paths)

	req, err := s.subscribeRequest(mode, paths, sampleIntervalMs)
	if err != nil {
		return nil, nil, err
	}
	// The NotFound paths go out on trust. If the target refuses the stream
	// before answering, they are the likely cause: retry once without them.
	retryWithout := s.retryCandidates(paths)
	if len(retryWithout) == len(paths) {
		retryWithout = nil // nothing would be left to subscribe to
	}

	// Own context for the producer so Close() can stop it independently of the
	// caller's ctx lifetime.
	subCtx, cancel := context.WithCancel(ctx)
	s.subCancel = cancel
	s.subs++
	name := fmt.Sprintf("%s-%d", subscriptionName, s.subs)
	s.subName = name

	// Each attempt runs under its own context so a retry can end the first.
	attemptCtx, endAttempt := context.WithCancel(subCtx)
	rawResp, rawErr := s.tg.SubscribeChan(attemptCtx, req, name)

	notes := make(chan Notification)
	errs := make(chan error, 1)

	go func() {
		defer close(notes)
		defer close(errs)
		defer func() { endAttempt() }()
		answered := false
		// refused is the first attempt's refusal while the retry runs: if the
		// retry fails too, the dropped paths were not the cause, so they stay
		// and the caller sees the refusal as it would have without a retry.
		var refused error
		forward := func(e error) {
			if !answered && refused != nil {
				e = refused
			}
			if e == nil {
				return
			}
			select {
			case errs <- e:
			case <-subCtx.Done():
			}
		}
		for {
			select {
			case <-subCtx.Done():
				return
			case wrapped, ok := <-rawResp:
				if !ok {
					// rawResp closed — but SubscribeChan may have already queued an
					// error on rawErr that this select didn't pick (the async
					// ON_CHANGE-rejection path auto mode depends on). Drain it
					// non-blocking and forward it; otherwise streamLoop sees a clean
					// notes close, returns nil, and the target reconnects at on_change
					// forever instead of downgrading to SAMPLE/GET.
					var e error
					select {
					case terr, ok := <-rawErr:
						if ok && terr != nil {
							e = terr.Err
						}
					default:
					}
					forward(e)
					return
				}
				// SubscribeChan wraps the proto response in .Response.
				resp := wrapped.Response
				if resp == nil {
					continue
				}
				if !answered && refused != nil {
					// The retry is served, so the dropped paths were the cause.
					s.pruneNotFound(retryWithout)
				}
				answered = true
				if resp.GetSyncResponse() {
					select {
					case notes <- Notification{SyncDone: true}:
					case <-subCtx.Done():
						return
					}
					continue
				}
				if upd := resp.GetUpdate(); upd != nil {
					n := convertNotification(upd)
					select {
					case notes <- n:
					case <-subCtx.Done():
						return
					}
				}
			case terr, ok := <-rawErr:
				if !ok {
					return
				}
				// TargetError wraps the underlying error in .Err.
				if terr == nil || terr.Err == nil {
					forward(nil)
					return
				}
				if !answered && refused == nil && len(retryWithout) > 0 && !Transient(terr.Err) {
					// Wait for the refused attempt to wind down first: its
					// teardown stops the subscription by name, and would stop
					// the retry if it ran after it.
					endAttempt()
					drainSubscription(rawResp, rawErr)
					kept := slices.DeleteFunc(slices.Clone(paths), func(p string) bool { return slices.Contains(retryWithout, p) })
					retry, err := s.subscribeRequest(mode, kept, sampleIntervalMs)
					if err == nil && subCtx.Err() == nil {
						refused = terr.Err
						attemptCtx, endAttempt = context.WithCancel(subCtx)
						rawResp, rawErr = s.tg.SubscribeChan(attemptCtx, retry, name)
						continue
					}
				}
				forward(terr.Err)
				return
			}
		}
	}()

	return notes, errs, nil
}

// drainSubscription reads a SubscribeChan's channels until its producer has
// exited and closed both.
func drainSubscription(resp <-chan *target.SubscribeResponse, errs <-chan *target.TargetError) {
	for resp != nil || errs != nil {
		select {
		case _, ok := <-resp:
			if !ok {
				resp = nil
			}
		case _, ok := <-errs:
			if !ok {
				errs = nil
			}
		}
	}
}

// subscribeRequest builds a STREAM subscription over paths in mode.
func (s *gnmicSession) subscribeRequest(mode Mode, paths []string, sampleIntervalMs int) (*gnmiproto.SubscribeRequest, error) {
	subOpts := []gapi.GNMIOption{
		gapi.SubscriptionListModeSTREAM(),
		gapi.Encoding(s.subEnc()),
	}
	for _, p := range paths {
		var pathOpts []gapi.GNMIOption
		pathOpts = append(pathOpts, gapi.Path(withOrigin(s.origin, p)))
		switch mode {
		case OnChange:
			pathOpts = append(pathOpts, gapi.SubscriptionModeON_CHANGE())
		default: // Sample
			pathOpts = append(pathOpts, gapi.SubscriptionModeSAMPLE())
			if sampleIntervalMs > 0 {
				pathOpts = append(pathOpts, gapi.SampleInterval(time.Duration(sampleIntervalMs)*time.Millisecond))
			}
		}
		subOpts = append(subOpts, gapi.Subscription(pathOpts...))
	}
	req, err := gapi.NewSubscribeRequest(subOpts...)
	if err != nil {
		return nil, fmt.Errorf("gnmi subscribe: build request: %w", err)
	}
	return req, nil
}

// GetOnce performs a single gNMI Get over the given paths, returning the error
// of each path that failed.
func (s *gnmicSession) GetOnce(ctx context.Context, paths []string) (Notification, map[string]error, error) {
	// Fast path: one Get for all paths — most targets handle a multi-path Get fine.
	if n, err := s.getPaths(ctx, paths); err == nil {
		return n, nil, nil
	}
	// A multi-path Get can fail ATOMICALLY when the target returns
	// NotFound/Unimplemented for one optional subtree it doesn't model (e.g.
	// switched-vlan or network-instance VLAN/VRF leaves). Retry per path and
	// tolerate the per-path failures so one unsupported optional path doesn't
	// abort the whole discovery pass (dropping otherwise-available hostname/
	// interface data and leaving the target reconnecting with no ingest). Only
	// surface an error when EVERY path fails (a genuine transport/auth problem).
	var result Notification
	result.SyncDone = true
	got := 0
	var lastErr error
	failed := map[string]error{}
	for _, p := range paths {
		n, err := s.getPaths(ctx, []string{p})
		if err != nil {
			lastErr = err
			failed[p] = err
			continue
		}
		result.Updates = append(result.Updates, n.Updates...)
		result.Deletes = append(result.Deletes, n.Deletes...)
		got++
	}
	if got == 0 && lastErr != nil {
		return Notification{}, failed, fmt.Errorf("gnmi get: all paths failed: %w", lastErr)
	}
	return result, failed, nil
}

// getPaths issues a single gNMI Get for the given paths and merges the response
// notifications into one Notification.
func (s *gnmicSession) getPaths(ctx context.Context, paths []string) (Notification, error) {
	getOpts := []gapi.GNMIOption{
		gapi.Encoding(s.enc()),
		gapi.DataTypeALL(),
	}
	for _, p := range paths {
		getOpts = append(getOpts, gapi.Path(withOrigin(s.origin, p)))
	}
	req, err := gapi.NewGetRequest(getOpts...)
	if err != nil {
		return Notification{}, fmt.Errorf("gnmi get: build request: %w", err)
	}

	resp, err := s.tg.Get(ctx, req)
	if err != nil {
		return Notification{}, fmt.Errorf("gnmi get: %w", err)
	}

	var result Notification
	result.SyncDone = true
	for _, notif := range resp.GetNotification() {
		n := convertNotification(notif)
		result.Updates = append(result.Updates, n.Updates...)
		result.Deletes = append(result.Deletes, n.Deletes...)
	}
	return result, nil
}

// GetConfig fetches the CONFIG datastore as serialized JSON_IETF: one Get with
// DataType=CONFIG over the origin-prefixed root path "/". Returns the raw JSON
// payload of the first update carrying one. JSON_IETF (not PROTO) is requested
// because the artifact is stored as a config document, not consumed as flat
// leaves.
func (s *gnmicSession) GetConfig(ctx context.Context) ([]byte, error) {
	req, err := gapi.NewGetRequest(
		gapi.Path(withOrigin(s.origin, "/")),
		gapi.DataTypeCONFIG(),
		gapi.Encoding("json_ietf"),
	)
	if err != nil {
		return nil, fmt.Errorf("gnmi get config: build request: %w", err)
	}
	resp, err := s.tg.Get(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gnmi get config: %w", err)
	}
	for _, notif := range resp.GetNotification() {
		for _, upd := range notif.GetUpdate() {
			tv := upd.GetVal()
			if b := tv.GetJsonIetfVal(); len(b) > 0 {
				return b, nil
			}
			if b := tv.GetJsonVal(); len(b) > 0 {
				return b, nil
			}
		}
	}
	return nil, fmt.Errorf("gnmi get config: response carried no JSON config payload")
}

// Close releases the underlying gNMI connection. It first cancels the
// subscribe context so the gnmic producer goroutine exits (even if blocked in
// its internal retry-timer wait), then closes the target's gRPC connection.
func (s *gnmicSession) Close() error {
	if s.subCancel != nil {
		s.subCancel()
	}
	return s.tg.Close()
}

// vendorCanonical maps a lower-cased vendor token (as it may appear within a
// SupportedModel Organization string) to the canonical NetBox manufacturer
// surfaced as the discovered vendor. NVIDIA Cumulus may report "NVIDIA",
// "Cumulus", or "Mellanox" depending on release; the "cumulus" token resolves
// to the NVIDIA manufacturer (Cumulus is NVIDIA's NOS, not a NetBox
// manufacturer of its own), so every NVIDIA-Cumulus spelling still lines up
// with the nvidia_cumulus overlay's aliases.
var vendorCanonical = map[string]string{
	"arista":   "Arista",
	"nokia":    "Nokia",
	"cisco":    "Cisco",
	"juniper":  "Juniper",
	"nvidia":   "NVIDIA",
	"cumulus":  "NVIDIA",
	"mellanox": "Mellanox",
	"huawei":   "Huawei",
	"dell":     "Dell",
}

// vendorTokenOrder fixes the scan order over vendorCanonical so the first match
// is deterministic across runs (map iteration order is randomized).
var vendorTokenOrder = []string{"arista", "nokia", "cisco", "juniper", "nvidia", "cumulus", "mellanox", "huawei", "dell"}

// nosCanonical maps a network-OS token (as it may appear in a SupportedModel
// Organization) to its canonical name. A NOS is software that runs on hardware
// from a separate OEM, so it is detected independently of vendorCanonical and
// never becomes a device Manufacturer — it only biases profile selection.
// SONiC is the case in point: a Dell/Edgecore/etc. box runs SONiC, so the
// manufacturer stays the hardware OEM while the profile is the sonic overlay.
var nosCanonical = map[string]string{
	"sonic": "SONiC",
}

// nosTokenOrder fixes the NOS scan order (deterministic; map order is randomized).
var nosTokenOrder = []string{"sonic"}

// mapCapabilities converts a raw gNMI CapabilityResponse to our CapabilitiesResult.
func mapCapabilities(resp *gnmiproto.CapabilityResponse) *CapabilitiesResult {
	result := &CapabilitiesResult{}

	models := resp.GetSupportedModels()
	// Scan all SupportedModel Organizations for a known hardware-vendor token.
	// We collect the best (lowest index in vendorTokenOrder) match across all
	// models so a higher-priority token wins regardless of which model appears
	// first in the list. If nothing matches, Vendor stays "" — we deliberately do
	// NOT fall back to models[0]'s raw Organization, which would surface noise
	// like "OpenConfig working group" as a literal NetBox manufacturer. The
	// profile Store.Match still works because each canonical token is a substring
	// of itself (and of the overlay aliases).
	bestIdx := len(vendorTokenOrder) // sentinel: no match yet
	for _, m := range models {
		org := strings.ToLower(m.GetOrganization())
		for idx, tok := range vendorTokenOrder {
			if idx >= bestIdx {
				break // no improvement possible
			}
			if strings.Contains(org, tok) {
				bestIdx = idx
				result.Vendor = vendorCanonical[tok]
				break
			}
		}
	}
	// Network-OS detection is independent of the hardware vendor: a Dell-built
	// SONiC box matches both "dell" (Vendor/manufacturer) and "sonic" (NOS, which
	// biases profile selection). Same lowest-index-wins scan over nosTokenOrder.
	nosIdx := len(nosTokenOrder)
	for _, m := range models {
		org := strings.ToLower(m.GetOrganization())
		for idx, tok := range nosTokenOrder {
			if idx >= nosIdx {
				break
			}
			if strings.Contains(org, tok) {
				nosIdx = idx
				result.NOS = nosCanonical[tok]
				break
			}
		}
	}
	for _, m := range models {
		result.Models = append(result.Models, m.GetName())
	}

	for _, enc := range resp.GetSupportedEncodings() {
		result.Encodings = append(result.Encodings, enc.String())
	}

	return result
}

// convertNotification maps a proto *gnmi.Notification to our Notification.
func convertNotification(n *gnmiproto.Notification) Notification {
	if n == nil {
		return Notification{}
	}
	prefix := pathToString(n.GetPrefix())

	result := Notification{}
	for _, upd := range n.GetUpdate() {
		p := joinPaths(prefix, pathToString(upd.GetPath()))
		result.Updates = append(result.Updates, Update{
			Path:  p,
			Value: decodeTypedValue(upd.GetVal()),
		})
	}
	for _, del := range n.GetDelete() {
		result.Deletes = append(result.Deletes, joinPaths(prefix, pathToString(del)))
	}
	return result
}

// pathToString renders a *gnmi.Path to an absolute XPath-style string.
// Keys within each element are sorted for deterministic output.
//
// The Path.Origin field is intentionally not rendered. Profile paths are
// origin-less OpenConfig xpaths, so omitting origin lets incoming updates
// match the profile regardless of whether the target sets origin (e.g.
// "openconfig"). Prepending origin would break AllowsPath / profile matching.
func pathToString(p *gnmiproto.Path) string {
	if p == nil {
		return ""
	}
	var b strings.Builder
	for _, elem := range p.GetElem() {
		b.WriteByte('/')
		// Strip a YANG module prefix from the element name (e.g. some targets
		// render the first element of a subscribe update as "openconfig-system:system").
		// Our profile paths and AllowsPath use bare OpenConfig names, so normalize
		// "module:name" to "name" — a no-op for the already-bare names Get returns.
		name := elem.GetName()
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[i+1:]
		}
		b.WriteString(name)
		if len(elem.GetKey()) > 0 {
			keys := make([]string, 0, len(elem.GetKey()))
			for k := range elem.GetKey() {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(&b, "[%s=%s]", k, elem.GetKey()[k])
			}
		}
	}
	// Fall back to the deprecated repeated Path.element when Path.elem is absent —
	// older targets/proxies still populate it, and rendering empty here would make
	// AllowsPath drop every update. gpath.ToStrings reads the deprecated field
	// internally (so we never reference it directly); each entry is an
	// already-rendered element (e.g. "interface[name=eth0]"). prefix=false keeps
	// origin/target out, consistent with the elem rendering above.
	if len(p.GetElem()) == 0 {
		for _, e := range gpath.ToStrings(p, false) {
			b.WriteByte('/')
			b.WriteString(e)
		}
	}
	return b.String()
}

// joinPaths concatenates a prefix path and a leaf path, avoiding double slashes.
func joinPaths(prefix, path string) string {
	if prefix == "" {
		return path
	}
	if path == "" {
		return prefix
	}
	return strings.TrimSuffix(prefix, "/") + "/" + strings.TrimPrefix(path, "/")
}

// decodeTypedValue converts a *gnmi.TypedValue to a plain Go value.
func decodeTypedValue(tv *gnmiproto.TypedValue) any {
	if tv == nil {
		return nil
	}
	switch v := tv.GetValue().(type) {
	case *gnmiproto.TypedValue_StringVal:
		return v.StringVal
	case *gnmiproto.TypedValue_IntVal:
		return v.IntVal
	case *gnmiproto.TypedValue_UintVal:
		return v.UintVal
	case *gnmiproto.TypedValue_BoolVal:
		return v.BoolVal
	case *gnmiproto.TypedValue_DoubleVal:
		return v.DoubleVal
	case *gnmiproto.TypedValue_BytesVal:
		return v.BytesVal
	case *gnmiproto.TypedValue_AsciiVal:
		return v.AsciiVal
	case *gnmiproto.TypedValue_JsonIetfVal:
		var decoded any
		if err := json.Unmarshal(v.JsonIetfVal, &decoded); err == nil {
			return decoded
		}
		return string(v.JsonIetfVal)
	case *gnmiproto.TypedValue_JsonVal:
		var decoded any
		if err := json.Unmarshal(v.JsonVal, &decoded); err == nil {
			return decoded
		}
		return string(v.JsonVal)
	case *gnmiproto.TypedValue_LeaflistVal:
		// A native leaf-list (e.g. trunk-vlans when a target ignores the json_ietf
		// encoding hint): decode each element to a plain Go value, yielding []any —
		// the same shape JSON_IETF produces, so downstream leaf-list consumers
		// (e.g. mapping.expandTrunkVlans) handle both encodings uniformly.
		if v.LeaflistVal == nil {
			return nil
		}
		out := make([]any, 0, len(v.LeaflistVal.GetElement()))
		for _, el := range v.LeaflistVal.GetElement() {
			out = append(out, decodeTypedValue(el))
		}
		return out
	default:
		// Remaining scalar types — including the deprecated FloatVal/DecimalVal that
		// older targets may still send — are decoded via the openconfig value
		// helper, so we never reference the deprecated proto fields directly. Falls
		// back to the proto string repr only for a genuinely unknown type.
		if s, err := value.ToScalar(tv); err == nil {
			return s
		}
		return tv.String()
	}
}
