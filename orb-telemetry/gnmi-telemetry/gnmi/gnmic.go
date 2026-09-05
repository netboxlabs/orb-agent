package gnmi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	gpath "github.com/openconfig/gnmi/path"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/gnmi/value"
	gapi "github.com/openconfig/gnmic/pkg/api"
	"github.com/openconfig/gnmic/pkg/api/target"
)

// subscriptionPrefix begins the gnmic-side name of every subscription attempt
// this backend registers. Each attempt is named prefix + its own generation
// rather than one fixed name: gnmic's attemptSubscription defers
// StopSubscription(name), which cancels and deletes whatever the target holds
// under that name, so an old producer exiting after the ladder opened the next
// attempt would tear the new attempt down under a shared name. A target that
// rejects ON_CHANGE would then skip the SAMPLE rung it does support and fall
// to Get.
const subscriptionPrefix = "gnmi-telemetry"

// GnmicDialer implements Dialer using the gnmic library.
type GnmicDialer struct {
	// Logger receives the events a session raises on its own, such as a pruned
	// subscription path. Nil leaves the session on slog.Default().
	Logger *slog.Logger
}

// Dial creates a gnmic-backed Session connected to the given target.
func (d *GnmicDialer) Dial(ctx context.Context, spec TargetSpec) (Session, error) {
	opts := []gapi.TargetOption{
		gapi.Name("gnmi-telemetry"),
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
	return &gnmicSession{tg: tg, origin: spec.Origin, logger: d.Logger}, nil
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
	// subCancel cancels the context driving the active SubscribeChan producer
	// goroutine. It is set by Subscribe and invoked by Close so the producer
	// always observes cancellation, even while it is blocked in gnmic's
	// internal retry-timer wait (which only selects on this context).
	subCancel context.CancelFunc
	// subGen numbers the subscription attempts made on this session, so each
	// one registers with gnmic under a name no other attempt owns.
	subGen atomic.Uint64
	// subName is the gnmic-side name of the attempt subCancel drives, the one
	// StopSubscribe tears down. Empty until stream registers the first attempt,
	// and again once one is stopped.
	subName string
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
	// accepted caches the subscribe paths the target accepts (probed once per
	// session); nil until the first Subscribe probes them.
	accepted []string
	// probed caches the per-subscription probe verdicts for SubscribeMany, keyed
	// by origin + "|" + path; the value is whether the target accepted the path.
	probed map[string]bool
	// logger is the dialer's logger, carried so this session's own events reach
	// the deployment's handler and level; nil means slog.Default().
	logger *slog.Logger
}

// logPruned reports one subscription path the target refused.
//
// It goes through the session's logger so the configured level and handler
// apply: the package-level slog this used printed a text line on stderr at info
// level whatever the deployment asked for, which put a routine device condition
// past --log-level error and beside a JSON stream rather than in it.
func logPruned(logger *slog.Logger, sub Subscription, err error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("gnmi subscription path pruned", "path", sub.Path, "origin", sub.Origin, "error", err)
}

// acceptedPaths returns the subset of paths the target accepts, so one
// unsupported path can't make a strict target reject the whole atomic
// subscription. Fast path: a single multi-path Get — if it succeeds, every path
// is valid. Only on failure does it Get per path to prune the unsupported ones
// (reusing the same per-path tolerance as GetOnce). Result is cached for the
// session (the auto ladder re-subscribes on the same session). If probing prunes
// everything (e.g. a target that rejects Get), it falls back to the full set so
// behavior is never worse than before.
func (s *gnmicSession) acceptedPaths(ctx context.Context, paths []string) []string {
	if s.accepted != nil {
		return s.accepted
	}
	if _, err := s.getPaths(ctx, paths); err == nil {
		s.accepted = paths
		return paths
	}
	ok := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, err := s.getPaths(ctx, []string{p}); err == nil {
			ok = append(ok, p)
		}
	}
	if len(ok) == 0 {
		ok = paths
	}
	s.accepted = ok
	return ok
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
	// Only ever the name this session registered: a fixed name would be the
	// next attempt's too, and stopping it here (or from the old producer's own
	// deferred StopSubscription) would cancel the stream the ladder just
	// opened. Empty means no attempt of ours is registered.
	if s.subName != "" {
		s.tg.StopSubscription(s.subName)
		s.subName = ""
	}
}

// nextSubscriptionName returns the gnmic-side name for this session's next
// subscription attempt: the backend prefix and a generation that never
// repeats, so no two attempts on one session share a name.
func (s *gnmicSession) nextSubscriptionName() string {
	return fmt.Sprintf("%s-%d", subscriptionPrefix, s.subGen.Add(1))
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
	// Close() calling subCancel again is harmless. No attempt is registered
	// before the first subscribe, so this is safe there too.
	s.StopSubscribe()

	// A gNMI SubscribeRequest is ATOMIC: a strict target (e.g. Nokia SR Linux)
	// rejects the WHOLE multi-path subscription if any one path is unsupported
	// (an optional subtree like switched-vlan), which would sink discovery of the
	// supported paths too. Prune to the accepted paths first so one bad subtree
	// can't take down the rest.
	paths = s.acceptedPaths(ctx, paths)

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
		return nil, nil, fmt.Errorf("gnmi subscribe: build request: %w", err)
	}

	return s.stream(ctx, req)
}

// stream drives one built SubscribeRequest: it opens the gnmic subscription,
// owns the producer's context so Close() can stop it, and pumps responses into
// the returned notification and error channels. Shared by Subscribe and
// SubscribeMany, which differ only in how they build the request.
func (s *gnmicSession) stream(ctx context.Context, req *gnmiproto.SubscribeRequest) (<-chan Notification, <-chan error, error) {
	// Own context for the producer so Close() can stop it independently of the
	// caller's ctx lifetime.
	subCtx, cancel := context.WithCancel(ctx)
	s.subCancel = cancel
	s.subName = s.nextSubscriptionName()

	rawResp, rawErr := s.tg.SubscribeChan(subCtx, req, s.subName)

	notes := make(chan Notification)
	errs := make(chan error, 1)

	go func() {
		defer close(notes)
		defer close(errs)
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
					select {
					case terr, ok := <-rawErr:
						if ok && terr != nil && terr.Err != nil {
							select {
							case errs <- terr.Err:
							case <-subCtx.Done():
							}
						}
					default:
					}
					return
				}
				// SubscribeChan wraps the proto response in .Response.
				resp := wrapped.Response
				if resp == nil {
					continue
				}
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
				if terr != nil && terr.Err != nil {
					select {
					case errs <- terr.Err:
					case <-subCtx.Done():
					}
				}
				return
			}
		}
	}()

	return notes, errs, nil
}

// buildSubscribeRequest turns subscriptions into one STREAM request. Each
// path carries its own origin; an empty origin is sent bare.
func buildSubscribeRequest(encoding string, subs []Subscription) (*gnmiproto.SubscribeRequest, error) {
	opts := []gapi.GNMIOption{gapi.SubscriptionListModeSTREAM(), gapi.Encoding(encoding)}
	for _, sub := range subs {
		pathOpts := []gapi.GNMIOption{gapi.Path(withOrigin(sub.Origin, sub.Path))}
		switch sub.Mode {
		case OnChange:
			pathOpts = append(pathOpts, gapi.SubscriptionModeON_CHANGE())
		case Sample:
			pathOpts = append(pathOpts, gapi.SubscriptionModeSAMPLE())
			if sub.SampleIntervalMs > 0 {
				pathOpts = append(pathOpts, gapi.SampleInterval(time.Duration(sub.SampleIntervalMs)*time.Millisecond))
			}
		default:
			return nil, fmt.Errorf("gnmi subscribe: mode %q is not a stream mode", sub.Mode)
		}
		opts = append(opts, gapi.Subscription(pathOpts...))
	}
	req, err := gapi.NewSubscribeRequest(opts...)
	if err != nil {
		return nil, fmt.Errorf("gnmi subscribe: build request: %w", err)
	}
	return req, nil
}

// acceptedSubscriptions prunes subscriptions whose path the target rejects,
// probing each once per session with a one-path Get under its own origin
// and remembering the verdict. A subscription is atomic on a strict target,
// so one bad path would sink the rest. Get is a proxy for Subscribe support:
// a path a target streams but refuses to Get is pruned too, which is why
// each pruned path is logged with its error. s.origin is swapped around the
// probe; every session method runs on the caller's goroutine, so a caller
// that used one session from two goroutines at once would break this.
func (s *gnmicSession) acceptedSubscriptions(ctx context.Context, subs []Subscription) []Subscription {
	if s.probed == nil {
		s.probed = map[string]bool{}
	}
	kept := make([]Subscription, 0, len(subs))
	for _, sub := range subs {
		key := sub.Origin + "|" + sub.Path
		ok, seen := s.probed[key]
		if !seen {
			saved := s.origin
			s.origin = sub.Origin
			_, err := s.getPaths(ctx, []string{sub.Path})
			s.origin = saved
			ok = err == nil
			s.probed[key] = ok
			if !ok {
				logPruned(s.logger, sub, err)
			}
		}
		if ok {
			kept = append(kept, sub)
		}
	}
	if len(kept) == 0 {
		return subs
	}
	return kept
}

// SubscribeMany is Subscribe with per-subscription mode and origin.
func (s *gnmicSession) SubscribeMany(ctx context.Context, subs []Subscription) (<-chan Notification, <-chan error, error) {
	s.StopSubscribe()
	subs = s.acceptedSubscriptions(ctx, subs)
	req, err := buildSubscribeRequest(s.subEnc(), subs)
	if err != nil {
		return nil, nil, err
	}
	return s.stream(ctx, req)
}

// GetOnce performs a single gNMI Get over the given paths.
func (s *gnmicSession) GetOnce(ctx context.Context, paths []string) (Notification, error) {
	// Fast path: one Get for all paths — most targets handle a multi-path Get fine.
	if n, err := s.getPaths(ctx, paths); err == nil {
		return n, nil
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
	for _, p := range paths {
		n, err := s.getPaths(ctx, []string{p})
		if err != nil {
			lastErr = err
			continue
		}
		mergeGetResults(&result, n)
		got++
	}
	if got == 0 && lastErr != nil {
		return Notification{}, fmt.Errorf("gnmi get: all paths failed: %w", lastErr)
	}
	return result, nil
}

// mergeGetResults folds one converted notification into a merged Get result:
// updates and deletes are appended, and the greatest device timestamp wins. A
// Get response carries one notification per path, so the latest device time is
// the honest stamp for the merged snapshot; a notification the target left
// unstamped (zero) never lowers it.
func mergeGetResults(into *Notification, n Notification) {
	into.Updates = append(into.Updates, n.Updates...)
	into.Deletes = append(into.Deletes, n.Deletes...)
	if n.Timestamp > into.Timestamp {
		into.Timestamp = n.Timestamp
	}
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
		mergeGetResults(&result, convertNotification(notif))
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
	result.Timestamp = n.GetTimestamp()
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
