package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/metrics"
)

// targetHostIP returns the bare IP literal from a policy target host, suitable
// for exact-matching against discovered address strings: strips any :port,
// unbrackets an IPv6 literal, and drops an IPv6 zone id. Returns "" for a host
// with no embedded IP (e.g. a DNS name) so AssignPrimaryIP no-ops.
func targetHostIP(host string) string {
	h := host
	if hp, _, err := net.SplitHostPort(host); err == nil {
		h = hp // strips :port; unbrackets [2001:db8::1]
	}
	h = strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[") // bare bracketed IPv6 w/o port
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i] // drop zone id (fe80::1%eth0)
	}
	if net.ParseIP(h) == nil {
		return "" // DNS name / not an IP literal -> no primary-IP match
	}
	return h
}

// errEarlyStreamFailure marks a subscription that produced an error BEFORE it
// ever yielded a notification — i.e. the mode is unviable, not merely flapping.
// The real gnmic transport reports an ON_CHANGE rejection ASYNCHRONOUSLY on the
// error channel (Subscribe itself returns nil), so the auto ladder can only
// distinguish "mode unsupported" from "transient drop" by whether the stream was
// ever productive. The auto branch downgrades on this sentinel; explicit
// on_change/sample modes treat it like any other error (reconnect at same mode).
var errEarlyStreamFailure = errors.New("early stream failure")

// Runner owns the subscriptions for one policy.
type Runner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	logger   *slog.Logger
	name     string
	policy   config.Policy
	client   diode.Client
	dialer   gnmi.Dialer
	store    *mapping.Store
	runStore *RunStore
	wg       sync.WaitGroup

	backoffBase time.Duration // initial reconnect backoff; tests shorten it

	mu     sync.Mutex
	states map[string]*targetState // by host
}

type targetState struct {
	ActiveMode     string
	FallbackReason string
	LastSync       time.Time // last completed initial-sync / snapshot boundary
	LastFlush      time.Time // last successful Diode ingest
	LastError      string
	lastProfile    string // last profile selected for this host; gates the selection log
}

// NewRunner creates a runner for a policy.
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy,
	client diode.Client, dialer gnmi.Dialer, store *mapping.Store,
) (*Runner, error) {
	rctx, cancel := context.WithCancel(ctx)
	return &Runner{
		ctx: rctx, cancel: cancel, logger: logger, name: name, policy: policy,
		client: client, dialer: dialer, store: store,
		runStore:    NewRunStore(),
		backoffBase: time.Second,
		states:      map[string]*targetState{},
	}, nil
}

// Runs returns the recent flush runs for this policy (newest first), for /status.
func (r *Runner) Runs() []*Run { return r.runStore.GetRunsForPolicy(r.name) }

// Start launches one goroutine per target.
func (r *Runner) Start() {
	for _, t := range r.policy.Scope.Targets {
		r.mu.Lock()
		r.states[t.Host] = &targetState{}
		r.mu.Unlock()
		r.wg.Add(1)
		go r.targetLoop(t)
	}
}

// Stop cancels all goroutines and waits.
func (r *Runner) Stop() error {
	r.cancel()
	r.wg.Wait()
	return nil
}

func (r *Runner) setState(host string, fn func(*targetState)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.states[host]; ok {
		fn(s)
	}
}

// targetLoop owns the per-target in-memory model and debouncer for the whole
// lifetime of the target (NOT per connection). This is what lets the model
// survive reconnects (spec §9): a flap reconnects, the fresh initial sync
// re-marks the live paths, and generation pruning removes only what genuinely
// disappeared — no full re-ingest churn, no leaked debouncer goroutines.
func (r *Runner) targetLoop(t config.Target) {
	defer r.wg.Done()
	model := mapping.NewDeviceModel()
	deb := NewDebouncer(time.Duration(r.policy.Config.DebounceMs) * time.Millisecond)
	defer deb.Stop()

	metrics.GetTargetsActive().Add(r.ctx, 1)
	defer metrics.GetTargetsActive().Add(r.ctx, -1)

	// Single-flight, ctx-aware ingest retry (H-5): exactly one timer per target.
	// A failed flush Reset()s it (replacing any pending fire, never stacking);
	// it fires deb.Trigger only while the runner is still running, and is
	// stopped on shutdown so no flush happens post-cancel.
	retry := time.AfterFunc(time.Hour, func() {
		if r.ctx.Err() == nil {
			deb.Trigger()
		}
	})
	retry.Stop()
	defer retry.Stop()

	backoff := r.backoffBase
	first := true
	for {
		if r.ctx.Err() != nil {
			return
		}
		if !first {
			metrics.GetReconnects().Add(r.ctx, 1)
		}
		first = false
		err := r.runOnce(t, model, deb, retry)
		if r.ctx.Err() != nil {
			return
		}
		if err != nil {
			r.logger.Warn("gnmi target loop error", "policy", r.name, "host", t.Host, "error", err)
			r.setState(t.Host, func(s *targetState) { s.LastError = err.Error() })
		}
		select {
		case <-time.After(backoff):
		case <-r.ctx.Done():
			return
		}
		backoff = time.Duration(math.Min(float64(backoff*2), float64(30*time.Second)))
	}
}

// runOnce dials, selects a profile, resolves the delivery mode, and runs ONE
// connection's worth of delivery. It returns when the connection ends (error or
// ctx). In auto mode it walks the fallback ladder on a subscribe-time rejection
// OR an early stream failure (a stream that errors before yielding any data —
// how the real gnmic transport reports an async ON_CHANGE rejection). A stream
// error AFTER data (a productive flap) is returned as-is so targetLoop reconnects
// and re-attempts the preferred mode — a transient ON_CHANGE drop never
// permanently demotes the target. Explicit on_change/sample modes never
// auto-downgrade; they return the error to reconnect at the same mode.
func (r *Runner) runOnce(t config.Target, model *mapping.DeviceModel, deb *Debouncer, retry *time.Timer) error {
	sess, err := r.dialer.Dial(r.ctx, gnmi.TargetSpec{
		Host: t.Host, Username: t.Username, Password: t.Password,
		SkipVerify: t.TLS.SkipVerify, Insecure: t.TLS.Insecure, Origin: t.ResolvedOrigin(),
		CAFile: t.TLS.CAFile, CertFile: t.TLS.CertFile, KeyFile: t.TLS.KeyFile,
	})
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()

	// M-6: do not swallow Capabilities errors — they usually mean auth/TLS/model
	// detection failed. Log, surface in status, count, then fall back to _base
	// (matcher already does that) so discovery still attempts standard OpenConfig.
	caps, capErr := sess.Capabilities(r.ctx)
	if capErr != nil {
		r.logger.Warn("gnmi capabilities failed", "policy", r.name, "host", t.Host, "error", capErr)
		r.setState(t.Host, func(s *targetState) { s.LastError = "capabilities: " + capErr.Error() })
		metrics.GetCapabilityErrors().Add(r.ctx, 1)
	}
	profile := r.selectProfile(t, caps)
	defaults := config.MergeDefaults(&r.policy.Config.Defaults, t.OverrideDefaults)
	// Capabilities vendor is the lowest-precedence discovered manufacturer source
	// (chassis mfg-name and the policy default both override it in Translate).
	discoveredVendor := ""
	if caps != nil {
		discoveredVendor = caps.Vendor
	}

	warnedNoIdentity := false // rate-limit the no-identity warning to once per connection

	// Config capture (options.capture_config): fetch the CONFIG datastore once per
	// connection — on the first flush, which fires right after the initial sync —
	// redact it, and cache it for subsequent flushes. A fresh runOnce on reconnect
	// resets these, so config is re-fetched after a re-sync. A fetch failure logs
	// WARN and leaves configRaw empty: the inventory flush proceeds without config.
	var configRaw []byte
	configFetched := false
	maybeCaptureConfig := func() {
		if !r.policy.Config.Options.ConfigCaptureEnabled() || configFetched {
			return
		}
		configFetched = true // attempt once per connection, regardless of outcome
		raw, cerr := sess.GetConfig(r.ctx)
		if cerr != nil {
			r.logger.Warn("config capture failed", "policy", r.name, "host", t.Host, "error", cerr)
			return
		}
		configRaw = mapping.RedactConfig(raw)
	}

	// asset_tag resolution (defaults.asset_tag): literal or a "/"-prefixed gNMI
	// path reference, resolved once per connection and cached. A path reference is
	// looked up in the snapshot first, then via a targeted Get (the curated
	// subscription does not collect arbitrary leaves), so an operator can point at
	// whatever leaf carries the asset tag — mirroring snmp-discovery's OID-or-literal
	// mechanism. Vetted (placeholder / 50-rune cap / non-printable); unresolved →
	// left unset.
	var assetTag string
	assetResolved := false
	resolveAssetTag := func(snap map[string]any) {
		if assetResolved {
			return
		}
		assetResolved = true
		raw := defaults.AssetTag
		if raw == "" {
			return
		}
		fetch := func(path string) (string, bool) {
			n, gerr := sess.GetOnce(r.ctx, []string{path})
			if gerr != nil {
				r.logger.Warn("asset_tag reference fetch failed", "policy", r.name, "host", t.Host, "path", path, "error", gerr)
				return "", false
			}
			for _, u := range n.Updates {
				if u.Path == path {
					return fmt.Sprintf("%v", u.Value), true
				}
			}
			return "", false
		}
		if at, ok := mapping.ResolveAssetTag(raw, snap, fetch); ok {
			assetTag = at
		}
	}

	flush := func() {
		maybeCaptureConfig()
		snap := model.Snapshot()
		resolveAssetTag(snap)
		entities := mapping.Translate(profile, snap, defaults, discoveredVendor)
		mapping.AssignPrimaryIP(entities, targetHostIP(t.Host))
		dev, _ := entities[0].(*diode.Device) // Translate always emits the Device first
		// Attach the captured CONFIG datastore (already redacted) to the Device,
		// when capture_config is on and the fetch succeeded. Same post-Translate
		// decoration pattern as AssignPrimaryIP; no-op when configRaw is empty.
		if dev != nil {
			if dc := mapping.NewDeviceConfig(configRaw); dc != nil {
				dev.Config = dc
			}
			if assetTag != "" {
				dev.AssetTag = &assetTag
			}
		}
		// Q2: thread target netbox_id onto the Device for explicit NetBox matching.
		if t.NetboxID != nil && dev != nil {
			if dev.Metadata == nil {
				dev.Metadata = diode.Metadata{}
			}
			dev.Metadata["source_match"] = diode.Metadata{"netbox_id": *t.NetboxID}
		}
		// H-1: never ingest a nameless, unidentified device. A flush can fire from
		// an interface-only update or an empty/partial sync before the hostname
		// leaf has arrived; with neither a name nor a netbox_id there is no device
		// identity, so skip until one is known. MED-1: this is also the symptom of
		// a hostname-path mismatch for an unknown vendor on _base, which would
		// otherwise be a permanent silent no-ingest — so count it and warn once.
		hasName := dev != nil && dev.Name != nil && *dev.Name != ""
		if !hasName && t.NetboxID == nil {
			metrics.GetFlushSkippedNoIdentity().Add(r.ctx, 1)
			if !warnedNoIdentity {
				warnedNoIdentity = true
				r.logger.Warn("skipping flush: no device identity (no hostname leaf / netbox_id) — "+
					"check the profile's device.hostname path for this vendor",
					"policy", r.name, "host", t.Host, "profile", profile.Name)
			}
			return
		}
		// Per-flush run: create it, stamp run_id on every entity, ingest with the
		// run_id/policy in Diode metadata, then close the run completed/failed.
		run := r.runStore.CreateRun(r.name, t.Host)
		annotateEntitiesWithRunID(entities, run.ID)
		// Shrink the wire payload: replace nested Device/Interface references with
		// matcher-only stubs (after annotation, before Ingest). Critically, the
		// stub omits the Device's captured config.running, so the heavy blob rides
		// only on the single top-level Device instead of being duplicated onto
		// every interface/IP/module reference. Mirrors snmp-discovery (#392) and
		// device-discovery (#394).
		mapping.PruneNestedRefs(entities, dev)
		resp, ierr := r.client.Ingest(r.ctx, entities, diode.WithIngestMetadata(diode.Metadata{
			"policy_name": r.name, "run_id": run.ID, // keys match snmp/network backends
		}))
		// A nil Go error does NOT mean success — Diode reports per-entity
		// validation/ingestion failures in resp.Errors, which the other backends
		// also check. Distinguish the two: a Go error is a TRANSPORT failure
		// (Diode down) worth retrying; resp.Errors are DETERMINISTIC validation
		// failures that would fail identically on retry, so they are surfaced but
		// not retried (no retry storm).
		transportErr := ierr != nil
		if ierr == nil && resp != nil && len(resp.Errors) > 0 {
			ierr = fmt.Errorf("diode ingest errors: %v", resp.Errors)
		}
		if ierr != nil {
			r.runStore.UpdateRun(r.name, t.Host, run.ID, RunStatusFailed, ierr, len(entities))
			r.logger.Warn("diode ingest failed", "policy", r.name, "host", t.Host, "error", ierr)
			r.setState(t.Host, func(s *targetState) { s.LastError = ierr.Error() })
			metrics.GetIngestErrors().Add(r.ctx, 1)
			if transportErr {
				// MED-6 + H-5: single-flight bounded retry for transient transport
				// failures only. Reset replaces any pending fire (no stacking); the
				// timer's func is ctx-guarded and stopped on shutdown, so a Diode
				// outage self-heals without a flush storm or post-stop firing.
				retry.Reset(5 * time.Second)
			}
			return
		}
		r.runStore.UpdateRun(r.name, t.Host, run.ID, RunStatusCompleted, nil, len(entities))
		r.setState(t.Host, func(s *targetState) { s.LastFlush = time.Now(); s.LastError = "" })
		metrics.GetFlushes().Add(r.ctx, 1)
	}

	mode := t.Mode
	if mode == "" {
		mode = r.policy.Config.Mode
	}
	sampleEvery := time.Duration(r.policy.Config.SampleIntervalMs) * time.Millisecond

	switch mode {
	case config.ModeGet:
		r.setState(t.Host, func(s *targetState) { s.ActiveMode = "get" })
		return r.deliverGet(t.Host, sess, profile, model, deb, flush)
	case config.ModeSample:
		notes, errs, serr := sess.Subscribe(r.ctx, gnmi.Sample, profile.SubscribePaths(), r.policy.Config.SampleIntervalMs)
		if serr != nil {
			return serr
		}
		r.setState(t.Host, func(s *targetState) { s.ActiveMode = "sample" })
		return r.runOpenStream(t.Host, profile, sampleEvery, notes, errs, model, deb, flush)
	case config.ModeOnChange:
		notes, errs, serr := sess.Subscribe(r.ctx, gnmi.OnChange, profile.SubscribePaths(), 0)
		if serr != nil {
			return serr // explicit on_change: surface failure, do not degrade
		}
		r.setState(t.Host, func(s *targetState) { s.ActiveMode = "on_change"; s.FallbackReason = "" })
		return r.runOpenStream(t.Host, profile, 0, notes, errs, model, deb, flush)
	default: // auto — walk the ladder on subscribe rejection OR early stream failure
		// LOW-2: gNMI advertises no per-path ON_CHANGE capability, so neither a
		// Subscribe error nor an early stream failure can be distinguished from a
		// transient gRPC blip. Either therefore causes a one-connection downgrade
		// to sample; it self-heals on the next reconnect (auto retries on_change
		// first), and the current mode is visible via active_mode/fallback_reason.
		//
		// Two rejection shapes are handled: (a) a SYNCHRONOUS Subscribe error
		// (serr != nil), and (b) the real gnmic transport's ASYNCHRONOUS rejection,
		// where Subscribe returns nil and the error arrives on the stream before any
		// data — surfaced by runOpenStream as errEarlyStreamFailure.
		notes, errs, serr := sess.Subscribe(r.ctx, gnmi.OnChange, profile.SubscribePaths(), 0)
		var ocReason string
		if serr == nil {
			r.setState(t.Host, func(s *targetState) { s.ActiveMode = "on_change"; s.FallbackReason = "" })
			err := r.runOpenStream(t.Host, profile, 0, notes, errs, model, deb, flush)
			// A non-early error (productive flap, or ctx-cancel returning nil) goes
			// back to targetLoop to reconnect at the preferred mode — do NOT demote.
			if !errors.Is(err, errEarlyStreamFailure) {
				return err
			}
			ocReason = err.Error() // on_change unviable mid-stream → fall through to sample
		} else {
			ocReason = serr.Error()
		}
		if r.ctx.Err() != nil {
			return nil // ctx cancelled during/after on_change attempt
		}

		r.logger.Info("on_change unsupported, trying sample", "policy", r.name, "host", t.Host, "reason", ocReason)
		metrics.GetModeFallbacks().Add(r.ctx, 1)
		notes, errs, s2 := sess.Subscribe(r.ctx, gnmi.Sample, profile.SubscribePaths(), r.policy.Config.SampleIntervalMs)
		if s2 == nil {
			r.setState(t.Host, func(s *targetState) { s.ActiveMode = "sample"; s.FallbackReason = ocReason })
			err := r.runOpenStream(t.Host, profile, sampleEvery, notes, errs, model, deb, flush)
			if !errors.Is(err, errEarlyStreamFailure) {
				return err
			}
			s2 = err // sample unviable mid-stream → fall through to get
		}
		if r.ctx.Err() != nil {
			return nil // ctx cancelled during/after sample attempt
		}
		r.logger.Info("sample unsupported, falling back to get", "policy", r.name, "host", t.Host, "reason", s2)
		metrics.GetModeFallbacks().Add(r.ctx, 1)
		// Tear down the SAMPLE subscription before switching to Get on the same
		// session — Subscribe/Close are the only other teardown points and Close is
		// deferred until deliverGet exits, so without this an async-rejected SAMPLE
		// producer/gRPC stream would keep retrying in the background for the entire
		// GET fallback.
		sess.StopSubscribe()
		r.setState(t.Host, func(s *targetState) { s.ActiveMode = "get"; s.FallbackReason = s2.Error() })
		return r.deliverGet(t.Host, sess, profile, model, deb, flush)
	}
}

// runOpenStream tracks the active-subscription gauge around an already-opened
// stream, then reconciles it, propagating streamLoop's (possibly
// errEarlyStreamFailure-wrapped) error unchanged. Subscribe is done by the caller
// so a subscribe-time rejection stays distinguishable from a mid-stream error;
// the auto ladder downgrades on a sync rejection or an early (pre-data) stream
// failure, but not on a productive flap.
func (r *Runner) runOpenStream(host string, profile *mapping.Profile, pruneEvery time.Duration,
	notes <-chan gnmi.Notification, errs <-chan error, model *mapping.DeviceModel, deb *Debouncer, flush func(),
) error {
	metrics.GetSubscriptionsActive().Add(r.ctx, 1)
	defer metrics.GetSubscriptionsActive().Add(r.ctx, -1)
	return r.streamLoop(host, profile, pruneEvery, notes, errs, model, deb, flush)
}

// streamLoop reconciles an open subscription stream into the model and flushes
// on debounce. Cycle rotation keeps the model reflecting ONLY currently present
// data so departed interfaces simply stop being ingested (no NetBox delete is
// ever attempted — that is a Diode-side gap, tracked via metrics):
//   - pruneEvery == 0 (ON_CHANGE): rotate on the stream's sync_response boundary,
//     keep=1 (the initial dump is an authoritative full view).
//   - pruneEvery  > 0 (SAMPLE): rotate every interval, keep=2 — SAMPLE re-sends
//     the full set each cycle but emits no per-cycle marker, and a tick may land
//     mid-cycle, so a one-cycle TTL would partial-prune (HIGH-A). keep=2 tolerates
//     a misaligned tick / one quiet interval.
//
// rotate() also applies the empty-view guard (MED-B): if the device-anchor leaf
// was not seen this cycle, the cycle advances WITHOUT pruning so a partial/empty
// dump can never wipe a good persisted model.
func (r *Runner) streamLoop(host string, profile *mapping.Profile, pruneEvery time.Duration,
	notes <-chan gnmi.Notification, errs <-chan error, model *mapping.DeviceModel, deb *Debouncer, flush func(),
) error {
	keep := int64(1)
	var prune <-chan time.Time
	// MED-2 / Codex: BOTH modes hold the first flush until the initial full view
	// is complete, so a slow initial dump (longer than debounce_ms) can't ingest a
	// half-built device. gNMI STREAM subscriptions (ON_CHANGE *and* SAMPLE) emit a
	// sync_response after the initial full dump, so we gate on it for both — see
	// the SyncDone handling below. FALLBACK: rotate() also sets synced=true, so a
	// non-compliant target that never emits sync_response still ingests after the
	// first prune tick (SAMPLE) / never blocks indefinitely.
	synced := false
	if pruneEvery > 0 {
		keep = 2
		ticker := time.NewTicker(pruneEvery)
		defer ticker.Stop()
		prune = ticker.C
	}
	anchor := profile.Device.Hostname
	notif := metrics.GetNotifications() // LOW-1: resolve the hot-path counter once

	// Start this (re)connection's initial dump in a fresh model generation so the
	// post-sync rotate() can prune paths absent from the new full view. On a
	// reconnect the dump would otherwise share the cycle that prior steady-state
	// ON_CHANGE updates already stamped, and an object deleted while the stream was
	// down would survive EndCycle(keep=1) forever. See DeviceModel.BeginSync.
	model.BeginSync()

	// productive tracks whether the stream ever yielded a notification. A stream
	// error after ≥1 notification is a transient flap of a working mode (return it
	// raw → targetLoop reconnects at the preferred mode, no demote). A stream error
	// before ANY notification means the mode is unviable (e.g. a real gnmic async
	// ON_CHANGE rejection): wrap it as errEarlyStreamFailure so the auto ladder
	// downgrades. ctx-cancel always returns nil regardless.
	productive := false

	rotate := func(keepN int64) {
		trustworthy := anchor == "" || model.SeenInCycle(anchor)
		pruned := model.EndCycle(keepN, trustworthy)
		if len(pruned) > 0 {
			metrics.GetRemovalsBlocked().Add(r.ctx, int64(len(pruned)))
		}
		if trustworthy {
			r.setState(host, func(s *targetState) { s.LastSync = time.Now() })
		}
		synced = true // initial dump complete — debounced flushes may proceed
		deb.Trigger()
	}

	// earlyFailureErr wraps e as errEarlyStreamFailure when the stream never
	// produced data, or returns e as-is when it did (a productive flap). This
	// logic is shared by the errs-case and the notes-closed drain below.
	earlyFailureErr := func(e error) error {
		if !productive {
			// Preserve the underlying stream error text (why ON_CHANGE/SAMPLE was
			// rejected) while wrapping the sentinel so errors.Is still matches and
			// the auto ladder can downgrade.
			return fmt.Errorf("subscription failed before any data: %w: %v", errEarlyStreamFailure, e)
		}
		return e
	}

	for {
		select {
		case <-r.ctx.Done():
			return nil
		case e, ok := <-errs:
			if !ok {
				errs = nil // MED-4: closed channel is always-ready; stop selecting on it
				continue
			}
			if e != nil {
				return earlyFailureErr(e)
			}
		case n, ok := <-notes:
			if !ok {
				// notes closed: the producer may have buffered a non-nil error on
				// errs before closing both channels. Drain it non-blocking so a
				// notes-close that wins the select race doesn't silently discard an
				// early-failure error, causing the auto ladder to see a clean exit
				// (return nil) and reconnect at on_change instead of downgrading.
				if errs != nil {
					select {
					case e := <-errs:
						if e != nil {
							return earlyFailureErr(e)
						}
					default:
					}
				}
				return nil
			}
			productive = true
			notif.Add(r.ctx, 1)
			n = r.filterNotification(n, profile) // B-1/M-2: drop non-curated updates and out-of-scope deletes
			if len(n.Deletes) > 0 {
				// M-1: count observed deletes as blocked removals (Diode can't propagate them).
				metrics.GetRemovalsBlocked().Add(r.ctx, int64(len(n.Deletes)))
			}
			if model.Apply(n) {
				deb.Trigger()
			}
			if n.SyncDone {
				if pruneEvery == 0 {
					rotate(keep) // ON_CHANGE: prune on the initial-sync boundary (keep=1), sets synced, triggers flush
				} else if !synced {
					// SAMPLE: the initial sync_response is a complete, authoritative
					// full view, so prune to it with keep=1 right here — paths absent
					// from it (e.g. objects deleted while the stream was down) must not
					// linger in the snapshot until the next prune tick (up to
					// sample_interval_ms). Ongoing pruning stays ticker-driven with the
					// keep=2 tolerance (misaligned mid-stream snapshots). rotate also
					// sets synced and triggers the flush.
					rotate(1)
				}
			}
		case <-prune:
			rotate(keep) // SAMPLE: prune per interval with keep=2 (nil channel blocks forever for ON_CHANGE)
		case <-deb.C():
			if synced {
				flush() // MED-2: suppressed until the initial ON_CHANGE sync completes
			}
		}
	}
}

// filterNotification drops updates whose path is not a curated leaf, and drops
// deletes that fall outside the curated subtrees (B-1 / M-2 / L-10). Bounding
// deletes to curated areas means a broad or unexpected delete from a target
// (e.g. /network-instances) cannot wipe curated model state. Dropped items are
// counted. A legitimate list-entry/subtree delete within /interfaces or
// /components is still allowed and applied subtree-aware by the model.
func (r *Runner) filterNotification(n gnmi.Notification, profile *mapping.Profile) gnmi.Notification {
	if len(n.Updates) > 0 {
		kept := make([]gnmi.Update, 0, len(n.Updates))
		for _, u := range n.Updates {
			if profile.AllowsPath(u.Path) {
				kept = append(kept, u)
			} else {
				metrics.GetNotificationsDropped().Add(r.ctx, 1)
			}
		}
		n.Updates = kept
	}
	if len(n.Deletes) > 0 {
		kept := make([]string, 0, len(n.Deletes))
		for _, d := range n.Deletes {
			if profile.AllowsDelete(d) {
				kept = append(kept, d)
			} else {
				metrics.GetNotificationsDropped().Add(r.ctx, 1)
			}
		}
		n.Deletes = kept
	}
	return n
}

// deliverGet polls the target with periodic Get over the profile's curated
// paths. Each Get is an authoritative full view (keep=1), reconciled into the
// shared model so a departed path drops out of the ingested snapshot — subject
// to the same empty-view guard as streaming (a Get that returns no device
// anchor must not wipe the model).
func (r *Runner) deliverGet(host string, sess gnmi.Session, profile *mapping.Profile, model *mapping.DeviceModel, deb *Debouncer, flush func()) error {
	paths := profile.SubscribePaths()
	anchor := profile.Device.Hostname
	ticker := time.NewTicker(time.Duration(r.policy.Config.GetIntervalMs) * time.Millisecond)
	defer ticker.Stop()
	do := func() error {
		n, err := sess.GetOnce(r.ctx, paths)
		if err != nil {
			return err
		}
		metrics.GetNotifications().Add(r.ctx, 1)
		model.Apply(r.filterNotification(n, profile))
		trustworthy := anchor == "" || model.SeenInCycle(anchor)
		pruned := model.EndCycle(1, trustworthy)
		if len(pruned) > 0 {
			metrics.GetRemovalsBlocked().Add(r.ctx, int64(len(pruned)))
		}
		if trustworthy {
			r.setState(host, func(s *targetState) { s.LastSync = time.Now() })
		}
		flush()
		return nil
	}
	if err := do(); err != nil {
		return err
	}
	for {
		select {
		case <-r.ctx.Done():
			return nil
		case <-ticker.C:
			if err := do(); err != nil {
				return err
			}
		case <-deb.C():
			// The single-flight ingest-retry timer triggers the debouncer on a
			// transient Diode transport failure; in GET mode we consume it here and
			// re-flush the current model snapshot (streamLoop consumes it the same
			// way). Without this the 5s retry was a no-op and a transient Diode
			// outage waited for the next get_interval_ms poll to recover.
			flush()
		}
	}
}

// selectProfile pins t.Profile if set, else matches caps, else _base.
func (r *Runner) selectProfile(t config.Target, caps *gnmi.CapabilitiesResult) *mapping.Profile {
	if t.Profile != "" {
		if p, ok := r.store.Get(t.Profile); ok {
			return p
		}
		// StartPolicy validates pinned profiles, so this is only reachable if the
		// profile vanished after start (e.g. profiles_dir changed). Don't silently
		// auto-match — record it so the operator sees why.
		r.logger.Warn("pinned profile not found; falling back to auto-detect",
			"policy", r.name, "host", t.Host, "profile", t.Profile)
		r.setState(t.Host, func(s *targetState) { s.LastError = "pinned profile not found: " + t.Profile })
	}
	in := mapping.MatchInput{}
	if caps != nil {
		// Profile selection prefers the network-OS hint over the hardware vendor:
		// a Dell-built SONiC box (Vendor "Dell", NOS "SONiC") selects the sonic
		// overlay while its manufacturer still resolves to Dell in Translate.
		in.Vendor = caps.Vendor
		if caps.NOS != "" {
			in.Vendor = caps.NOS
		}
	}
	p := r.store.Match(in)
	if p.Name == "_base" {
		metrics.GetProfileFallbacks().Add(r.ctx, 1) // count vendors that may need an overlay
	}
	// Log only when the selected profile changes for this host, so a flapping
	// target reconnecting on the backoff loop does not re-emit the line every time.
	changed := false
	r.setState(t.Host, func(s *targetState) {
		if s.lastProfile != p.Name {
			s.lastProfile = p.Name
			changed = true
		}
	})
	if changed {
		r.logger.Info("selected profile",
			"policy", r.name, "host", t.Host, "vendor", in.Vendor, "profile", p.Name)
	}
	return p
}

// TargetStatus is the externally-visible per-target state.
type TargetStatus struct {
	Host           string    `json:"host"`
	ActiveMode     string    `json:"active_mode"`
	FallbackReason string    `json:"fallback_reason,omitempty"`
	LastSync       time.Time `json:"last_sync,omitempty"`
	LastFlush      time.Time `json:"last_flush,omitempty"`
	// LastError carries the most recent error of any kind for the target —
	// dial/TLS, Capabilities, stream, or ingest — so it is named generically.
	LastError string `json:"last_error,omitempty"`
}

// TargetStatuses returns a snapshot of all target states.
func (r *Runner) TargetStatuses() []TargetStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TargetStatus, 0, len(r.states))
	for host, s := range r.states {
		out = append(out, TargetStatus{
			Host: host, ActiveMode: s.ActiveMode, FallbackReason: s.FallbackReason,
			LastSync: s.LastSync, LastFlush: s.LastFlush, LastError: s.LastError,
		})
	}
	return out
}
