package policy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"reflect"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-co-op/gocron/v2"
	"github.com/google/uuid"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/snmp"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/targets"
)

// errPolicyStopped is the reason recorded for a run its policy's stop cut
// short. Process shutdown cancels plainly, so its runs record "context
// canceled".
var errPolicyStopped = errors.New("run interrupted: policy stopped")

// schedulerStopTimeout is how long a stop waits for the policy's running jobs,
// gocron's default. A variable so tests can shorten it.
var schedulerStopTimeout = 10 * time.Second

// newScheduler makes a policy's scheduler. A variable so tests can see it shut
// down.
var newScheduler = gocron.NewScheduler

// startWalk starts a crawl's walk on its own goroutine. A variable so tests can
// run a walk to its end before the crawl waits for it.
var startWalk = func(walk func()) { go walk() }

// Define a custom type for the context key
type contextKey string

// Define the policy key
const (
	policyKey               contextKey = "policy"
	defaultTimeout                     = 2 * time.Minute
	defaultSNMPTimeout                 = 5 * time.Second
	defaultSNMPProbeTimeout            = 1 * time.Second
	defaultSNMPProbeOID                = "1.3.6.1.2.1.1" // SNMPv2-MIB::system
)

// expandedTargetGroup represents a group of expanded targets with their original target string
type expandedTargetGroup struct {
	originalTarget string          // Original target string (e.g., "192.168.1.0/24")
	targets        []config.Target // Expanded targets
	entry          int             // The entry's index in the policy's scope targets
	// several marks an entry that expands to several addresses. Its hosts are
	// probed before they are crawled, however many are left to scan.
	several bool
}

// Runner represents the policy runner
type Runner struct {
	scheduler        gocron.Scheduler
	ctx              context.Context
	cancel           context.CancelCauseFunc // ends ctx, which every scan and crawl derives from
	ingestCtx        context.Context         // bounds sending to Diode, which a stop ends only once its wait does
	cancelIngest     context.CancelCauseFunc
	client           diode.Client
	logger           *slog.Logger
	timeout          time.Duration
	snmpTimeout      time.Duration
	snmpProbeTimeout time.Duration
	scope            config.Scope
	config           config.PolicyConfig
	ClientFactory    snmp.ClientFactory
	manufacturers    data.ManufacturerRetriever
	mappingConfig    *config.Mapping
	deviceLookup     data.DeviceRetriever
	runStore         *RunStore
	activeHostJobs   map[string]uuid.UUID
	activeHostJobsMu sync.Mutex
	assetTagOwners   map[string]string
	assetTagOwnersMu sync.Mutex
	// An unscoped VLAN is a config mistake, not an event: the policy either
	// sets a scope or it does not. Warn once per runner rather than once per
	// target per cycle, which on a large estate would be thousands of
	// identical lines an operator learns to filter out. Targets run
	// concurrently, hence Once rather than a bool.
	warnedUnscopedVLANs sync.Once
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, ClientFactory snmp.ClientFactory, mappingConfig *config.Mapping, manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, runStore *RunStore) (_ *Runner, err error) {
	logger = logger.With("policy", name)
	// A backstop: runs and scans recover their own panics and fail their run.
	s, err := newScheduler(gocron.WithStopTimeout(schedulerStopTimeout), gocron.WithGlobalJobOptions(gocron.WithEventListeners(
		gocron.AfterJobRunsWithPanic(func(_ uuid.UUID, job string, recovered any) {
			logger.Error("recovered from a panic in a job", "job", job,
				"error", fmt.Errorf("panic: %v", recovered), "stack", string(debug.Stack()))
		}))))
	if err != nil {
		return nil, err
	}
	// The scheduler's goroutine is already running: a policy refused below
	// shuts it down rather than leaving it for the life of the process.
	defer func() {
		if err != nil {
			_ = s.Shutdown()
		}
	}()

	runner := &Runner{
		scheduler:      s,
		client:         client,
		logger:         logger,
		ClientFactory:  ClientFactory,
		manufacturers:  manufacturers,
		mappingConfig:  mappingConfig,
		deviceLookup:   deviceLookup,
		runStore:       runStore,
		activeHostJobs: make(map[string]uuid.UUID),
		assetTagOwners: make(map[string]string),
	}

	runner.timeout = time.Duration(policy.Config.Timeout) * time.Second
	if runner.timeout == 0 {
		runner.timeout = defaultTimeout
	}
	runner.snmpTimeout = time.Duration(policy.Config.SNMPTimeout) * time.Second
	if runner.snmpTimeout == 0 {
		runner.snmpTimeout = defaultSNMPTimeout
	}
	runner.snmpProbeTimeout = time.Duration(policy.Config.SNMPProbeTimeout) * time.Second
	if runner.snmpProbeTimeout == 0 {
		runner.snmpProbeTimeout = defaultSNMPProbeTimeout
	}
	if runner.timeout <= runner.snmpTimeout {
		return nil, fmt.Errorf("policy timeout (%s) must be greater than snmp_timeout (%s)", runner.timeout, runner.snmpTimeout)
	}
	runner.scope = policy.Scope
	runner.config = policy.Config

	// Normalised once per policy rather than per member per poll: a bad
	// template is an operator mistake to fix, and a warning repeated on
	// every scan of every stack is one nobody reads. Every consumer
	// downstream then reads a template already known to be usable.
	runner.config.Defaults.StackMemberNameTemplate = config.NormalizeStackMemberTemplate(
		runner.config.Defaults.StackMemberNameTemplate, logger)
	for i := range runner.scope.Targets {
		od := runner.scope.Targets[i].OverrideDefaults
		if od == nil || od.StackMemberNameTemplate == "" {
			continue
		}
		od.StackMemberNameTemplate = config.NormalizeStackMemberTemplate(od.StackMemberNameTemplate, logger)
	}

	expandedTargetGroups := runner.expandTargetRanges(runner.scope.Targets)
	runner.warnOverlappingEntries(expandedTargetGroups)
	expandedTargetGroups = runner.leaveOutOwnEntries(expandedTargetGroups)

	for _, group := range expandedTargetGroups {
		if !group.several {
			// Create scan task for single target
			task := gocron.NewTask(runner.run, group.entry, group.targets[0])
			if policy.Config.Schedule != nil {
				_, err = runner.scheduler.NewJob(gocron.CronJob(*policy.Config.Schedule, false), task,
					gocron.WithSingletonMode(gocron.LimitModeReschedule))
			} else {
				_, err = runner.scheduler.NewJob(gocron.OneTimeJob(
					gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
					gocron.WithSingletonMode(gocron.LimitModeReschedule))
			}
			if err != nil {
				return nil, err
			}
			continue
		}
		// Create scan task for multiple targets with original target
		runner.warnSlowScan(group)
		task := gocron.NewTask(runner.runScanWithOriginal, group.entry, group.targets, group.originalTarget)
		if policy.Config.Schedule != nil {
			_, err = runner.scheduler.NewJob(gocron.CronJob(*policy.Config.Schedule, false), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		} else {
			_, err = runner.scheduler.NewJob(gocron.OneTimeJob(
				gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		}
		if err != nil {
			return nil, err
		}
	}
	// Made last, so a policy refused above leaves no context behind. Sending
	// has its own context, so a stop can leave an ingest under way to end.
	parent := context.WithValue(ctx, policyKey, name)
	runner.ctx, runner.cancel = context.WithCancelCause(parent)
	runner.ingestCtx, runner.cancelIngest = context.WithCancelCause(parent)
	return runner, nil
}

func (r *Runner) runScanWithOriginal(entry int, targets []config.Target, originalTarget string) {
	// A scan that starts once its policy has stopped records nothing: the
	// policy may already run again under its name.
	if r.ctx.Err() != nil {
		return
	}
	policyName := r.ctx.Value(policyKey).(string)
	log := r.logger.With("entry", entry+1, "target", originalTarget)

	// All expanded targets have the same port, get it from the first target
	port := uint16(161) // default
	if len(targets) > 0 {
		port = targets[0].Port
	}

	// Create run for the scan operation (includes port)
	scanRun := r.runStore.CreateRun(policyName, originalTarget, port, "")
	defer r.recoverRun(log, originalTarget, port, scanRun.ID)

	log.Info("starting SNMP probe scan", "target_count", len(targets))
	workerCount := min(maxProbeWorkers, len(targets))

	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	targetCh := make(chan config.Target)
	resultsCh := make(chan config.Target, workerCount)

	// Addresses whose probe started before the scan ran out of time, and
	// probes that panicked.
	var probed, panicked atomic.Int64
	var wg sync.WaitGroup
	wg.Add(workerCount)
	for range workerCount {
		go func() {
			defer wg.Done()
			for target := range targetCh {
				if ctx.Err() != nil {
					continue
				}
				probed.Add(1)
				if r.probeRecovering(ctx, log, target, &panicked) {
					resultsCh <- target
				}
			}
		}()
	}

	go func() {
		defer close(targetCh)
		for _, target := range targets {
			select {
			case <-ctx.Done():
				return
			case targetCh <- target:
			}
		}
	}()

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	var responsive []config.Target
	for target := range resultsCh {
		responsive = append(responsive, target)
		log.Debug("SNMP probe succeeded", "host", target.Host, "port", target.Port)
	}

	// Probe panics past the first are only counted. The count goes once on
	// the scan's last line, and in its reason when it fails.
	panics := panicked.Load()
	withPanics := func(attrs ...any) []any {
		if panics > 0 {
			attrs = append(attrs, "panicked_probes", panics)
		}
		return attrs
	}
	failure := func(err error) error {
		if panics > 0 {
			return fmt.Errorf("%w; %d probes panicked, the log has the first one's stack", err, panics)
		}
		return err
	}

	// A scan its policy's stop cut short is a stopped run.
	endStopped := func() {
		cause := context.Cause(r.ctx)
		log.Info("SNMP probe scan stopped with its policy", withPanics("error", cause, "responsive_target_count", len(responsive))...)
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusFailed, failure(cause), len(responsive))
	}

	// A scan stopped by now crawls nothing, and asks the scheduler, which is
	// stopping, for nothing.
	if r.ctx.Err() != nil {
		endStopped()
		return
	}

	// Snapshot live job IDs before the loop to avoid holding two locks simultaneously.
	// Done here (before the early returns below) so stale entries are pruned on every scan
	// that was not stopped, including the zero-responsive and context-timeout paths.
	jobs := r.scheduler.Jobs()
	liveIDs := make(map[uuid.UUID]struct{}, len(jobs))
	for _, j := range jobs {
		liveIDs[j.ID()] = struct{}{}
	}

	// Crawl jobs are keyed by scope entry, so each entry crawls every host its
	// own probe finds, with its own credentials, even when two entries are
	// written identically. Stale ones are pruned for this entry only, so a
	// concurrent scan of another entry keeps the jobs it just added.
	keyPrefix := fmt.Sprintf("%d::%s::", entry, originalTarget)
	r.pruneHostJobs(keyPrefix, liveIDs)

	// A scan that ran out of its own time still crawls the hosts it found,
	// and its run fails saying how far it got. One the stop cuts short from
	// here on ends below.
	var timedOut error
	if ctxErr := ctx.Err(); errors.Is(ctxErr, context.DeadlineExceeded) {
		timedOut = failure(fmt.Errorf("%w (started probing %d of %d addresses, %d responded; raise timeout to probe them all)",
			ctxErr, probed.Load(), len(targets), len(responsive)))
		log.Warn("SNMP probe scan interrupted", withPanics("error", timedOut, "responsive_target_count", len(responsive))...)
	}

	var err error
	for _, target := range responsive {
		jobKey := fmt.Sprintf("%s%s:%d", keyPrefix, target.Host, target.Port)

		// Checked and recorded apart from scheduling, so the mutex is never
		// held across the scheduler's internal locks.
		if r.hostJobActive(jobKey, liveIDs) {
			log.Debug("crawl job already active, skipping", "host", target.Host)
			continue
		}

		task := gocron.NewTask(r.runWithMetadata, entry, target, originalTarget)
		var newJob gocron.Job
		if r.config.Schedule != nil {
			// Crawled right after the scan that found it, then on the schedule.
			newJob, err = r.scheduler.NewJob(gocron.CronJob(*r.config.Schedule, false), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule),
				gocron.WithStartAt(gocron.WithStartImmediately()))
		} else {
			newJob, err = r.scheduler.NewJob(gocron.OneTimeJob(
				gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		}
		if err != nil {
			log.Error("failed to schedule crawl task for responsive target", "host", target.Host, "error", err)
			continue
		}

		r.recordHostJob(jobKey, newJob.ID())
		liveIDs[newJob.ID()] = struct{}{} // keep snapshot current for remaining iterations
	}

	// A stop that landed since the check above leaves the crawls just
	// scheduled unrun, so the scan is a stopped run all the same.
	if r.ctx.Err() != nil {
		endStopped()
		return
	}

	if len(responsive) == 0 {
		if timedOut != nil {
			r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusFailed, timedOut, 0)
			return
		}
		log.Warn("no hosts responded to SNMP probe", withPanics()...)
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID,
			RunStatusFailed, failure(fmt.Errorf("no hosts responded to SNMP probe")), 0)
		return
	}

	if timedOut != nil {
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusFailed, timedOut, len(responsive))
		return
	}

	// Update scan run status
	r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusCompleted, nil, len(responsive))
	log.Info("SNMP probe scan complete", withPanics("responsive_target_count", len(responsive))...)
}

// pruneHostJobs forgets the crawl jobs under keyPrefix, one scope entry's,
// that are no longer scheduled.
func (r *Runner) pruneHostJobs(keyPrefix string, liveIDs map[uuid.UUID]struct{}) {
	r.activeHostJobsMu.Lock()
	defer r.activeHostJobsMu.Unlock()
	for jobKey, jobID := range r.activeHostJobs {
		if strings.HasPrefix(jobKey, keyPrefix) {
			if _, alive := liveIDs[jobID]; !alive {
				delete(r.activeHostJobs, jobKey)
			}
		}
	}
}

// hostJobActive reports whether jobKey's crawl job is still scheduled.
func (r *Runner) hostJobActive(jobKey string, liveIDs map[uuid.UUID]struct{}) bool {
	r.activeHostJobsMu.Lock()
	defer r.activeHostJobsMu.Unlock()
	id, ok := r.activeHostJobs[jobKey]
	if !ok {
		return false
	}
	_, alive := liveIDs[id]
	return alive
}

// recordHostJob records the crawl job scheduled for jobKey.
func (r *Runner) recordHostJob(jobKey string, id uuid.UUID) {
	r.activeHostJobsMu.Lock()
	defer r.activeHostJobsMu.Unlock()
	r.activeHostJobs[jobKey] = id
}

// targetLogger is the runner's logger naming one target.
func (r *Runner) targetLogger(target config.Target) *slog.Logger {
	return r.logger.With("host", target.Host, "port", target.Port)
}

// crawlLogger names one target and the scope entry it is crawled for,
// counting entries from 1.
func (r *Runner) crawlLogger(entry int, target config.Target) *slog.Logger {
	return r.targetLogger(target).With("entry", entry+1)
}

// panicError is a panic recovered on a goroutine of a crawl, carried to the
// crawl's job as its error so the job fails its run and logs the panic once.
type panicError struct {
	value any
	stack []byte
}

func (e *panicError) Error() string {
	return fmt.Sprintf("panic: %v", e.value)
}

// recoverRun is deferred by a scan once its run exists. It turns a panic into
// a failed run and one error record, so one target cannot stop the process or
// leave its policy running.
func (r *Runner) recoverRun(log *slog.Logger, target string, port uint16, runID string) {
	if recovered := recover(); recovered != nil {
		r.failRunOnPanic(log, target, port, runID, &panicError{value: recovered, stack: debug.Stack()})
	}
}

// finishCrawl is deferred by a crawl once its run exists. A panic fails the
// run and counts as a failed discovery. A crawl that walked and mapped its
// target, and ended without a panic, counts as a successful one.
func (r *Runner) finishCrawl(log *slog.Logger, host string, port uint16, runID string, discovered *bool) {
	policyName, _ := r.ctx.Value(policyKey).(string)
	if recovered := recover(); recovered != nil {
		r.countDiscoveryFailure(policyName, "panic")
		r.failRunOnPanic(log, host, port, runID, &panicError{value: recovered, stack: debug.Stack()})
		return
	}
	if *discovered {
		if rMetric := metrics.GetDiscoverySuccess(); rMetric != nil {
			rMetric.Add(r.ctx, 1, metric.WithAttributes(attribute.String("policy", policyName)))
		}
	}
}

// failRunOnPanic marks a run failed by a panic and logs the panic with its
// stack.
func (r *Runner) failRunOnPanic(log *slog.Logger, target string, port uint16, runID string, err *panicError) {
	log.Error("recovered from a panic; the run is marked failed", "error", err, "stack", string(err.stack))
	policyName, _ := r.ctx.Value(policyKey).(string)
	r.runStore.UpdateRun(policyName, target, port, runID, RunStatusFailed, err, 0)
}

// probeRecovering probes one address. A panic counts as no answer, so the
// worker that hit it goes on probing the rest of the range. Only the scan's
// first panic is logged, with its stack; panicked counts them all.
func (r *Runner) probeRecovering(ctx context.Context, log *slog.Logger, target config.Target, panicked *atomic.Int64) (answered bool) {
	defer func() {
		if recovered := recover(); recovered != nil {
			if panicked.Add(1) == 1 {
				log.Error("recovered from a panic while probing; the address counts as not answering, and the scan counts any further probe panics",
					"host", target.Host, "port", target.Port,
					"error", fmt.Errorf("panic: %v", recovered), "stack", string(debug.Stack()))
			}
			answered = false
		}
	}()
	return r.probeTarget(ctx, target)
}

// resolveTargetAuthentication returns the authentication to use for a target
// Uses target-level auth if available, otherwise falls back to policy-level auth
func (r *Runner) resolveTargetAuthentication(target config.Target) *config.Authentication {
	if target.Authentication != nil {
		r.logger.Debug("using target-level authentication", "host", target.Host)
		return target.Authentication
	}

	r.logger.Debug("using policy-level authentication (fallback)", "host", target.Host)
	return &r.scope.Authentication
}

// The production lookup names modules from an operator's modules: entries.
var _ mapping.ModuleModelLookup = (*data.DeviceLookup)(nil)

// moduleModels is the device lookup when it can name module types, else nil.
func (r *Runner) moduleModels() mapping.ModuleModelLookup {
	if lookup, ok := r.deviceLookup.(mapping.ModuleModelLookup); ok {
		return lookup
	}
	return nil
}

// userDefinedModels is implemented by a device lookup that can say whether a
// model came from lookup_extensions_dir.
type userDefinedModels interface {
	UserDefined(deviceOID string) bool
}

// The production lookup must keep answering, or a lookup pin silently lapses.
var _ userDefinedModels = (*data.DeviceLookup)(nil)

// modelPin reports whether the operator named this target's device model: in
// its defaults, which pins every device of the target, or in a
// lookup_extensions_dir entry for its sysObjectID, which pins a standalone
// device. Either wins over the model a chassis row reports.
func (r *Runner) modelPin(defaults *config.Defaults, sysOID string) mapping.ModelPin {
	if defaults.Device.Model != "" {
		return mapping.ModelPinnedByDefaults
	}
	if lookup, ok := r.deviceLookup.(userDefinedModels); ok && lookup.UserDefined(mapping.TrimSNMPString(sysOID)) {
		return mapping.ModelPinnedByLookup
	}
	return mapping.ModelNotPinned
}

// resolveTargetDefaults returns the defaults to use for a target
// Merges target-level override defaults with policy-level defaults
func (r *Runner) resolveTargetDefaults(target config.Target) *config.Defaults {
	if target.OverrideDefaults != nil {
		r.logger.Debug("merging target-level override defaults", "host", target.Host)
		return config.MergeDefaults(&r.config.Defaults, target.OverrideDefaults)
	}

	r.logger.Debug("using policy-level defaults", "host", target.Host)
	return &r.config.Defaults
}

// probeProbeUser is the USM user the v3 probe presents instead of the
// operator's. gosnmp rejects an empty user name, so the probe needs some
// value; this one is never a credential and is only ever seen by an agent that
// has already answered engine discovery.
const probeProbeUser = "orb-probe"

// engineDiscoverer is answered by a client that learned a peer's SNMPv3
// authoritative engine ID.
//
// Asserted rather than added to snmp.Walker so a walker that cannot report it
// keeps the walk-error admission rule, which is the only one v1 and v2c have.
type engineDiscoverer interface {
	EngineDiscovered() bool
}

// probeAuthentication returns the credentials the reachability probe may send
// to an address that has not yet proven anything is there.
//
// SNMPv3 carries a credential-free engine discovery exchange before any
// authenticated request (RFC 3414 section 4), so the probe presents a
// placeholder user at noAuthNoPriv: the operator's user never reaches a
// scanned address, and without an authenticated request there is no HMAC to
// capture and attack offline. Presence comes from the discovery answer, so
// nothing is lost by not authenticating.
//
// v1 and v2c are returned unchanged, and this is the exposure the probe cannot
// close: the community IS the credential and there is no discovery exchange to
// stand in for it. A conformant agent silently discards a request bearing the
// wrong community, so substituting one turns every device into a false
// negative rather than protecting anything. Whether a v2c range may be scanned
// at all is a policy question, not one the probe can answer.
func probeAuthentication(auth *config.Authentication) *config.Authentication {
	if auth == nil || auth.ProtocolVersion != snmp.ProtocolVersion3 {
		return auth
	}

	// Copied rather than mutated: the caller's authentication is the policy's
	// own and is reused for the real run.
	probe := *auth
	probe.Username = probeProbeUser
	probe.SecurityLevel = "noAuthNoPriv"
	// The sentinels rather than empty strings: getAuthProtocol and
	// getPrivProtocol accept "NoAuth" and "NoPriv" and reject everything else
	// they do not recognise, the empty string included. Clearing these to ""
	// makes the client factory fail before it connects, which rejects every
	// address and quietly turns off v3 range scanning altogether.
	probe.AuthProtocol = "NoAuth"
	probe.AuthPassphrase = ""
	probe.PrivProtocol = "NoPriv"
	probe.PrivPassphrase = ""
	probe.ContextName = ""
	return &probe
}

func (r *Runner) probeTarget(ctx context.Context, target config.Target) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	auth := probeAuthentication(r.resolveTargetAuthentication(target))

	snmpClient, err := r.ClientFactory(target.Host, target.Port, 0, r.snmpProbeTimeout, auth, r.targetLogger(target))
	if err != nil {
		return false
	}
	defer func() {
		_ = snmpClient.Close()
	}()

	if err := snmpClient.Connect(); err != nil {
		return false
	}

	_, err = snmpClient.Walk(ctx, defaultSNMPProbeOID, 0)
	if err == nil {
		return true
	}

	// The v3 probe deliberately cannot authenticate, so its walk fails against
	// a live agent too. Answering engine discovery is what proves one is there.
	if discoverer, ok := snmpClient.(engineDiscoverer); ok {
		return discoverer.EngineDiscovered()
	}
	return false
}

// run runs the policy for a single target (no parent)
func (r *Runner) run(entry int, target config.Target) {
	r.runWithMetadata(entry, target, "")
}

// runWithMetadata runs the policy with metadata tracking
func (r *Runner) runWithMetadata(entry int, target config.Target, parentTarget string) {
	// A crawl that starts once its policy has stopped records nothing: the
	// policy may already run again under its name.
	if r.ctx.Err() != nil {
		return
	}
	policyName := r.ctx.Value(policyKey).(string)
	targetHost := target.Host
	targetPort := target.Port
	log := r.crawlLogger(entry, target)

	// Create run at start (includes port)
	run := r.runStore.CreateRun(policyName, targetHost, targetPort, parentTarget)
	discovered := false
	defer r.finishCrawl(log, targetHost, targetPort, run.ID, &discovered)

	// Track policy execution
	if rMetric := metrics.GetPolicyExecutions(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", r.ctx.Value(policyKey).(string)),
			))
	}
	startTime := time.Now()

	defer func() {
		if rMetric := metrics.GetDiscoveryLatency(); rMetric != nil {
			// Calculate duration in milliseconds
			duration := float64(time.Since(startTime).Milliseconds())
			rMetric.Record(r.ctx, duration, metric.WithAttributes(
				attribute.String("policy", policyName),
			))
		}
	}()

	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	// A crawl the stop cut short counts as neither a success nor a failure.
	endStopped := func(stopped context.Context, entityCount int, err error) bool {
		if !r.endStoppedCrawl(stopped, log, targetHost, targetPort, run.ID, entityCount, err) {
			return false
		}
		discovered = false
		return true
	}

	entities, primaryHits, err := r.queryTarget(ctx, entry, target)
	if err != nil {
		var walkPanic *panicError
		if errors.As(err, &walkPanic) {
			r.failRunOnPanic(log, targetHost, targetPort, run.ID, walkPanic)
			return
		}
		if endStopped(r.ctx, 0, err) {
			return
		}
		log.Error("error querying target", "error", err)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, 0)
		return
	}
	discovered = true
	log.Info("SNMP crawl complete", "entity_count", len(entities))

	if len(entities) == 0 {
		// Nothing to send is no reason to call a stopped crawl complete.
		if endStopped(r.ctx, 0, nil) {
			return
		}
		log.Info("no entities to ingest")
		// Update run status to completed even if no entities
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusCompleted, nil, 0)
		return
	}

	if target.NetboxID != nil {
		annotateDeviceWithSourceMatch(entities, *target.NetboxID)
	}
	// Resolve the master once; reused for name suppression and pruning.
	currentDevice := mapping.CurrentDeviceFrom(entities)
	// Suppress Device.name (emit_device_name: false) after source_match is
	// stamped so the matcher guard can see netbox_id, and before
	// PruneNestedRefs so the device stubs inherit the cleared name.
	mapping.ApplyDeviceNameEmission(
		entities,
		currentDevice,
		r.config.Options.DeviceNameEmissionEnabled(),
		log,
	)
	annotateEntitiesWithRunID(entities, run.ID)
	r.warnUnscopedVLANs(log, entities)

	// Strip nested Device/Interface refs to matcher-only stubs to shrink
	// the wire payload. Runs after annotation so the annotators can walk
	// the rich shared graph with their unsafe.Pointer dedup intact —
	// otherwise every stub would need its own metadata pass.
	if r.config.Options.IPAddressEmissionEnabled() {
		logEntitiesForIngestion(log, entities)
		mapping.PruneNestedRefs(entities, currentDevice, primaryHits)
	} else {
		// emit_ip_addresses: false. Prefixes, VRFs and stack routing have
		// already used the addresses; each now gives way to the interface
		// stub it carried.
		entities = mapping.OmitIPAddresses(entities, currentDevice)
		logEntitiesForIngestion(log, entities)
	}

	// After pruning, so it checks exactly what is sent: until then, copies
	// made during mapping can still hold a value this run dropped, such as a
	// suppressed device name.
	if err := repairInvalidUTF8(log, entities); err != nil {
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, len(entities))
		return
	}

	// Nothing is sent for a policy that has stopped: it may already have been
	// replaced by a new version, and this crawl read the device with the old
	// one's settings. Once past this check the ingest counts as under way,
	// chunking included, and is left to end unless the stop's wait for it
	// ends first.
	if endStopped(r.ctx, len(entities), nil) {
		return
	}
	resp, err := r.ingest(log, entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": policyName,
		"run_id":      run.ID,
	}))
	// Whether the stop ended the ingest is the ingest context's to say: the
	// SDK reports a cancelled request as a gRPC status, not as the context's
	// error, and a failure Diode reports during the stop's wait is still one.
	if err != nil && endStopped(r.ingestCtx, len(entities), err) {
		return
	}
	if err != nil {
		log.Error("error ingesting entities", "error", err, "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, len(entities))
	} else if resp != nil && resp.Errors != nil {
		ingestErr := fmt.Errorf("ingestion errors: %v", resp.Errors)
		log.Error("error ingesting entities", "error", resp.Errors, "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, ingestErr, len(entities))
	} else {
		log.Info("entities ingested successfully", "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusCompleted, nil, len(entities))
	}
}

// endStoppedCrawl ends the crawl if stopped has ended, and reports whether it
// did. The run fails with stopped's cause and one info line, not an error; err,
// if any, goes on that line to say how far the crawl got.
func (r *Runner) endStoppedCrawl(stopped context.Context, log *slog.Logger, host string, port uint16, runID string, entityCount int, err error) bool {
	if stopped.Err() == nil {
		return false
	}
	cause := context.Cause(stopped)
	if err == nil {
		err = cause
	}
	log.Info("SNMP crawl stopped with its policy", "error", err)
	policyName, _ := r.ctx.Value(policyKey).(string)
	r.runStore.UpdateRun(policyName, host, port, runID, RunStatusFailed, cause, entityCount)
	return true
}

func logEntitiesForIngestion(log *slog.Logger, entities []diode.Entity) {
	for _, entity := range entities {
		log.Debug("entity for ingestion", "entity", entity.ConvertToProtoMessage())
	}
}

// assetTagClaimer returns the per-target claim callback handed to
// mapping.TranslateAsStack. targetID is the device's address, host:port,
// not the crawl job's key: entries that crawl one host share its asset tags.
// Not the bare host either: two agents on one host behind different ports
// are distinct devices, and keying by host alone would let them share a
// cloned tag. First target to discover a tag owns it for the lifetime
// of this runner (one policy); the same target may re-claim its tags
// on every cycle. A different target reporting an already-owned tag —
// vendor-cloned EEPROM values, mislabeled gear — is suppressed with a
// warn, because emitting it would make Diode's highest-precedence
// matcher merge two devices onto one NetBox record.
//
// The state is in-memory only: after a restart, whichever target runs
// first claims the tag, so a pre-existing NetBox record created by the
// other target may still be matched. This guards the steady state; it
// cannot see NetBox's actual tag assignments.
func (r *Runner) assetTagClaimer(targetID string, log *slog.Logger) func(string) bool {
	return func(tag string) bool {
		r.assetTagOwnersMu.Lock()
		defer r.assetTagOwnersMu.Unlock()
		// Lazy init keeps the claimer safe on Runner values built as
		// literals (tests); NewRunner pre-initializes the map.
		if r.assetTagOwners == nil {
			r.assetTagOwners = make(map[string]string)
		}
		owner, ok := r.assetTagOwners[tag]
		if !ok {
			r.assetTagOwners[tag] = targetID
			return true
		}
		if owner == targetID {
			return true
		}
		log.Warn("asset tag skipped: already discovered on another target of this policy",
			"asset_tag", tag, "target", targetID, "owner_target", owner)
		return false
	}
}

// countTimeout records a crawl that ran out of its own time as a failed
// discovery. One its policy's stop cut short is not counted.
func (r *Runner) countTimeout(policyName string, err error) {
	if r.ctx.Err() == nil {
		r.countDiscoveryFailure(policyName, err.Error())
	}
}

// countDiscoveryFailure records a failed discovery and why.
func (r *Runner) countDiscoveryFailure(policyName, reason string) {
	if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
		rMetric.Add(r.ctx, 1, metric.WithAttributes(
			attribute.String("policy", policyName),
			attribute.String("error", reason),
		))
	}
}

// walkResult is what a walk goroutine sends its crawl.
type walkResult struct {
	oids mapping.ObjectIDValueMap
	err  error
}

// walkHandoff carries a walk goroutine's one result to its crawl. Once the
// crawl stops waiting, a panic the walk reports is logged here, with its
// stack, rather than lost in a channel nobody reads.
type walkHandoff struct {
	ch        chan walkResult
	log       *slog.Logger
	mu        sync.Mutex
	abandoned bool
}

func newWalkHandoff(log *slog.Logger) *walkHandoff {
	// Buffered, so the walk can always hand its result over and exit.
	return &walkHandoff{ch: make(chan walkResult, 1), log: log}
}

// deliver hands res to the crawl without blocking, or logs it if it is a
// panic the crawl will not read.
func (h *walkHandoff) deliver(res walkResult) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.abandoned {
		h.logUnread(res)
		return
	}
	select {
	case h.ch <- res:
	default:
		h.logUnread(res)
	}
}

// abandon records that the crawl stopped waiting, and logs a panic already
// handed over that the crawl did not read.
func (h *walkHandoff) abandon() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.abandoned = true
	select {
	case res := <-h.ch:
		h.logUnread(res)
	default:
	}
}

func (h *walkHandoff) logUnread(res walkResult) {
	var walkPanic *panicError
	if errors.As(res.err, &walkPanic) {
		h.log.Error("recovered from a panic in a walk the crawl had stopped waiting for",
			"error", walkPanic, "stack", string(walkPanic.stack))
	}
}

// sendWalkPanic is deferred by a walk goroutine. It hands a panic to the
// crawl as the walk's error, so the crawl fails at once instead of at the
// timeout.
func sendWalkPanic(h *walkHandoff) {
	if recovered := recover(); recovered != nil {
		h.deliver(walkResult{err: &panicError{value: recovered, stack: debug.Stack()}})
	}
}

// queryTarget walks the target, maps the result to entities, and returns
// the entity slice along with the per-target set of cycle-closer primary
// IP entities (the top-level ipam.ipaddress entities that set a device's
// primary IP). The hits are returned by value — never stashed on the
// shared Runner, which serves targets concurrently — so the caller can
// thread them into PruneNestedRefs for this target only.
func (r *Runner) queryTarget(ctx context.Context, entry int, target config.Target) ([]diode.Entity, map[*diode.IPAddress]bool, error) {
	if ctx.Err() != nil {
		return nil, nil, context.Cause(ctx)
	}

	targetDefaults := r.resolveTargetDefaults(target)
	log := r.crawlLogger(entry, target)

	mappingConfig, err := mapping.NewConfig(r.mappingConfig.Entries, log, r.manufacturers, r.deviceLookup, targetDefaults, r.config.Options)
	if err != nil {
		log.Error("error creating mapping config", "error", err)
		return nil, nil, err
	}
	targetHost := strings.TrimSpace(target.Host)

	mapper := mapping.NewObjectIDMapper(mappingConfig, log, targetDefaults, targetHost)
	mapper.SetContext(ctx)
	policyName := r.ctx.Value(policyKey).(string)
	// Track discovery attempt
	if rMetric := metrics.GetDiscoveryAttempts(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Start timing the discovery
	startTime := time.Now()

	auth := r.resolveTargetAuthentication(target)

	host := snmp.NewHost(targetHost, target.Port, r.config.Retries, r.snmpTimeout, auth, log, r.ClientFactory)

	// Phase 1: walk generic OIDs (sysObjectID/sysDescr included).
	genericOIDs := mappingConfig.GenericObjectIDs()
	log.Info("querying target", "object_count", len(genericOIDs))
	log.Debug("phase 1 walk", "oid_count", len(genericOIDs))

	// The handoff lets the goroutine always hand its result over and exit,
	// even if we have already returned due to context cancellation. The goroutine is
	// bounded by snmpTimeout (set on the SNMP client), so it is not a permanent leak.
	generic := newWalkHandoff(log)
	startWalk(func() {
		defer sendWalkPanic(generic)
		oids, err := host.Walk(ctx, genericOIDs)
		generic.deliver(walkResult{oids, err})
	})

	var oids mapping.ObjectIDValueMap
	select {
	case <-ctx.Done():
		generic.abandon()
		r.countTimeout(policyName, ctx.Err())
		return nil, nil, context.Cause(ctx)
	case res := <-generic.ch:
		var walkPanic *panicError
		switch {
		case errors.As(res.err, &walkPanic):
			// Logged once, with its stack, by the crawl.
			r.countDiscoveryFailure(policyName, "panic")
			return nil, nil, res.err
		case res.err != nil && r.ctx.Err() != nil:
			// The walk ended with the stop and was heard first: the crawl was
			// stopped, as in the branch above, not failed.
			return nil, nil, context.Cause(r.ctx)
		case res.err != nil:
			log.Warn("error crawling host", "error", res.err)
			r.countDiscoveryFailure(policyName, res.err.Error())
			return nil, nil, res.err
		}
		oids = res.oids
	}

	// Phase 2: resolve vendor from phase-1 results, walk vendor-scoped OIDs.
	sysOID, sysDescr := ExtractSysIdentity(oids)
	vendor := ResolveVendor(sysOID, sysDescr, defaultVendorMatchers)
	if vendor != "" {
		vendorOIDs := mappingConfig.VendorObjectIDs(vendor)
		if len(vendorOIDs) > 0 {
			log.Debug("phase 2 walk", "vendor", vendor, "oid_count", len(vendorOIDs))
			vendorWalk := newWalkHandoff(log)
			startWalk(func() {
				defer sendWalkPanic(vendorWalk)
				out, err := host.Walk(ctx, vendorOIDs)
				vendorWalk.deliver(walkResult{out, err})
			})
			select {
			case <-ctx.Done():
				vendorWalk.abandon()
				// Mirror the phase-1 ctx.Done() handling: record the
				// failure metric and return. Latency on the failure
				// path is captured by runWithMetadata's defer (the
				// outermost scope), which fires regardless of how
				// queryTarget exits, so we deliberately don't record
				// latency here.
				r.countTimeout(policyName, ctx.Err())
				return nil, nil, context.Cause(ctx)
			case res := <-vendorWalk.ch:
				var walkPanic *panicError
				switch {
				case errors.As(res.err, &walkPanic):
					// A panic fails the crawl, as one in the first phase does.
					r.countDiscoveryFailure(policyName, "panic")
					return nil, nil, res.err
				case res.err != nil && r.ctx.Err() != nil:
					// Stopped, as in the first phase.
					return nil, nil, context.Cause(r.ctx)
				case res.err != nil:
					log.Warn("phase 2 walk failed; continuing with generic only", "vendor", vendor, "error", res.err)
				default:
					for k, v := range res.oids {
						oids[k] = v
					}
				}
			}
		}
	} else {
		log.Debug("no vendor matched; generic-only path")
	}

	// Record discovery latency
	if rMetric := metrics.GetDiscoveryLatency(); rMetric != nil {
		rMetric.Record(r.ctx, time.Since(startTime).Seconds(),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Normalise the walk before any consumer reads it. On the Junos platforms
	// that index dot1qVlanStaticTable internally, the VLAN catalog, the port
	// masks and the SVI resolver would each otherwise read an internal number
	// as a VLAN ID. Done here, once, so every consumer below sees one keying
	// and the translation's warnings are logged once per target. A no-op
	// everywhere else.
	oids = mapping.ResolveJuniperVlanIndices(oids, log)

	entities := make([]diode.Entity, 0)
	entitiesForTarget := mapper.MapObjectIDsToEntity(oids)
	ifIndexByIface := mapper.InterfacesByIfIndex()
	entitiesForTarget = mapping.TranslateAsStack(entitiesForTarget, oids, ifIndexByIface,
		r.assetTagClaimer(fmt.Sprintf("%s:%d", targetHost, target.Port), log),
		targetDefaults.StackMemberNameTemplate, r.modelPin(targetDefaults, sysOID), log)

	// Module / module bay emission. Opt-in via options.discover_modules
	// (default = off -> zero behaviour change). Reuses the chassis-path
	// entAliasMappingTable index for iface <-> transceiver attachment.
	//
	// Diode ingest ordering contract:
	//   Device(s) -> module bay + module -> Interface -> IP -> MAC -> VLAN
	//
	// TranslateAsStack already partitioned entitiesForTarget into that
	// bucket order, but module entities land in their OWN bucket — naively
	// appending them would leave them at the tail and break ifaceModuleMap
	// attachment (Interfaces would appear BEFORE the Modules they reference).
	// Fix: partition-and-prepend. Find the first non-Device/non-VC index in
	// entitiesForTarget and splice moduleEntities there.
	//
	// Early-exit on mode=off so the default-path target poll skips the
	// ChassisInventoryFromOIDs re-parse + the entAliasMappingTable scan
	// entirely (both iterate the full oids map). Without this gate,
	// every target paid the scan cost even though TranslateModulesWithAlias
	// would short-circuit before emitting anything.
	if r.config.Options.ModuleDiscoveryMode() != config.DiscoverModulesOff {
		// TODO(orb-discovery): double-parse — TranslateAsStack already
		// ran extractInventory internally; ChassisInventoryFromOIDs
		// runs it again here. Cheap parse on string maps (no SNMP work
		// repeated), so left as-is for now. Refactor fallout:
		// TranslateAsStack call sites in mapping/chassis_test.go (9 sites)
		// would need to accept a pre-parsed inventory parameter; this
		// caller would then pass it directly instead of re-deriving via
		// ChassisInventoryFromOIDs. Defer until a broader runner cleanup.
		chassisInv := mapping.ChassisInventoryFromOIDs(oids, log)
		memberDevices := mapping.MemberDevicesFromEntities(entitiesForTarget, chassisInv)
		aliasMap := mapping.AliasMapFromOIDs(oids)

		moduleEntities, ifaceModuleMap := mapping.TranslateModulesWithAlias(
			oids, chassisInv, memberDevices,
			&r.config.Options, targetDefaults,
			log, aliasMap, r.moduleModels(),
		)

		entitiesForTarget = mapping.SpliceModulesAfterDevices(entitiesForTarget, moduleEntities)

		// Attach Interface.Module on physical-port Interfaces for `full` mode.
		// Order-safe because modules now precede interfaces in the slice.
		// Key by ifIndex (globally unique in the SNMP walk space) — keying
		// by Interface.Name would collide on VC members that reuse the same
		// canonical name locally. AttachIfaceModules also walks
		// IPAddress.AssignedObject / MACAddress.AssignedObject so L3
		// routed-port interfaces (filtered out of the top-level entity
		// slice by MapObjectIDsToEntity.getAssignedInterfaces) still get
		// their module set.
		mapping.AttachIfaceModules(entitiesForTarget, ifaceModuleMap, ifIndexByIface)
	}

	// Link-aggregation membership (default on, opt-out via
	// emit_lag_membership: false): set Interface.lag on each member port
	// from IEEE8023-LAG-MIB. Runs after stack translation so the member and
	// aggregate Device pointers already name the owning member.
	if r.config.Options.LagMembershipEnabled() {
		mapping.AttachLagMembership(oids, ifIndexByIface, log)
	}

	// VRF discovery: translate the walked VRF MIB rows (the columns are
	// only in the walk set when discover_vrfs is on) and attach the
	// discovered VRFs to the IP addresses of their member interfaces by
	// ifIndex — overwriting the vrf / vrf_ipv4 / vrf_ipv6 defaults for
	// those interfaces, which remain the fallback everywhere else. Runs
	// after stack translation so both single-device and stack paths are
	// covered; VRF entities append at the tail like VLANs (IP-attached
	// refs reconcile against them by name+rd).
	vrfByAddress := map[string]*diode.VRF{}
	if r.config.Options.VrfDiscoveryEnabled() {
		vrfEntities, vrfByIfIndex := mapping.TranslateVrfs(oids, targetDefaults, log)
		if len(vrfEntities) > 0 {
			vrfByAddress = mapping.AttachVrfs(entitiesForTarget, vrfByIfIndex, ifIndexByIface, log)
			// Addresses whose interface was never walked had their assignment
			// cleared during mapping, so AttachVrfs cannot reach them by
			// interface pointer. Recover their VRF from the ifIndex recorded
			// before the clear, or the discovered VRF would be lost for exactly
			// the addresses this backend already had to degrade.
			mapping.AttachVrfsToUnverified(
				mapper.UnverifiedAssignmentIfIndexes(), vrfByIfIndex, vrfByAddress, log,
			)
			entitiesForTarget = append(entitiesForTarget, vrfEntities...)
		}
	}

	// Resolve SVI VLANs before prefix derivation: VLAN entities are already
	// appended to entitiesForTarget by this point, and the resolver only
	// references VLANs the device's own VLAN tables report. Gated on the
	// option so a target pays nothing (no ifName/ifDescr rescan) when it's off.
	var sviVlanByIfIndex map[int]*diode.VLAN
	if r.config.Options.PrefixVlanMode() != "off" {
		sviVlanByIfIndex = mapping.ResolveSviVlans(oids, entitiesForTarget, log)
	}

	// Prefix derivation (default on, opt-out via emit_prefixes: false):
	// one Prefix per unique (network, VRF) derived from the discovered IP
	// addresses, matching device-discovery's behavior. Runs after VRF
	// attachment so prefixes of VRF-member addresses carry the discovered
	// VRF; everything else follows defaults.prefix.
	if r.config.Options.PrefixEmissionEnabled() {
		prefixEntities := mapping.DerivePrefixes(
			entitiesForTarget, vrfByAddress, sviVlanByIfIndex, ifIndexByIface,
			targetDefaults, &r.config.Options, log,
		)
		entitiesForTarget = append(entitiesForTarget, prefixEntities...)
	}

	entities = append(entities, entitiesForTarget...)

	// Update discovered hosts gauge
	if rMetric := metrics.GetDiscoveredHosts(); rMetric != nil {
		rMetric.Record(r.ctx, int64(len(entitiesForTarget)),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Capture the per-target cycle-closer primary IP hits and return them
	// by value so the caller can thread them into PruneNestedRefs without
	// any shared Runner state (concurrency-safe).
	return entities, mapper.PrimaryIPHits(), nil
}

func (r *Runner) expandTargetRanges(configuredTargets []config.Target) []expandedTargetGroup {
	expandedGroups := make([]expandedTargetGroup, 0, len(configuredTargets))
	for entry, target := range configuredTargets {
		originalHost := target.Host // Preserve original target string
		ips, err := targets.Expand(target.Host)
		if err != nil {
			r.logger.Warn("error expanding target host", "host", target.Host, "error", err)
			continue
		}

		expandedTargets := make([]config.Target, len(ips))
		for i := range ips {
			expandedTargets[i] = config.Target{
				Host:             ips[i],
				Port:             target.Port,
				Authentication:   target.Authentication,
				OverrideDefaults: target.OverrideDefaults,
			}
			if len(ips) == 1 && originalHost == ips[i] {
				expandedTargets[i].NetboxID = target.NetboxID
			}
		}
		expandedGroups = append(expandedGroups, expandedTargetGroup{
			originalTarget: originalHost,
			targets:        expandedTargets,
			entry:          entry,
			several:        len(ips) > 1,
		})
	}
	return expandedGroups
}

// maxProbeWorkers is how many addresses a scan probes at once.
const maxProbeWorkers = 256

// worstScanTime is how long probing addresses takes when none answers: each
// round of maxProbeWorkers waits out the probe timeout.
func worstScanTime(addresses int, probeTimeout time.Duration) time.Duration {
	rounds := (addresses + maxProbeWorkers - 1) / maxProbeWorkers
	return time.Duration(rounds) * probeTimeout
}

// warnSlowScan warns when a scan of the range may run out of time before it
// probes every address. Nothing else changes: the scan still crawls what it
// finds.
func (r *Runner) warnSlowScan(group expandedTargetGroup) {
	worst := worstScanTime(len(group.targets), r.snmpProbeTimeout)
	if worst <= r.timeout {
		return
	}
	r.logger.Warn("a scan of this target may run out of time before probing every address; raise timeout to probe them all",
		"target", group.originalTarget, "addresses", len(group.targets),
		"probe_time", worst.String(), "timeout", r.timeout.String())
}

// maxOverlapsNamed is how many pairs of entries an overlap warning names.
const maxOverlapsNamed = 5

// The warnings about entries that crawl the same hosts, one per kind.
const (
	hostListedTwiceWarning = "a host is listed on several entries; each crawls it, " +
		"and a crawl with credentials the host does not accept fails"
	sameCommunityOverlapWarning = "subnets or ranges probe the same hosts with the same version and community; " +
		"each crawls every host that answers"
	v3OverlapWarning = "SNMPv3 subnets or ranges reach the same hosts; SNMPv3 probes do not present the entry's user, " +
		"so each crawls every host that answers, and a crawl with credentials the host does not accept fails; " +
		"list such hosts on entries of their own, or use disjoint ranges"
	differentDefaultsWarning = "scope entries with different override_defaults reach the same hosts; " +
		"a host that answers several of these entries is sent with each entry's defaults in turn; " +
		"list such a host once, on a single entry of its own"
)

// probeKey is what a scan's probe presents. SNMPv1 and SNMPv2c send the
// entry's community; SNMPv3 sends a placeholder user whatever the entry's (see
// probeAuthentication), so its version alone.
type probeKey struct {
	version, community string
}

func probeKeyOf(auth config.Authentication) probeKey {
	if auth.ProtocolVersion == snmp.ProtocolVersion3 {
		return probeKey{version: auth.ProtocolVersion}
	}
	return probeKey{auth.ProtocolVersion, auth.Community}
}

// overlaps counts the pairs of entries of one kind, keeping only the ones a
// warning names.
type overlaps struct {
	named []string
	count int
}

func (o *overlaps) add(entry, other string) {
	o.count++
	if len(o.named) < maxOverlapsNamed {
		o.named = append(o.named, other+" with "+entry)
	}
}

// warnOverlappingEntries warns at load about entries that crawl the same hosts
// on the same port, with one line per kind:
//   - a host listed on several entries, each crawled with no probe;
//   - subnets or ranges whose probes present the same version and community:
//     a host that answers one answers all;
//   - SNMPv3 subnets or ranges, whose probes all present the same placeholder
//     user, so every one finds every SNMPv3 host;
//   - entries with different effective override_defaults, whatever their
//     credentials, since each sends a host it crawls with its own.
//
// Subnets or ranges probing with a different version or community are left
// out: each finds only the hosts that accept its own, which is how a range is
// scanned with several. Every entry still crawls what it finds. Hosts listed
// on their own leave every subnet or range first, so ranges that share only
// such hosts no longer overlap.
func (r *Runner) warnOverlappingEntries(groups []expandedTargetGroup) {
	type entry struct {
		name     string
		defaults *config.Defaults
	}
	type span struct {
		entry
		probe probeKey
		port  uint16
		addrs ipv4Span
	}
	var spans []span
	singles := make(map[string][]entry)
	listed := listedAddresses(groups)
	var listedTwice, sameCommunity, v3, differentDefaults overlaps
	for _, group := range groups {
		if len(group.targets) == 0 {
			continue
		}
		first := group.targets[0]
		// Each entry sends what it crawls with its own defaults, whatever its
		// credentials, so a host two entries crawl flips between them.
		this := entry{group.originalTarget, config.MergeDefaults(&r.config.Defaults, first.OverrideDefaults)}
		if !group.several {
			endpoint := endpointKey(first.Host, first.Port)
			for _, other := range singles[endpoint] {
				listedTwice.add(this.name, other.name)
				if !reflect.DeepEqual(this.defaults, other.defaults) {
					differentDefaults.add(this.name, other.name)
				}
			}
			singles[endpoint] = append(singles[endpoint], this)
			continue
		}
		// An expanded subnet or range runs in order from its first address
		// to its last.
		start, err1 := netip.ParseAddr(first.Host)
		end, err2 := netip.ParseAddr(group.targets[len(group.targets)-1].Host)
		if err1 != nil || err2 != nil || !start.Is4() || !end.Is4() {
			continue
		}
		auth := r.scope.Authentication
		if first.Authentication != nil {
			auth = *first.Authentication
		}
		thisSpan := span{this, probeKeyOf(auth), effectivePort(first.Port), ipv4Span{ipv4Value(start), ipv4Value(end)}}
		kind := &sameCommunity
		if auth.ProtocolVersion == snmp.ProtocolVersion3 {
			kind = &v3
		}
		for _, other := range spans {
			if other.port != thisSpan.port || !other.addrs.sharesHost(thisSpan.addrs, listed[thisSpan.port]) {
				continue
			}
			if other.probe == thisSpan.probe {
				kind.add(this.name, other.name)
			}
			if !reflect.DeepEqual(this.defaults, other.defaults) {
				differentDefaults.add(this.name, other.name)
			}
		}
		spans = append(spans, thisSpan)
	}
	r.warnOverlaps(hostListedTwiceWarning, listedTwice)
	r.warnOverlaps(sameCommunityOverlapWarning, sameCommunity)
	r.warnOverlaps(v3OverlapWarning, v3)
	r.warnOverlaps(differentDefaultsWarning, differentDefaults)
}

// ipv4Span is the addresses of an expanded subnet or range, first to last.
type ipv4Span struct {
	first, last uint32
}

// sharesHost reports whether two spans still share an address once the hosts
// listed on their own, sorted in listed, have left them both.
func (s ipv4Span) sharesHost(o ipv4Span, listed []uint32) bool {
	lo, hi := max(s.first, o.first), min(s.last, o.last)
	if lo > hi {
		return false
	}
	from, _ := slices.BinarySearch(listed, lo)
	to, found := slices.BinarySearch(listed, hi)
	if found {
		to++
	}
	return uint64(to-from) < uint64(hi-lo)+1
}

func ipv4Value(addr netip.Addr) uint32 {
	b := addr.As4()
	return binary.BigEndian.Uint32(b[:])
}

// listedAddresses returns, per port, the sorted IPv4 addresses of the hosts
// the policy lists as entries of their own, which leave every subnet or range
// as leaveOutOwnEntries takes them out.
func listedAddresses(groups []expandedTargetGroup) map[uint16][]uint32 {
	listed := make(map[uint16][]uint32)
	for _, group := range groups {
		if group.several || len(group.targets) != 1 {
			continue
		}
		addr, err := netip.ParseAddr(group.targets[0].Host)
		if err != nil || !addr.Is4() {
			continue
		}
		port := effectivePort(group.targets[0].Port)
		listed[port] = append(listed[port], ipv4Value(addr))
	}
	for port, addrs := range listed {
		slices.Sort(addrs)
		listed[port] = slices.Compact(addrs)
	}
	return listed
}

// warnOverlaps logs one warning naming the first pairs and counting the rest.
func (r *Runner) warnOverlaps(msg string, o overlaps) {
	if o.count == 0 {
		return
	}
	list := strings.Join(o.named, ", ")
	if more := o.count - len(o.named); more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	r.logger.Warn(msg, "entries", list)
}

// effectivePort is the port a target is scanned on: an unset port is 161.
func effectivePort(port uint16) uint16 {
	if port == 0 {
		return SNMPDefaultPort
	}
	return port
}

// maxLeftOutNamed is how many left-out hosts a range's load line names.
const maxLeftOutNamed = 10

// leaveOutOwnEntries takes out of each subnet or range the hosts the policy
// also lists as entries of their own, on the same port, so each is crawled
// once with its own entry's settings. A subnet or range left empty is dropped.
func (r *Runner) leaveOutOwnEntries(groups []expandedTargetGroup) []expandedTargetGroup {
	own := make(map[string]bool)
	for _, target := range r.scope.Targets {
		if endpoint, ok := endpointOf(target); ok {
			own[endpoint] = true
		}
	}
	if len(own) == 0 {
		return groups
	}
	kept := make([]expandedTargetGroup, 0, len(groups))
	for _, group := range groups {
		if group.several {
			group.targets = r.withoutOwnEntries(group, own)
			if len(group.targets) == 0 {
				continue
			}
		}
		kept = append(kept, group)
	}
	return kept
}

// withoutOwnEntries returns a range's hosts less those in own, and logs the
// ones it left out. It filters in place, so a large range is not copied.
func (r *Runner) withoutOwnEntries(group expandedTargetGroup, own map[string]bool) []config.Target {
	kept := group.targets[:0]
	var named []string
	leftOut := 0
	for _, target := range group.targets {
		if !own[endpointKey(target.Host, target.Port)] {
			kept = append(kept, target)
			continue
		}
		leftOut++
		if len(named) < maxLeftOutNamed {
			named = append(named, target.Host)
		}
	}
	if leftOut > 0 {
		list := strings.Join(named, ", ")
		if more := leftOut - len(named); more > 0 {
			list += fmt.Sprintf(" and %d more", more)
		}
		r.logger.Info("Leaving out "+list+", discovered from their own scope entries",
			"target", group.originalTarget)
	}
	return kept
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("starting policy runner")
	r.scheduler.Start()
}

// Stop stops the policy runner, and nothing of the policy is sent once it
// returns. Cancelling ctx first ends the scans and crawls under way, which the
// scheduler can wait for but not cut short. An ingest already under way is left
// to end while Shutdown waits for the running jobs, and is cancelled if that
// wait ends first. Shutdown, rather than StopJobs, answers a scan still asking
// the scheduler for jobs: StopJobs holds such a call until its timeout.
func (r *Runner) Stop() error {
	r.cancel(errPolicyStopped)
	err := r.scheduler.Shutdown()
	r.cancelIngest(errPolicyStopped)
	return err
}

// repairInvalidUTF8 repairs invalid UTF-8 in free text and logs each field it
// touched, so the operator can find the value on the device. It returns an
// error when any other field is invalid, and the target must then not be
// ingested.
func repairInvalidUTF8(log *slog.Logger, entities []diode.Entity) error {
	repaired, refused := mapping.RepairInvalidUTF8(entities)
	if len(refused) == 0 {
		for _, rep := range repaired {
			log.Warn(mapping.InvalidUTF8Warning,
				"entity", rep.Entity, "field", rep.Field, "count", rep.Count, "example", rep.Example)
		}
		return nil
	}
	fields := make([]string, 0, len(refused))
	for _, rep := range refused {
		log.Error(mapping.InvalidUTF8Refusal,
			"entity", rep.Entity, "field", rep.Field, "count", rep.Count, "example", rep.Example)
		fields = append(fields, rep.Entity+"."+rep.Field)
	}
	return fmt.Errorf("not ingested: invalid UTF-8 in %s", strings.Join(fields, ", "))
}

// warnUnscopedVLANs reports VLANs Diode cannot separate, once per runner. A
// runner is per policy, so a re-applied policy warns again, and the Once keeps
// concurrently scheduled targets from repeating it. The count test sits outside
// the Once so a target with nothing to report cannot burn it.
func (r *Runner) warnUnscopedVLANs(log *slog.Logger, entities []diode.Entity) {
	n := mapping.CountUnscopedVLANs(entities)
	if n == 0 {
		return
	}
	r.warnedUnscopedVLANs.Do(func() {
		log.Warn(mapping.UnscopedVLANWarning, "vlans", n)
	})
}
