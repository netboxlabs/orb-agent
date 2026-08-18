package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
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
}

// Runner represents the policy runner
type Runner struct {
	scheduler        gocron.Scheduler
	ctx              context.Context
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
}

// NewRunner returns a new policy runner
func NewRunner(ctx context.Context, logger *slog.Logger, name string, policy config.Policy, client diode.Client, ClientFactory snmp.ClientFactory, mappingConfig *config.Mapping, manufacturers data.ManufacturerRetriever, deviceLookup data.DeviceRetriever, runStore *RunStore) (*Runner, error) {
	s, err := gocron.NewScheduler()
	if err != nil {
		return nil, err
	}

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
	runner.ctx = context.WithValue(ctx, policyKey, name)
	runner.scope = policy.Scope
	runner.config = policy.Config

	expandedTargetGroups := runner.expandTargetRanges(runner.scope.Targets)

	for _, group := range expandedTargetGroups {
		if len(group.targets) == 1 {
			// Create scan task for single target
			task := gocron.NewTask(runner.run, group.targets[0])
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
		task := gocron.NewTask(runner.runScanWithOriginal, group.targets, group.originalTarget)
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
	return runner, nil
}

func (r *Runner) runScanWithOriginal(targets []config.Target, originalTarget string) {
	policyName := r.ctx.Value(policyKey).(string)

	// All expanded targets have the same port, get it from the first target
	port := uint16(161) // default
	if len(targets) > 0 {
		port = targets[0].Port
	}

	// Create run for the scan operation (includes port)
	scanRun := r.runStore.CreateRun(policyName, originalTarget, port, "")

	r.logger.Info("starting SNMP probe scan", "policy", policyName, "target", originalTarget, "target_count", len(targets))
	workerCount := min(256, len(targets))

	ctx, cancel := context.WithTimeout(r.ctx, r.timeout)
	defer cancel()

	targetCh := make(chan config.Target)
	resultsCh := make(chan config.Target, workerCount)

	var wg sync.WaitGroup
	wg.Add(workerCount)
	for range workerCount {
		go func() {
			defer wg.Done()
			for target := range targetCh {
				if r.probeTarget(ctx, target) {
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
		r.logger.Debug("SNMP probe succeeded", "host", target.Host, "port", target.Port, "policy", policyName)
	}

	// Snapshot live job IDs before the loop to avoid holding two locks simultaneously.
	// Done here (before early returns) so stale entries are pruned on every probe invocation,
	// including the zero-responsive and context-timeout paths.
	jobs := r.scheduler.Jobs()
	liveIDs := make(map[uuid.UUID]struct{}, len(jobs))
	for _, j := range jobs {
		liveIDs[j.ID()] = struct{}{}
	}

	// Prune stale host->job mappings for this originalTarget only.
	// Scoped to the current range to avoid deleting entries freshly added by a concurrent
	// runScanWithOriginal invocation for a different range target in the same policy.
	keyPrefix := originalTarget + "::"
	r.activeHostJobsMu.Lock()
	for jobKey, jobID := range r.activeHostJobs {
		if strings.HasPrefix(jobKey, keyPrefix) {
			if _, alive := liveIDs[jobID]; !alive {
				delete(r.activeHostJobs, jobKey)
			}
		}
	}
	r.activeHostJobsMu.Unlock()

	// Check if context was canceled or timed out
	if ctxErr := ctx.Err(); ctxErr != nil {
		r.logger.Warn("SNMP probe scan interrupted", "policy", policyName, "error", ctxErr, "responsive_target_count", len(responsive))
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusFailed, ctxErr, len(responsive))
		return
	}

	if len(responsive) == 0 {
		r.logger.Warn("no hosts responded to SNMP probe",
			"policy", policyName, "target", originalTarget)
		r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID,
			RunStatusFailed, fmt.Errorf("no hosts responded to SNMP probe"), 0)
		return
	}

	var err error
	for _, target := range responsive {
		jobKey := fmt.Sprintf("%s::%s:%d", originalTarget, target.Host, target.Port)

		// Check under lock, then unlock before calling scheduler to avoid holding mutex
		// across scheduler's internal locks.
		r.activeHostJobsMu.Lock()
		if existingID, ok := r.activeHostJobs[jobKey]; ok {
			if _, alive := liveIDs[existingID]; alive {
				r.activeHostJobsMu.Unlock()
				r.logger.Debug("crawl job already active, skipping",
					"host", target.Host, "policy", policyName)
				continue
			}
		}
		r.activeHostJobsMu.Unlock()

		task := gocron.NewTask(r.runWithMetadata, target, originalTarget)
		var newJob gocron.Job
		if r.config.Schedule != nil {
			newJob, err = r.scheduler.NewJob(gocron.CronJob(*r.config.Schedule, false), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		} else {
			newJob, err = r.scheduler.NewJob(gocron.OneTimeJob(
				gocron.OneTimeJobStartDateTime(time.Now().Add(1*time.Second))), task,
				gocron.WithSingletonMode(gocron.LimitModeReschedule))
		}
		if err != nil {
			r.logger.Error("failed to schedule crawl task for responsive target",
				"host", target.Host, "policy", policyName, "error", err)
			continue
		}

		r.activeHostJobsMu.Lock()
		r.activeHostJobs[jobKey] = newJob.ID()
		liveIDs[newJob.ID()] = struct{}{} // keep snapshot current for remaining iterations
		r.activeHostJobsMu.Unlock()
	}

	// Update scan run status
	r.runStore.UpdateRun(policyName, originalTarget, port, scanRun.ID, RunStatusCompleted, nil, len(responsive))
	r.logger.Info("SNMP probe scan complete", "policy", policyName, "responsive_target_count", len(responsive))
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

func (r *Runner) probeTarget(ctx context.Context, target config.Target) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	auth := r.resolveTargetAuthentication(target)

	snmpClient, err := r.ClientFactory(target.Host, target.Port, 0, r.snmpProbeTimeout, auth, r.logger)
	if err != nil {
		return false
	}
	defer func() {
		_ = snmpClient.Close()
	}()

	if err := snmpClient.Connect(); err != nil {
		return false
	}

	_, err = snmpClient.Walk(defaultSNMPProbeOID, 0)
	return err == nil
}

// run runs the policy for a single target (no parent)
func (r *Runner) run(target config.Target) {
	r.runWithMetadata(target, "")
}

// runWithMetadata runs the policy with metadata tracking
func (r *Runner) runWithMetadata(target config.Target, parentTarget string) {
	policyName := r.ctx.Value(policyKey).(string)
	targetHost := target.Host
	targetPort := target.Port

	// Create run at start (includes port)
	run := r.runStore.CreateRun(policyName, targetHost, targetPort, parentTarget)

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

	entities, primaryHits, err := r.queryTarget(ctx, target)
	if err != nil {
		r.logger.Error("error querying target", "host", target.Host, "error", err, "policy", policyName)
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, 0)
		return
	}
	r.logger.Info("SNMP crawl complete", "host", target.Host, "policy", policyName, "entity_count", len(entities))

	if len(entities) == 0 {
		r.logger.Info("no entities to ingest", "host", target.Host, "policy", policyName)
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
		targetHost,
		r.logger,
	)
	annotateEntitiesWithRunID(entities, run.ID)
	r.logEntitiesForIngestion(entities)

	// Strip nested Device/Interface refs to matcher-only stubs to shrink
	// the wire payload. Runs after annotation so the annotators can walk
	// the rich shared graph with their unsafe.Pointer dedup intact —
	// otherwise every stub would need its own metadata pass.
	mapping.PruneNestedRefs(entities, currentDevice, primaryHits)

	resp, err := r.client.Ingest(r.ctx, entities, diode.WithIngestMetadata(diode.Metadata{
		"policy_name": policyName,
		"run_id":      run.ID,
	}))
	if err != nil {
		r.logger.Error("error ingesting entities", "host", target.Host, "error", err, "policy", policyName, "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, err, len(entities))
	} else if resp != nil && resp.Errors != nil {
		ingestErr := fmt.Errorf("ingestion errors: %v", resp.Errors)
		r.logger.Error("error ingesting entities", "host", target.Host, "error", resp.Errors, "policy", policyName, "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusFailed, ingestErr, len(entities))
	} else {
		r.logger.Info("entities ingested successfully", "host", target.Host, "policy", policyName, "entity_count", len(entities))
		r.runStore.UpdateRun(policyName, targetHost, targetPort, run.ID, RunStatusCompleted, nil, len(entities))
	}
}

func (r *Runner) logEntitiesForIngestion(entities []diode.Entity) {
	for _, entity := range entities {
		r.logger.Debug("entity for ingestion", "entity", entity.ConvertToProtoMessage())
	}
}

// assetTagClaimer returns the per-target claim callback handed to
// mapping.TranslateAsStack. targetID must uniquely identify the target
// within this policy — host:port, matching the runner's job identity —
// NOT the bare host: two agents on one host behind different ports are
// distinct devices, and keying by host alone would let them share a
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
func (r *Runner) assetTagClaimer(targetID string) func(string) bool {
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
		r.logger.Warn("asset tag skipped: already discovered on another target of this policy",
			"asset_tag", tag, "target", targetID, "owner_target", owner)
		return false
	}
}

// queryTarget walks the target, maps the result to entities, and returns
// the entity slice along with the per-target set of cycle-closer primary
// IP entities (the top-level ipam.ipaddress entities that set a device's
// primary IP). The hits are returned by value — never stashed on the
// shared Runner, which serves targets concurrently — so the caller can
// thread them into PruneNestedRefs for this target only.
func (r *Runner) queryTarget(ctx context.Context, target config.Target) ([]diode.Entity, map[*diode.IPAddress]bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	targetDefaults := r.resolveTargetDefaults(target)

	mappingConfig, err := mapping.NewConfig(r.mappingConfig.Entries, r.logger, r.manufacturers, r.deviceLookup, targetDefaults, r.config.Options)
	if err != nil {
		r.logger.Error("error creating mapping config", "error", err)
		return nil, nil, err
	}
	targetHost := strings.TrimSpace(target.Host)

	mapper := mapping.NewObjectIDMapper(mappingConfig, r.logger, targetDefaults, targetHost)
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

	host := snmp.NewHost(targetHost, target.Port, r.config.Retries, r.snmpTimeout, auth, r.logger, r.ClientFactory)

	type walkResult struct {
		oids mapping.ObjectIDValueMap
		err  error
	}

	// Phase 1: walk generic OIDs (sysObjectID/sysDescr included).
	genericOIDs := mappingConfig.GenericObjectIDs()
	r.logger.Info("querying target", "host", targetHost, "port", target.Port, "object_count", len(genericOIDs))
	r.logger.Debug("phase 1 walk", "host", targetHost, "oid_count", len(genericOIDs))

	// The buffered channel ensures the goroutine can always send its result and exit,
	// even if we have already returned due to context cancellation. The goroutine is
	// bounded by snmpTimeout (set on the SNMP client), so it is not a permanent leak.
	resultCh := make(chan walkResult, 1)
	go func() {
		oids, err := host.Walk(genericOIDs)
		resultCh <- walkResult{oids, err}
	}()

	var oids mapping.ObjectIDValueMap
	select {
	case <-ctx.Done():
		if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
			rMetric.Add(r.ctx, 1,
				metric.WithAttributes(
					attribute.String("policy", policyName),
					attribute.String("error", ctx.Err().Error()),
				))
		}
		return nil, nil, ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			r.logger.Warn("error crawling host", "host", targetHost, "error", res.err)
			if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
				rMetric.Add(r.ctx, 1,
					metric.WithAttributes(
						attribute.String("policy", policyName),
						attribute.String("error", res.err.Error()),
					))
			}
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
			r.logger.Debug("phase 2 walk",
				"host", targetHost, "vendor", vendor, "oid_count", len(vendorOIDs))
			vendorCh := make(chan walkResult, 1)
			go func() {
				out, err := host.Walk(vendorOIDs)
				vendorCh <- walkResult{out, err}
			}()
			select {
			case <-ctx.Done():
				// Mirror the phase-1 ctx.Done() handling: record the
				// failure metric and return. Latency on the failure
				// path is captured by runWithMetadata's defer (the
				// outermost scope), which fires regardless of how
				// queryTarget exits, so we deliberately don't record
				// latency here.
				if rMetric := metrics.GetDiscoveryFailure(); rMetric != nil {
					rMetric.Add(r.ctx, 1,
						metric.WithAttributes(
							attribute.String("policy", policyName),
							attribute.String("error", ctx.Err().Error()),
						))
				}
				return nil, nil, ctx.Err()
			case res := <-vendorCh:
				if res.err != nil {
					r.logger.Warn("phase 2 walk failed; continuing with generic only",
						"host", targetHost, "vendor", vendor, "error", res.err)
				} else {
					for k, v := range res.oids {
						oids[k] = v
					}
				}
			}
		}
	} else {
		r.logger.Debug("no vendor matched; generic-only path", "host", targetHost)
	}

	// Track successful discovery
	if rMetric := metrics.GetDiscoverySuccess(); rMetric != nil {
		rMetric.Add(r.ctx, 1,
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	// Record discovery latency
	if rMetric := metrics.GetDiscoveryLatency(); rMetric != nil {
		rMetric.Record(r.ctx, time.Since(startTime).Seconds(),
			metric.WithAttributes(
				attribute.String("policy", policyName)))
	}

	entities := make([]diode.Entity, 0)
	entitiesForTarget := mapper.MapObjectIDsToEntity(oids)
	ifIndexByIface := mapper.InterfacesByIfIndex()
	entitiesForTarget = mapping.TranslateAsStack(entitiesForTarget, oids, ifIndexByIface,
		r.assetTagClaimer(fmt.Sprintf("%s:%d", targetHost, target.Port)), r.logger)

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
		chassisInv := mapping.ChassisInventoryFromOIDs(oids, r.logger)
		memberDevices := mapping.MemberDevicesFromEntities(entitiesForTarget, chassisInv)
		aliasMap := mapping.AliasMapFromOIDs(oids)

		moduleEntities, ifaceModuleMap := mapping.TranslateModulesWithAlias(
			oids, chassisInv, memberDevices,
			&r.config.Options, targetDefaults,
			r.logger, aliasMap,
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
		vrfEntities, vrfByIfIndex := mapping.TranslateVrfs(oids, targetDefaults, r.logger)
		if len(vrfEntities) > 0 {
			vrfByAddress = mapping.AttachVrfs(entitiesForTarget, vrfByIfIndex, ifIndexByIface, r.logger)
			// Addresses whose interface was never walked had their assignment
			// cleared during mapping, so AttachVrfs cannot reach them by
			// interface pointer. Recover their VRF from the ifIndex recorded
			// before the clear, or the discovered VRF would be lost for exactly
			// the addresses this backend already had to degrade.
			mapping.AttachVrfsToUnverified(
				mapper.UnverifiedAssignmentIfIndexes(), vrfByIfIndex, vrfByAddress, r.logger,
			)
			entitiesForTarget = append(entitiesForTarget, vrfEntities...)
		}
	}

	// Prefix derivation (default on, opt-out via emit_prefixes: false):
	// one Prefix per unique (network, VRF) derived from the discovered IP
	// addresses, matching device-discovery's behavior. Runs after VRF
	// attachment so prefixes of VRF-member addresses carry the discovered
	// VRF; everything else follows defaults.prefix.
	if r.config.Options.PrefixEmissionEnabled() {
		prefixEntities := mapping.DerivePrefixes(
			entitiesForTarget, vrfByAddress, targetDefaults, &r.config.Options, r.logger,
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
	for _, target := range configuredTargets {
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
		})
	}
	return expandedGroups
}

// Start starts the policy runner
func (r *Runner) Start() {
	r.logger.Info("starting policy runner", "policy", r.ctx.Value(policyKey))
	r.scheduler.Start()
}

// Stop stops the policy runner
func (r *Runner) Stop() error {
	if err := r.scheduler.StopJobs(); err != nil {
		return err
	}
	return r.scheduler.Shutdown()
}
