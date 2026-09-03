package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/env"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/metrics"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/policy"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/profiles"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/server"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/traps"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/version"
)

// AppName is the application name
const AppName = "snmp-telemetry"

// metricsFlushTimeout bounds the final export at shutdown.
const metricsFlushTimeout = 5 * time.Second

// defaultHost is the address the policy API binds unless --host says otherwise.
// The API has no authentication, so anyone who can route to the listener can
// create policies, and a policy names both the credentials to send and the host
// to send them to. The agent runs this backend as a child process and reaches it
// on the loopback interface, so binding there costs nothing and leaves no remote
// caller. An operator who binds it wider is publishing an unauthenticated API
// and has to put their own access control in front of it.
const defaultHost = "localhost"

// stopper is the part of the server the shutdown sequence uses.
type stopper interface {
	Stop()
}

// closer is the part of the tally the shutdown sequence uses.
type closer interface {
	Close()
}

// shutdown unwinds the process in the order the export and the runners need.
//
// The flush comes first, before anything has been cancelled. Every runner
// context derives from the root one, so cancelling it makes an in-flight
// collection return a context error, and a collection whose run was cut short
// that way keeps its device only for a bounded number of consecutive
// interruptions before the observations it had stored are deleted. A flush
// placed after the cancellation therefore races that deletion for exactly the
// readings it is there to export, on any device already interrupted on the
// preceding cycles, and a deletion that wins empties the final export for it.
// Exporting first settles the race for every device rather than for most of
// them, since the store the flush reads still holds them all.
//
// The cancellation then comes before the server stop, which is what lets
// srv.Stop return: stopping the server first would wait on collections that
// have not been told to finish, a wait as long as the SNMP timeouts still
// outstanding.
//
// The server stop comes last because every metric this backend exports is an
// observable gauge reading the collector's observation store, and stopping the
// server stops the runners, which forget their policies, then releases their
// collectors, which unregisters the callbacks. A flush after that carries no
// SNMP data at all, which with a long export period is everything observed
// since the last periodic export. Nothing is recorded during srv.Stop, so
// running it after the meter provider has shut down drops no measurement, and
// unregistering a callback on a provider that has shut down is a list removal
// the SDK still honors.
//
// Exporting before the cancellation costs the readings of a collection that
// completes between the two, and runs the flush's timeout while collections are
// still going. That is one cycle of freshness against the whole interval the
// race could cost.
//
// Trap intake closes first. The tally is a map the export callback reads, so
// a trap counted after that callback's final run would sit in the map and
// never be exported, and the tally is closed right after. Closing the sockets
// ahead of the flush means every trap the process counted is in the final
// export, at the cost of up to the receiver's stop bound per socket spent
// before the flush rather than after it. The poll side keeps its order: the
// flush precedes the cancel so a running collection's observations are
// exported before they are forgotten, and the server stops last.
func shutdown(cancelRoot context.CancelFunc, intake closer, srv stopper, flush func()) {
	intake.Close()
	flush()
	cancelRoot()
	srv.Stop()
}

// flushMetrics exports whatever the meter provider still holds. It takes its
// own context rather than the root one because the shutdown sequence can be
// entered on a root that is already cancelled, and an exporter handed a
// cancelled context drops the export.
func flushMetrics(logger *slog.Logger, timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := metrics.Shutdown(ctx); err != nil {
		logger.Error("failed to shutdown metrics", "error", err)
	}
}

func main() {
	host := flag.String("host", defaultHost, "server host")
	port := flag.Int("port", 8078, "server port")
	otelEndpoint := flag.String("otel-endpoint", "", "OpenTelemetry exporter endpoint (e.g. localhost:4317)."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})")
	otelExportPeriod := flag.Int("otel-export-period", 10,
		fmt.Sprintf("period in seconds between OpenTelemetry exports, from 1 to %d (one year)",
			config.MaxDurationSeconds))
	snmpProfilesDir := flag.String("snmp-profiles-dir", "",
		"directory of ktranslate-compatible SNMP profile YAML files to overlay on the "+
			"profiles bundled into the binary. Files here replace bundled ones with the "+
			"same relative path; everything else is unaffected."+
			" Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_DIR})")
	policyEnvVars := flag.String("policy-env-vars", "",
		"comma-separated environment variable names a policy may read through a ${NAME} "+
			"reference in community, username, auth_passphrase or priv_passphrase. Empty, "+
			"the default, rejects every reference.")
	snmpProfilesRoot := flag.String("snmp-profiles-root", "",
		"directory a policy's own profiles_dir must resolve inside. A policy names an absolute "+
			"path under it, or one relative to it. Empty, the default, rejects every per-policy "+
			"profiles_dir."+
			" Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_ROOT})")
	logLevel := flag.String("log-level", "INFO", "log level (DEBUG, INFO, WARN, ERROR)")
	logFormat := flag.String("log-format", "TEXT", "log format (TEXT, JSON)")
	help := flag.Bool("help", false, "show this help")

	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", AppName)
		flag.PrintDefaults()
		os.Exit(0)
	}

	logger := config.NewLogger(*logLevel, *logFormat)
	logger.Info("starting "+AppName, "version", version.GetBuildVersion())

	// The policy manager derives every runner context from this one, so it is
	// created before the manager: handing it context.Background() would leave
	// in-flight collections running after a stop signal.
	rootCtx, cancelFunc := context.WithCancel(context.Background())

	endpoint := env.ResolveEnvOrExit(*otelEndpoint)
	if endpoint != "" {
		if err := metrics.SetupMetricsExport(rootCtx, logger, endpoint, *otelExportPeriod); err != nil {
			logger.Error("Failed to setup metrics export", "error", err)
			os.Exit(1)
		}
		logger.Info("Metrics export configured", "endpoint", endpoint, "period_seconds", *otelExportPeriod)
	}

	profilesDir := env.ResolveEnvOrExit(*snmpProfilesDir)
	trapNames, err := loadTrapNames(profilesDir, logger)
	if err != nil {
		logger.Error("Failed to load trap definitions", "error", err)
		os.Exit(1)
	}
	trapTally := traps.NewTally(logger)
	trapTally.Register()
	pool := traps.NewPool(trapTally, trapNames, logger)
	manager := policy.NewManager(rootCtx, logger, policy.Options{
		DefaultProfilesDir: profilesDir,
		ProfilesRoot:       env.ResolveEnvOrExit(*snmpProfilesRoot),
		AllowedEnvVars:     splitList(*policyEnvVars),
		TrapPool:           newTrapPool(pool),
	})
	srv := server.NewServer(*host, *port, logger, manager, version.GetBuildVersion())

	shutdownMetrics := func() { flushMetrics(logger, metricsFlushTimeout) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	serverErrCh := srv.Start()

	shutdownStopper := stopAll{tally: trapTally, server: srv}

	waitForShutdown(rootCtx, logger, sigs, serverErrCh, func() {
		shutdown(cancelFunc, pool, shutdownStopper, shutdownMetrics)
	})
}

// loadTrapNames builds the closed trap-name set from the bundled profile tree
// plus the operator's override directory. Every receiver labels with it, so
// it is built once here whether or not any policy declares traps; the manager
// loads the same tree per profiles directory for its collectors and there is
// no shared handle to borrow.
func loadTrapNames(profilesDir string, logger *slog.Logger) (map[string]string, error) {
	loader, err := profiles.LoadProfiles(profilesDir, logger)
	if err != nil {
		return nil, fmt.Errorf("loading trap definitions: %w", err)
	}
	all, err := loader.AllResolved()
	if err != nil {
		return nil, fmt.Errorf("resolving trap definitions: %w", err)
	}
	return traps.BuildNames(profiles.TrapNames(all)), nil
}

// trapPool adapts *traps.Pool to policy.TrapPool. The pool returns its own
// *traps.Lease and the interface names policy.TrapLease; Go does not widen a
// return type, so the widening happens here, and the error path returns an
// untyped nil so the caller's nil check holds.
//
// It lives in cmd because traps never imports policy: the pool belongs to
// traps, the caller belongs to policy, and the only place that knows both is
// the process that wires them together.
type trapPool struct {
	pool *traps.Pool
}

func newTrapPool(pool *traps.Pool) trapPool {
	return trapPool{pool: pool}
}

func (p trapPool) Acquire(listen, policyName string, devices []traps.Device) (policy.TrapLease, error) {
	lease, err := p.pool.Acquire(listen, policyName, devices)
	if err != nil {
		return nil, err
	}
	return lease, nil
}

// stopAll closes the tally, then the server. Both run after the final flush,
// so neither spends the flush's budget. The trap sockets are not here: they
// close in shutdown ahead of the flush, so that everything they counted is
// in it.
type stopAll struct {
	tally  closer
	server stopper
}

func (s stopAll) Stop() {
	s.tally.Close()
	s.server.Stop()
}

// splitList reads a comma-separated flag value as its non-empty, trimmed
// entries. A trailing comma or a padded name would otherwise become an entry
// that matches nothing, which on an allowlist reads as a name that was granted.
func splitList(value string) []string {
	var out []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// waitForShutdown blocks until a stop signal or a server error asks the process
// to stop, and returns only once the shutdown sequence has finished. Both paths
// go through one sync.Once: the sequence cancels the root context on its first
// step, so a caller that released main on that cancellation would let the
// process exit through the server stop and the final export.
func waitForShutdown(rootCtx context.Context, logger *slog.Logger, sigs <-chan os.Signal, serverErrCh <-chan error, run func()) {
	done := make(chan struct{})
	var once sync.Once
	trigger := func() {
		once.Do(func() {
			run()
			close(done)
		})
	}

	go func() {
		select {
		case <-sigs:
			logger.Warn("stop signal received, stopping " + AppName)
		case <-rootCtx.Done():
			logger.Warn("main context cancelled")
		}
		trigger()
	}()

	go func() {
		if err, ok := <-serverErrCh; ok && err != nil {
			logger.Error(AppName+" server encountered an error", "error", err)
			trigger()
		}
	}()

	<-done
}
