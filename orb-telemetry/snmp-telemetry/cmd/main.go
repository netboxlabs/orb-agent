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
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/server"
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

// shutdown unwinds the process in the order the runners need. Every runner
// context derives from the root one, so cancelling it first is what lets
// srv.Stop return: stopping the server first would wait on collections that
// have not been told to finish, a wait as long as the SNMP timeouts still
// outstanding. The flush runs last and on its own context, so the cancellation
// does not cost the last export.
func shutdown(cancelRoot context.CancelFunc, srv stopper, flush func()) {
	cancelRoot()
	srv.Stop()
	flush()
}

// flushMetrics exports whatever the meter provider still holds. It takes its
// own context because the root one is already cancelled by the time it runs,
// and an exporter handed a cancelled context drops the export.
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
		"period in seconds between OpenTelemetry exports, greater than 0")
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
	manager := policy.NewManager(rootCtx, logger, policy.Options{
		DefaultProfilesDir: profilesDir,
		ProfilesRoot:       env.ResolveEnvOrExit(*snmpProfilesRoot),
		AllowedEnvVars:     splitList(*policyEnvVars),
	})
	srv := server.NewServer(*host, *port, logger, manager, version.GetBuildVersion())

	shutdownMetrics := func() { flushMetrics(logger, metricsFlushTimeout) }

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	serverErrCh := srv.Start()

	waitForShutdown(rootCtx, logger, sigs, serverErrCh, func() {
		shutdown(cancelFunc, srv, shutdownMetrics)
	})
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
