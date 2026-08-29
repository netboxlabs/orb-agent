package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
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

func main() {
	host := flag.String("host", "0.0.0.0", "server host")
	port := flag.Int("port", 8078, "server port")
	otelEndpoint := flag.String("otel-endpoint", "", "OpenTelemetry exporter endpoint (e.g. localhost:4317)."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})")
	otelExportPeriod := flag.Int("otel-export-period", 10, "period in seconds between OpenTelemetry exports")
	snmpProfilesDir := flag.String("snmp-profiles-dir", "",
		"directory of ktranslate-compatible SNMP profile YAML files to overlay on the "+
			"profiles bundled into the binary. Files here replace bundled ones with the "+
			"same relative path; everything else is unaffected."+
			" Environment variable can be used by wrapping it in ${} (e.g. ${SNMP_PROFILES_DIR})")
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
	manager := policy.NewManager(rootCtx, logger, profilesDir)
	srv := server.NewServer(*host, *port, logger, manager, version.GetBuildVersion())

	// shutdownMetrics flushes on its own context: rootCtx is cancelled during
	// shutdown, and an exporter handed a cancelled context drops the last export.
	shutdownMetrics := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := metrics.Shutdown(ctx); err != nil {
			logger.Error("failed to shutdown metrics", "error", err)
		}
	}

	// Handle signals
	done := make(chan bool, 1)

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		for {
			select {
			case <-sigs:
				logger.Warn("stop signal received, stopping " + AppName)
				srv.Stop()
				shutdownMetrics()
				cancelFunc()
			case <-rootCtx.Done():
				logger.Warn("main context cancelled")
				done <- true
				return
			}
		}
	}()

	serverErrCh := srv.Start()

	go func() {
		if err, ok := <-serverErrCh; ok && err != nil {
			logger.Error(AppName+" server encountered an error", "error", err)
			srv.Stop()
			shutdownMetrics()
			cancelFunc()
		}
	}()

	<-done
}
