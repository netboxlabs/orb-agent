package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/data"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/env"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/server"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/version"
)

// AppName is the application name
const AppName = "snmp-discovery"

func main() {
	host := flag.String("host", "0.0.0.0", "server host")
	port := flag.Int("port", 8070, "server port")
	diodeTarget := flag.String("diode-target", "", "diode target."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_TARGET})")
	diodeClientID := flag.String("diode-client-id", "", "diode client ID."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_ID})")
	diodeClientSecret := flag.String("diode-client-secret", "", "diode client secret."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${DIODE_CLIENT_SECRET})")
	diodeAppNamePrefix := flag.String("diode-app-name-prefix", "", "diode producer_app_name prefix")
	dryRun := flag.Bool("dry-run", false, "run in dry-run mode, do not ingest data")
	dryRunOutputDir := flag.String("dry-run-output-dir", "", "output dir for dry-run mode. "+
		" Environment variable can be used by wrapping it in ${} (e.g. ${DRY_RUN_OUTPUT_DIR})")
	logLevel := flag.String("log-level", "INFO", "log level")
	logFormat := flag.String("log-format", "TEXT", "log format")
	help := flag.Bool("help", false, "show this help")
	// Add new flags for metrics
	otelEndpoint := flag.String("otel-endpoint", "", "OpenTelemetry exporter endpoint (e.g. localhost:4317)."+
		" Environment variable can be used by wrapping it in ${} (e.g. ${OTEL_ENDPOINT})")
	otelExportPeriod := flag.Int("otel-export-period", 10, "Period in seconds between OpenTelemetry exports")

	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stderr, "Usage of snmp-discovery:\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if !*dryRun && (*diodeTarget == "" || *diodeClientID == "" || *diodeClientSecret == "") {
		fmt.Fprintf(os.Stderr, "Usage of snmp-discovery:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	producerName := AppName
	if *diodeAppNamePrefix != "" {
		producerName = fmt.Sprintf("%s/%s", *diodeAppNamePrefix, AppName)
	}

	var client diode.Client
	var err error
	if *dryRun {
		client, err = diode.NewDryRunClient(
			producerName,
			env.ResolveEnvOrExit(*dryRunOutputDir),
		)
	} else {
		client, err = diode.NewClient(
			env.ResolveEnvOrExit(*diodeTarget),
			producerName,
			version.GetBuildVersion(),
			diode.WithClientID(env.ResolveEnvOrExit(*diodeClientID)),
			diode.WithClientSecret(env.ResolveEnvOrExit(*diodeClientSecret)),
		)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating diode client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	logger := config.NewLogger(*logLevel, *logFormat)

	if otelEndpoint != nil && *otelEndpoint != "" {
		if err := metrics.SetupMetricsExport(ctx, logger, *otelEndpoint, *otelExportPeriod); err != nil {
			logger.Error("failed to setup metrics export", "error", err)
			os.Exit(1)
		}
		logger.Info("Metrics export configured", slog.String("endpoint", *otelEndpoint), slog.Int("period_seconds", *otelExportPeriod))
	}

	manufacturers, err := data.NewManufacturerLookup()
	if err != nil {
		logger.Error("Failed to load manufacturer lookup", "error", err)
		os.Exit(1)
	}

	policyManager, err := policy.NewManager(ctx, logger, client, manufacturers)
	if err != nil {
		logger.Error("failed to create policy manager", "error", err)
		os.Exit(1)
	}
	server := server.NewServer(*host, *port, logger, policyManager, version.GetBuildVersion())

	// handle signals
	done := make(chan bool, 1)
	rootCtx, cancelFunc := context.WithCancel(context.Background())

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		for {
			select {
			case <-sigs:
				logger.Warn("stop signal received, stopping snmp-discovery")
				server.Stop()
				// Shutdown metrics
				if err := metrics.Shutdown(ctx); err != nil {
					logger.Error("failed to shutdown metrics", "error", err)
				}
				cancelFunc()
			case <-rootCtx.Done():
				logger.Warn("main context cancelled")
				done <- true
				return
			}
		}
	}()

	serverErrCh := server.Start()

	go func() {
		if err, ok := <-serverErrCh; ok && err != nil {
			logger.Error("snmp-discovery server encountered an error", "error", err)
			server.Stop()
			if shutdownErr := metrics.Shutdown(ctx); shutdownErr != nil {
				logger.Error("failed to shutdown metrics", "error", shutdownErr)
			}
			cancelFunc()
		}
	}()

	<-done
}
