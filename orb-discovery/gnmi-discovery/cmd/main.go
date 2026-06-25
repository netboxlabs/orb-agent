package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/env"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/metrics"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/policy"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/server"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/version"
)

// AppName is the application name
const AppName = "gnmi-discovery"

func main() {
	host := flag.String("host", "0.0.0.0", "server host")
	port := flag.Int("port", 8075, "server port")
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
	profilesDir := flag.String("profiles-dir", "", "directory of gNMI profile overrides")

	flag.Parse()

	if *help {
		fmt.Fprintf(os.Stderr, "Usage of gnmi-discovery:\n")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if !*dryRun && (*diodeTarget == "") {
		fmt.Fprintf(os.Stderr, "Usage of gnmi-discovery:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	producerName := AppName
	if *diodeAppNamePrefix != "" {
		producerName = fmt.Sprintf("%s/%s", *diodeAppNamePrefix, AppName)
	}

	logger := config.NewLogger(*logLevel, *logFormat)

	var client diode.Client
	var err error
	if *dryRun {
		client, err = diode.NewDryRunClient(
			producerName,
			env.ResolveEnvOrExit(*dryRunOutputDir),
		)
	} else if *diodeClientID != "" && *diodeClientSecret != "" {
		client, err = diode.NewClient(
			env.ResolveEnvOrExit(*diodeTarget),
			producerName,
			version.GetBuildVersion(),
			diode.WithClientID(env.ResolveEnvOrExit(*diodeClientID)),
			diode.WithClientSecret(env.ResolveEnvOrExit(*diodeClientSecret)),
		)
	} else if *diodeClientID != "" || *diodeClientSecret != "" {
		// Exactly one credential flag set → partial config would silently produce
		// confusing auth failures. Fail fast: require both together (or neither, to
		// use the unauthenticated OTLP path).
		fmt.Fprintln(os.Stderr, "error: --diode-client-id and --diode-client-secret must be set together")
		os.Exit(1)
	} else {
		logger.Debug("initializing OTLP client")
		client, err = diode.NewOTLPClient(
			env.ResolveEnvOrExit(*diodeTarget),
			producerName,
			version.GetBuildVersion(),
		)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating diode client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	if otelEndpoint != nil && *otelEndpoint != "" {
		// Resolve ${ENV} placeholders like the diode/profiles flags do, so
		// --otel-endpoint '${OTEL_ENDPOINT}' targets the real collector instead of
		// exporting to the literal placeholder.
		resolvedOtel := env.ResolveEnvOrExit(*otelEndpoint)
		if err := metrics.SetupMetricsExport(ctx, logger, resolvedOtel, *otelExportPeriod); err != nil {
			logger.Error("failed to setup metrics export", "error", err)
			os.Exit(1)
		}
		logger.Info("metrics export configured", "endpoint", resolvedOtel, "period_seconds", *otelExportPeriod)
	}

	dialer := &gnmi.GnmicDialer{}
	policyManager, err := policy.NewManager(ctx, logger, client, dialer, env.ResolveEnvOrExit(*profilesDir))
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
				logger.Warn("stop signal received, stopping gnmi-discovery")
				server.Stop()
				// Shutdown metrics under a bounded timeout so a slow/hung exporter
				// can't block process termination indefinitely.
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
				if err := metrics.Shutdown(shutdownCtx); err != nil {
					logger.Error("failed to shutdown metrics", "error", err)
				}
				shutdownCancel()
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
			logger.Error("gnmi-discovery server encountered an error", "error", err)
			server.Stop()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			if shutdownErr := metrics.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Error("failed to shutdown metrics", "error", shutdownErr)
			}
			shutdownCancel()
			cancelFunc()
		}
	}()

	<-done
}
