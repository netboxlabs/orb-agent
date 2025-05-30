package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/metrics"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/policy"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/server"
	"github.com/netboxlabs/orb-discovery/snmp-discovery/version"
)

// AppName is the application name
const AppName = "snmp-discovery"

func resolveEnv(value string) string {
	// Check if the value starts with ${ and ends with }
	if strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}") {
		// Extract the environment variable name
		envVar := value[2 : len(value)-1]
		// Get the value of the environment variable
		envValue := os.Getenv(envVar)
		if envValue != "" {
			return envValue
		}
		fmt.Printf("error: a provided environment %s variable is not set\n", envVar)
		os.Exit(1)
	}
	// Return the original value if no substitution occurs
	return value
}

func main() {
	host := flag.String("host", "0.0.0.0", "server host")
	port := flag.Int("port", 8070, "server port")
	diodeTarget := flag.String("diode-target", "", "diode target (REQUIRED)")
	diodeClientID := flag.String("diode-client-id", "", "diode client ID (REQUIRED)."+
		" Environment variables can be used by wrapping them in ${} (e.g. ${MY_DIODE_CLIENT_ID})")
	diodeClientSecret := flag.String("diode-client-secret", "", "diode client secret (REQUIRED)."+
		" Environment variables can be used by wrapping them in ${} (e.g. ${MY_DIODE_CLIENT_SECRET})")
	diodeAppNamePrefix := flag.String("diode-app-name-prefix", "", "diode producer_app_name prefix")
	logLevel := flag.String("log-level", "INFO", "log level")
	logFormat := flag.String("log-format", "TEXT", "log format")
	help := flag.Bool("help", false, "show this help")
	// Add new flags for metrics
	otelEndpoint := flag.String("otel-endpoint", "", "OpenTelemetry exporter endpoint (e.g. localhost:4317)."+
		" Environment variables can be used by wrapping them in ${} (e.g. ${OTEL_ENDPOINT})")
	otelExportPeriod := flag.Int("otel-export-period", 10, "Period in seconds between OpenTelemetry exports")

	flag.Parse()

	if *help || *diodeTarget == "" || *diodeClientID == "" || *diodeClientSecret == "" {
		fmt.Fprintf(os.Stderr, "Usage of snmp-discovery:\n")
		flag.PrintDefaults()
		if *help {
			os.Exit(0)
		}
		os.Exit(1)
	}

	producerName := AppName
	if *diodeAppNamePrefix != "" {
		producerName = fmt.Sprintf("%s/%s", *diodeAppNamePrefix, AppName)
	}

	client, err := diode.NewClient(
		resolveEnv(*diodeTarget),
		producerName,
		version.GetBuildVersion(),
		diode.WithClientID(resolveEnv(*diodeClientID)),
		diode.WithClientSecret(resolveEnv(*diodeClientSecret)),
	)
	if err != nil {
		fmt.Printf("error creating diode client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	logger := config.NewLogger(*logLevel, *logFormat)

	// Initialize metrics
	if err := metrics.SetupMetricsExport(ctx, logger, resolveEnv(*otelEndpoint), *otelExportPeriod); err != nil {
		logger.Error("failed to setup metrics export", "error", err)
		os.Exit(1)
	}

	policyManager := policy.NewManager(ctx, logger, client)
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

	server.Start()

	<-done
}
