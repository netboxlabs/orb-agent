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

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
	"github.com/netboxlabs/orb-discovery/network-discovery/server"
	"github.com/netboxlabs/orb-discovery/network-discovery/version"
)

// AppName is the application name
const AppName = "network-discovery"

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
		fmt.Printf("error: environment variable %s is not set\n", envVar)
		os.Exit(1)
	}
	// Return the original value if no substitution occurs
	return value
}

func main() {
	host := flag.String("host", "0.0.0.0", "server host")
	port := flag.Int("port", 8073, "server port")
	diodeTarget := flag.String("diode-target", "", "diode target (REQUIRED)")
	diodeAPIKey := flag.String("diode-api-key", "", "diode api key (REQUIRED)."+
		" Environment variables can be used by wrapping them in ${} (e.g. ${MY_API_KEY})")
	diodePrefixName := flag.String("diode-prefix-name", "", "diode producer_app_name prefix")
	logLevel := flag.String("log-level", "INFO", "log level")
	logFormat := flag.String("log-format", "TEXT", "log format")
	help := flag.Bool("help", false, "show this help")

	flag.Parse()

	if *help || *diodeTarget == "" || *diodeAPIKey == "" {
		fmt.Fprintf(os.Stderr, "Usage of network-discovery:\n")
		flag.PrintDefaults()
		if *help {
			os.Exit(0)
		}
		os.Exit(1)
	}

	producerName := AppName
	if *diodePrefixName != "" {
		producerName = fmt.Sprintf("%s/%s", *diodePrefixName, AppName)
	}

	client, err := diode.NewClient(
		*diodeTarget,
		producerName,
		version.GetBuildVersion(),
		diode.WithAPIKey(resolveEnv(*diodeAPIKey)),
	)
	if err != nil {
		fmt.Printf("error creating diode client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	logger := config.NewLogger(*logLevel, *logFormat)

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
				logger.Warn("stop signal received, stopping network-discovery")
				server.Stop()
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
