package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/a8m/envsubst"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
	"github.com/netboxlabs/orb-discovery/network-discovery/policy"
	"github.com/netboxlabs/orb-discovery/network-discovery/server"
	"github.com/netboxlabs/orb-discovery/network-discovery/version"
)

// AppName is the application name
const AppName = "network-discovery"

func main() {
	configPath := flag.String("config", "", "path to the configuration file (required)")

	flag.Parse()

	if *configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage of network-discovery:\n")
		flag.PrintDefaults()
		os.Exit(1)

	}
	if _, err := os.Stat(*configPath); os.IsNotExist(err) {
		fmt.Printf("configuration file '%s' does not exist", *configPath)
		os.Exit(1)
	}
	fileData, err := envsubst.ReadFile(*configPath)
	if err != nil {
		fmt.Printf("error reading configuration file: %v", err)
		os.Exit(1)
	}

	cfg := config.Config{
		Network: config.Network{
			Config: config.StartupConfig{
				Host:      "0.0.0.0",
				Port:      8073,
				LogLevel:  "INFO",
				LogFormat: "TEXT",
			}},
	}

	if err = yaml.Unmarshal(fileData, &cfg); err != nil {
		fmt.Printf("error parsing configuration file: %v\n", err)
		os.Exit(1)
	}

	client, err := diode.NewClient(
		cfg.Diode.Config.Target,
		AppName,
		version.GetBuildVersion(),
		diode.WithAPIKey(cfg.Diode.Config.APIKey),
	)
	if err != nil {
		fmt.Printf("error creating diode client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	logger := config.NewLogger(cfg.Network.Config.LogLevel, cfg.Network.Config.LogFormat)

	policyManager := policy.NewManager(ctx, logger, client)
	server := server.Server{}
	server.Configure(logger, policyManager, version.GetBuildVersion(), cfg.Network.Config)

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
