package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/netboxlabs/orb-agent/agent"
	"github.com/netboxlabs/orb-agent/agent/backend/devicediscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/networkdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/opentelemetryinfinity"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/backend/snmpdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/worker"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/redact"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const (
	routineKey config.ContextKey = "routine"
)

var (
	cfgFiles []string
	debug    bool
)

func init() {
	devicediscovery.Register()
	networkdiscovery.Register()
	opentelemetryinfinity.Register()
	snmpdiscovery.Register()
	pktvisor.Register()
	worker.Register()
}

// Version prints the version of the agent
func Version(_ *cobra.Command, _ []string) {
	fmt.Printf("orb-agent %s\n", version.GetBuildVersion())
	os.Exit(0)
}

func loadConfig(path string, configData *config.Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			cobra.CheckErr(fmt.Errorf("failed to close config file: %w", err))
		}
	}()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(configData); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}

// Run starts the agent
func Run(_ *cobra.Command, _ []string) {
	var configData config.Config

	// Override with user-provided config files
	for _, conf := range cfgFiles {
		if err := loadConfig(conf, &configData); err != nil {
			cobra.CheckErr(fmt.Errorf("error loading config file %s: %w", conf, err))
		}
	}

	// logger
	var l slog.Level
	if debug {
		l = slog.LevelDebug
	} else {
		l = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: l, AddSource: false})
	logger := slog.New(h)

	if len(cfgFiles) > 0 {
		configData.OrbAgent.ConfigFile = cfgFiles[0]
	} else {
		cobra.CheckErr(fmt.Errorf("no config file specified, use --config or -c flag to provide config files"))
	}

	logger.Info("backends loaded", "backends", redact.SensitiveData(configData.OrbAgent.Backends))

	// new agent
	a, err := agent.New(logger, configData)
	if err != nil {
		logger.Error("agent start up error", "error", err)
		os.Exit(1)
	}

	// handle signals
	done := make(chan bool, 1)
	rootCtx, cancelFunc := context.WithCancel(context.WithValue(context.Background(), routineKey, "mainRoutine"))

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		select {
		case <-sigs:
			logger.Warn("stop signal received stopping agent")
			a.Stop(rootCtx)
			cancelFunc()
			os.Exit(0)
		case <-rootCtx.Done():
			logger.Warn("mainRoutine context cancelled")
			done <- true
			return
		}
	}()

	// start agent
	err = a.Start(rootCtx, cancelFunc)
	if err != nil {
		logger.Error("agent startup error", "error", err)
		os.Exit(1)
	}

	<-done
}

func main() {
	rootCmd := &cobra.Command{
		Use: "orb-agent",
	}

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show agent version",
		Run:   Version,
	}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run orb-agent",
		Long:  `Run orb-agent`,
		Run:   Run,
	}

	runCmd.Flags().StringSliceVarP(&cfgFiles, "config", "c", []string{}, "Path to config files (may be specified multiple times)")
	runCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable verbose (debug level) output")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
	_ = rootCmd.Execute()
}
