package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/netboxlabs/orb-agent/agent"
	"github.com/netboxlabs/orb-agent/agent/backend/devicediscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/networkdiscovery"
	"github.com/netboxlabs/orb-agent/agent/backend/otel"
	"github.com/netboxlabs/orb-agent/agent/backend/pktvisor"
	"github.com/netboxlabs/orb-agent/agent/config"
	"github.com/netboxlabs/orb-agent/agent/version"
)

const (
	defaultConfig = "/opt/orb/agent_default.yaml"
)

var (
	cfgFiles []string
	Debug    bool
)

func init() {
	pktvisor.Register()
	otel.Register()
	devicediscovery.Register()
	networkdiscovery.Register()
}

func Version(_ *cobra.Command, _ []string) {
	fmt.Printf("orb-agent %s\n", version.GetBuildVersion())
	os.Exit(0)
}

func Run(_ *cobra.Command, _ []string) {

	initConfig()

	// configuration
	var configData config.Config
	err := viper.Unmarshal(&configData)
	if err != nil {
		cobra.CheckErr(fmt.Errorf("agent start up error (configData): %w", err))
		os.Exit(1)
	}

	// logger
	var logger *zap.Logger
	atomicLevel := zap.NewAtomicLevel()
	if Debug {
		atomicLevel.SetLevel(zap.DebugLevel)
	} else {
		atomicLevel.SetLevel(zap.InfoLevel)
	}
	encoderCfg := zap.NewProductionEncoderConfig()
	encoderCfg.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		os.Stdout,
		atomicLevel,
	)
	logger = zap.New(core, zap.AddCaller())
	defer func(logger *zap.Logger) {
		_ = logger.Sync()
	}(logger)

	_, err = os.Stat(pktvisor.DefaultBinary)
	logger.Info("backends loaded", zap.Any("backends", configData.OrbAgent.Backends))

	configData.OrbAgent.ConfigFile = defaultConfig
	if len(cfgFiles) > 0 {
		configData.OrbAgent.ConfigFile = cfgFiles[0]
	}

	// new agent
	a, err := agent.New(logger, configData)
	if err != nil {
		logger.Error("agent start up error", zap.Error(err))
		os.Exit(1)
	}

	// handle signals
	done := make(chan bool, 1)
	rootCtx, cancelFunc := context.WithCancel(context.WithValue(context.Background(), "routine", "mainRoutine"))

	go func() {
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL)
		select {
		case <-sigs:
			logger.Warn("stop signal received stopping agent")
			a.Stop(rootCtx)
			cancelFunc()
		case <-rootCtx.Done():
			logger.Warn("mainRoutine context cancelled")
			done <- true
			return
		}
	}()

	// start agent
	err = a.Start(rootCtx, cancelFunc)
	if err != nil {
		logger.Error("agent startup error", zap.Error(err))
		os.Exit(1)
	}

	<-done
}

func mergeOrError(path string) {

	v := viper.New()
	if len(path) > 0 {
		v.SetConfigFile(path)
		v.SetConfigType("yaml")
	}

	v.AutomaticEnv()
	replacer := strings.NewReplacer(".", "_")
	v.SetEnvKeyReplacer(replacer)

	if len(path) > 0 {
		cobra.CheckErr(v.ReadInConfig())
	}

	var fZero float64

	// check that version of config files are all matched up
	if versionNumber1 := viper.GetFloat64("version"); versionNumber1 != fZero {
		versionNumber2 := v.GetFloat64("version")
		if versionNumber2 == fZero {
			cobra.CheckErr("Failed to parse config version in: " + path)
		}
		if versionNumber2 != versionNumber1 {
			cobra.CheckErr("Config file version mismatch in: " + path)
		}
	}

	// load backend static functions for setting up default values
	backendVarsFunction := make(map[string]func(*viper.Viper))
	backendVarsFunction["pktvisor"] = pktvisor.RegisterBackendSpecificVariables
	backendVarsFunction["otel"] = otel.RegisterBackendSpecificVariables
	backendVarsFunction["device_discovery"] = devicediscovery.RegisterBackendSpecificVariables
	backendVarsFunction["network_discovery"] = networkdiscovery.RegisterBackendSpecificVariables

	// check if backends are configured
	// if not then add pktvisor as default
	if len(path) > 0 && len(v.GetStringMap("orb.backends")) == 0 {
		pktvisor.RegisterBackendSpecificVariables(v)
	} else {
		for backendName := range v.GetStringMap("orb.backends") {
			if backend := v.GetStringMap("orb.backends." + backendName); backend != nil && backendName != "common" {
				backendVarsFunction[backendName](v)
			}
		}
	}

	cobra.CheckErr(viper.MergeConfigMap(v.AllSettings()))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	// set defaults first
	mergeOrError("")
	if len(cfgFiles) == 0 {
		if _, err := os.Stat(defaultConfig); !os.IsNotExist(err) {
			mergeOrError(defaultConfig)
		}
	} else {
		for _, conf := range cfgFiles {
			mergeOrError(conf)
		}
	}
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
	runCmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "Enable verbose (debug level) output")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
	_ = rootCmd.Execute()
}
