package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/netboxlabs/orb-agent/agent/otlpbridge"
)

var (
	flagLogLevel string
	flagListen   string
	flagMQTTURL  string
	flagMQTTJWT  string
	flagTraces   string
	flagMetrics  string
	flagLogs     string
	flagEncoding string
	flagTLSCert  string // reserved for future
	flagTLSKey   string // reserved for future
)

func main() {
	rootCmd := &cobra.Command{Use: "otlp-mqtt-gateway"}

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run the OTLP → MQTT gateway",
		RunE:  run,
	}

	runCmd.Flags().StringVar(&flagLogLevel, "log-level", "info", "Log level: debug|info|warn|error")
	runCmd.Flags().StringVar(&flagListen, "listen", "0.0.0.0:4317", "gRPC listen address (host:port)")
	runCmd.Flags().StringVar(&flagMQTTURL, "mqtt-url", "", "MQTT broker URL")
	runCmd.Flags().StringVar(&flagMQTTJWT, "mqtt-jwt", "", "MQTT JWT for password auth")
	runCmd.Flags().StringVar(&flagTraces, "traces-topic", "", "MQTT topic for traces")
	runCmd.Flags().StringVar(&flagMetrics, "metrics-topic", "", "MQTT topic for metrics")
	runCmd.Flags().StringVar(&flagLogs, "logs-topic", "", "MQTT topic for logs")
	runCmd.Flags().StringVar(&flagEncoding, "encoding", "protobuf", "Payload encoding: protobuf|json")
	runCmd.Flags().StringVar(&flagTLSCert, "tls-cert", "", "TLS certificate path (reserved)")
	runCmd.Flags().StringVar(&flagTLSKey, "tls-key", "", "TLS private key path (reserved)")

	_ = runCmd.MarkFlagRequired("mqtt-url")
	_ = runCmd.MarkFlagRequired("mqtt-jwt")
	_ = runCmd.MarkFlagRequired("traces-topic")
	_ = runCmd.MarkFlagRequired("metrics-topic")
	_ = runCmd.MarkFlagRequired("logs-topic")

	rootCmd.AddCommand(runCmd)
	_ = rootCmd.Execute()
}

func run(_ *cobra.Command, _ []string) error {
	// logger
	level := slog.LevelInfo
	switch flagLogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))

	cfg := otlpbridge.BridgeConfig{
		ListenAddr:   flagListen,
		MQTTURL:      flagMQTTURL,
		MQTTJWT:      flagMQTTJWT,
		TracesTopic:  flagTraces,
		MetricsTopic: flagMetrics,
		LogsTopic:    flagLogs,
		Encoding:     flagEncoding,
	}

	server, err := otlpbridge.NewBridgeServer(cfg)
	if err != nil {
		return fmt.Errorf("server init error: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("server start error: %w", err)
	}

	// Block until signal
	<-ctx.Done()
	logger.Info("shutdown signal received")
	if err := server.Stop(context.Background()); err != nil {
		return fmt.Errorf("server stop error: %w", err)
	}
	return nil
}
