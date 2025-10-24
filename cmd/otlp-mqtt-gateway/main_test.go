package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestFlags_Defaults(t *testing.T) {
	cmd := &cobra.Command{Use: "run"}
	cmd.Flags().StringVar(&flagLogLevel, "log-level", "info", "")
	cmd.Flags().StringVar(&flagListen, "listen", "0.0.0.0:4317", "")
	cmd.Flags().StringVar(&flagMQTTURL, "mqtt-url", "", "")
	cmd.Flags().StringVar(&flagMQTTJWT, "mqtt-jwt", "", "")
	cmd.Flags().StringVar(&flagTraces, "traces-topic", "", "")
	cmd.Flags().StringVar(&flagMetrics, "metrics-topic", "", "")
	cmd.Flags().StringVar(&flagLogs, "logs-topic", "", "")
	cmd.Flags().StringVar(&flagEncoding, "encoding", "protobuf", "")

	// Defaults
	if flagListen != "0.0.0.0:4317" {
		t.Fatalf("expected listen default 0.0.0.0:4317, got %s", flagListen)
	}
	if flagEncoding != "protobuf" {
		t.Fatalf("expected encoding default protobuf, got %s", flagEncoding)
	}
}

func TestFlags_Required(t *testing.T) {
	root := &cobra.Command{Use: "otlp-mqtt-gateway"}
	cmd := &cobra.Command{Use: "run", RunE: run}

	cmd.Flags().StringVar(&flagMQTTURL, "mqtt-url", "", "")
	cmd.Flags().StringVar(&flagMQTTJWT, "mqtt-jwt", "", "")
	cmd.Flags().StringVar(&flagTraces, "traces-topic", "", "")
	cmd.Flags().StringVar(&flagMetrics, "metrics-topic", "", "")
	cmd.Flags().StringVar(&flagLogs, "logs-topic", "", "")

	_ = cmd.MarkFlagRequired("mqtt-url")
	_ = cmd.MarkFlagRequired("mqtt-jwt")
	_ = cmd.MarkFlagRequired("traces-topic")
	_ = cmd.MarkFlagRequired("metrics-topic")
	_ = cmd.MarkFlagRequired("logs-topic")

	root.AddCommand(cmd)

	// Execute without required flags should error
	root.SetArgs([]string{"run"})
	if err := root.Execute(); err == nil {
		t.Fatalf("expected error due to missing required flags")
	}
}
