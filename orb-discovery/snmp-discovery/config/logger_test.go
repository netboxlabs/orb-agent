package config_test

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-discovery/network-discovery/config"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		desc          string
		loggingLevel  string
		loggingFormat string
	}{
		{
			desc:          "with debug level and json format",
			loggingLevel:  "debug",
			loggingFormat: "json",
		},
		{
			desc:          "with debug level and text format",
			loggingLevel:  "debug",
			loggingFormat: "text",
		},
		{
			desc:          "with info level and json format",
			loggingLevel:  "info",
			loggingFormat: "json",
		},
		{
			desc:          "with info level and text format",
			loggingLevel:  "warn",
			loggingFormat: "json",
		},
		{
			desc:          "with error level and text format",
			loggingLevel:  "error",
			loggingFormat: "text",
		},
		{
			desc:          "with error level and empty format",
			loggingLevel:  "error",
			loggingFormat: "",
		},
		{
			desc:          "with empty level and text format",
			loggingLevel:  "",
			loggingFormat: "text",
		},
	}
	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			log := config.NewLogger(tt.loggingLevel, tt.loggingFormat)
			require.NotNil(t, log)

			handlerOK := false
			if tt.loggingFormat == "text" {
				_, handlerOK = log.Handler().(*slog.TextHandler)
			} else {
				_, handlerOK = log.Handler().(*slog.JSONHandler)
			}
			assert.True(t, handlerOK)
		})
	}
}
