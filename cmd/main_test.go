package main

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netboxlabs/orb-agent/agent/config"
)

func configWithDebug(enable bool) config.Config {
	var c config.Config
	c.OrbAgent.Debug.Enable = enable
	return c
}

func TestNewRootLogger_FlagSetsDebugImmediately(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestNewRootLogger_DefaultIsInfo(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_YAMLOnlyEnablesDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.True(t, logger.Enabled(context.Background(), slog.LevelDebug))
	// The switch itself must be visible in the (now debug-enabled) output.
	assert.Contains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_FlagOnlyStaysDebugNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(false))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file")
}

func TestApplyConfigDebug_BothOff(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, false)

	effective := applyConfigDebug(logger, level, false, configWithDebug(false))

	assert.False(t, effective)
	assert.Equal(t, slog.LevelInfo, level.Level())
	assert.False(t, logger.Enabled(context.Background(), slog.LevelDebug))
}

func TestApplyConfigDebug_BothOnNoDuplicateAnnounce(t *testing.T) {
	var buf bytes.Buffer
	logger, level := newRootLogger(&buf, true)

	effective := applyConfigDebug(logger, level, true, configWithDebug(true))

	assert.True(t, effective)
	assert.Equal(t, slog.LevelDebug, level.Level())
	assert.NotContains(t, buf.String(), "debug logging enabled via config file",
		"flag already enabled debug; config adds nothing to announce")
}
