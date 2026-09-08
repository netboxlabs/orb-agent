package collector

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/config"
	"github.com/netboxlabs/orb-agent/orb-telemetry/gnmi-telemetry/gnmi"
)

// TestLabSRLinuxExportsBaseMetrics runs against a real target named by
// GNMI_TARGET (host:port), GNMI_USERNAME and GNMI_PASSWORD, with TLS
// verification skipped. It is skipped otherwise.
func TestLabSRLinuxExportsBaseMetrics(t *testing.T) {
	addr := os.Getenv("GNMI_TARGET")
	if addr == "" {
		t.Skip("GNMI_TARGET not set")
	}
	host, portText, err := net.SplitHostPort(addr)
	require.NoError(t, err)
	port, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)
	reader := testReader(t)
	c := New(&gnmi.GnmicDialer{}, loadStore(t), nil)
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	scope := config.Scope{Username: os.Getenv("GNMI_USERNAME"), Password: os.Getenv("GNMI_PASSWORD"), Port: uint16(port), TLS: &config.TLSConfig{SkipVerify: true}}
	tgt := config.EffectiveTarget(scope, config.Target{Host: host})
	require.NoError(t, c.CollectTarget(ctx, tgt, Options{MetricsInterval: 5 * time.Second, Mode: "auto", PolicyName: "lab"}))
	waitFor(t, 30*time.Second, func() bool {
		got := collect(t, reader)
		_, a := got["gnmi.if_in_octets"]
		_, b := got["gnmi.if_oper_status"]
		return a && b
	})
	sum := collect(t, reader)["gnmi.if_in_octets"].Data.(metricdata.Sum[int64])
	assert.NotEmpty(t, sum.DataPoints)
	st := c.TargetStatuses("lab")
	require.Len(t, st, 1)
	assert.Equal(t, "nokia_srlinux", st[0].Profile)
	assert.Equal(t, "on_change", st[0].Mode)
	assert.True(t, st[0].Up)
}
