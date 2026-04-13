package fleet

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"sync/atomic"
	"testing"

	"github.com/eclipse/paho.golang/paho"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetTokenRefresher_StoresCallback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	assert.Nil(t, conn.tokenRefresher, "tokenRefresher should be nil initially")

	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		return "fresh-jwt", nil
	})

	assert.NotNil(t, conn.tokenRefresher, "tokenRefresher should be set after SetTokenRefresher")
}

func TestConnectPacketBuilder_FirstCallUsesInitialToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	var refreshCalled atomic.Int32
	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		refreshCalled.Add(1)
		return "refreshed-jwt-token", nil
	})

	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder, "builder should be non-nil when tokenRefresher is set")

	// First call: uses initial token, no refresh
	cp := &paho.Connect{Password: []byte("initial-token")}
	result, err := builder(cp, &url.URL{})
	assert.NoError(t, err)
	assert.Equal(t, int32(0), refreshCalled.Load(), "first call should not refresh")
	assert.Equal(t, []byte("initial-token"), result.Password, "first call should keep initial token")

	// Second call (autopaho auto-reconnect): refreshes
	cp2 := &paho.Connect{Password: []byte("stale-jwt-token")}
	result2, err := builder(cp2, &url.URL{})
	assert.NoError(t, err)
	assert.Equal(t, int32(1), refreshCalled.Load(), "tokenRefresher should be called on auto-reconnect")
	assert.Equal(t, []byte("refreshed-jwt-token"), result2.Password, "password should be updated with fresh JWT")
}

func TestConnectPacketBuilder_FallsThroughOnRefreshError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		return "", fmt.Errorf("auth server unavailable")
	})

	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder)

	// Consume the first-call pass-through
	_, _ = builder(&paho.Connect{Password: []byte("initial-token")}, &url.URL{})

	// Second call: refresh fails, should fall through with existing password
	cp := &paho.Connect{Password: []byte("original-jwt")}
	result, err := builder(cp, &url.URL{})

	assert.NoError(t, err, "builder should not return an error on refresh failure")
	assert.Equal(t, []byte("original-jwt"), result.Password, "original password should be preserved on refresh failure")
}

func TestConnectPacketBuilder_NilWhenNoRefresher(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	builder := buildConnectPacketBuilder(conn)
	assert.Nil(t, builder, "builder should be nil when no tokenRefresher is set")
}

func TestConnectPacketBuilder_AutoReconnectRefreshesAfterFirstCall(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	var callCount atomic.Int32
	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		n := callCount.Add(1)
		return fmt.Sprintf("jwt-v%d", n), nil
	})

	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder)

	// First call: initial token, no refresh
	cp0 := &paho.Connect{Password: []byte("managed-token")}
	result0, err := builder(cp0, &url.URL{})
	assert.NoError(t, err)
	assert.Equal(t, []byte("managed-token"), result0.Password)
	assert.Equal(t, int32(0), callCount.Load())

	// Subsequent calls: each refreshes
	for i := 1; i <= 3; i++ {
		cp := &paho.Connect{Password: []byte("stale")}
		result, err := builder(cp, &url.URL{})
		assert.NoError(t, err)
		assert.Equal(t, []byte(fmt.Sprintf("jwt-v%d", i)), result.Password)
	}
	assert.Equal(t, int32(3), callCount.Load())
}

func TestConnectPacketBuilder_EachConnectGetsOwnClosure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	var refreshCalled atomic.Int32
	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		refreshCalled.Add(1)
		return "refreshed", nil
	})

	builder1 := buildConnectPacketBuilder(conn)
	builder2 := buildConnectPacketBuilder(conn)

	// Both first calls should skip refresh
	r1, _ := builder1(&paho.Connect{Password: []byte("token-a")}, &url.URL{})
	r2, _ := builder2(&paho.Connect{Password: []byte("token-b")}, &url.URL{})
	assert.Equal(t, []byte("token-a"), r1.Password)
	assert.Equal(t, []byte("token-b"), r2.Password)
	assert.Equal(t, int32(0), refreshCalled.Load(), "neither first call should refresh")

	// Both second calls should refresh
	r3, _ := builder1(&paho.Connect{Password: []byte("stale")}, &url.URL{})
	r4, _ := builder2(&paho.Connect{Password: []byte("stale")}, &url.URL{})
	assert.Equal(t, []byte("refreshed"), r3.Password)
	assert.Equal(t, []byte("refreshed"), r4.Password)
	assert.Equal(t, int32(2), refreshCalled.Load())
}
