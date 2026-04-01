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

func TestConnectPacketBuilder_RefreshesToken(t *testing.T) {
	// Build a connection with a token refresher, then simulate what autopaho does:
	// call the ConnectPacketBuilder with a Connect packet and verify the password is updated.
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	var refreshCalled atomic.Int32
	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		refreshCalled.Add(1)
		return "refreshed-jwt-token", nil
	})

	// Build the ConnectPacketBuilder the same way Connect() does
	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder, "builder should be non-nil when tokenRefresher is set")

	// Simulate autopaho calling the builder before a CONNECT
	cp := &paho.Connect{
		Password: []byte("stale-jwt-token"),
	}
	result, err := builder(cp, &url.URL{})

	assert.NoError(t, err)
	assert.Equal(t, int32(1), refreshCalled.Load(), "tokenRefresher should be called once")
	assert.Equal(t, []byte("refreshed-jwt-token"), result.Password, "password should be updated with fresh JWT")
}

func TestConnectPacketBuilder_FallsThroughOnRefreshError(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		return "", fmt.Errorf("auth server unavailable")
	})

	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder)

	cp := &paho.Connect{
		Password: []byte("original-jwt"),
	}
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

func TestConnectPacketBuilder_CalledMultipleTimes(t *testing.T) {
	// Simulates multiple reconnect cycles — each should call the refresher
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	conn := NewMQTTConnection(logger, noopPM{}, make(chan struct{}, 1), make(chan struct{}, 1), noopBackendState{})

	var callCount atomic.Int32
	conn.SetTokenRefresher(func(_ context.Context) (string, error) {
		n := callCount.Add(1)
		return fmt.Sprintf("jwt-v%d", n), nil
	})

	builder := buildConnectPacketBuilder(conn)
	require.NotNil(t, builder)

	for i := 1; i <= 3; i++ {
		cp := &paho.Connect{Password: []byte("stale")}
		result, err := builder(cp, &url.URL{})
		assert.NoError(t, err)
		assert.Equal(t, []byte(fmt.Sprintf("jwt-v%d", i)), result.Password)
	}
	assert.Equal(t, int32(3), callCount.Load())
}
