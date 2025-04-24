package crawler_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/netboxlabs/diode-sdk-go/diode"
	"github.com/netboxlabs/diode-sdk-go/diode/v1/diodepb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/netboxlabs/orb-discovery/snmp-discovery/crawler"
)

// MockSNMP is a mock for gosnmp
type MockSNMP struct {
	mock.Mock
	Conn MockConn
}

type MockConn struct {
	mock.Mock
}

func (m *MockConn) Close() error {
	args := m.Called()
	return args.Error(0)
}

// MockClient mocks the diode.Client
type MockClient struct {
	mock.Mock
}

// Close implements diode.Client.
func (m *MockClient) Close() error {
	panic("unimplemented")
}

// Ingest implements diode.Client.
func (m *MockClient) Ingest(context.Context, []diode.Entity) (*diodepb.IngestResponse, error) {
	panic("unimplemented")
}

// NullSNMPWalker is a no-op implementation of SNMPWalker
type NullSNMPWalker struct{}

// Connect implements SNMPWalker interface
func (n *NullSNMPWalker) Connect() error {
	return nil
}

// Close implements SNMPWalker interface
func (n *NullSNMPWalker) Close() error {
	return nil
}

// WalkAll implements SNMPWalker interface
func (n *NullSNMPWalker) WalkAll(string) ([]gosnmp.SnmpPDU, error) {
	return []gosnmp.SnmpPDU{}, nil
}

func NewNullSNMPWalker(_ string) crawler.SNMPWalker {
	return &NullSNMPWalker{}
}

func TestCrawlTargets(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mockClient := new(MockClient)

	t.Run("Successfully crawls single target", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		targets := []string{"192.168.1.1"}

		// Create crawler with mock client
		c := crawler.NewCrawler(ctx, logger, mockClient, targets, NewNullSNMPWalker)

		// Execute
		entities, err := c.CrawlTargets()

		// Assert
		assert.NoError(t, err)
		assert.Len(t, entities, 1)

		ipAddress, ok := entities[0].(*diode.IPAddress)
		assert.True(t, ok)
		assert.Equal(t, "192.168.1.1/32", string(*ipAddress.Address))
	})

	t.Run("Handles empty target list", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		targets := []string{}

		// Create crawler with mock client
		c := crawler.NewCrawler(ctx, logger, mockClient, targets, NewNullSNMPWalker)

		// Execute
		entities, err := c.CrawlTargets()

		// Assert
		assert.NoError(t, err)
		assert.Empty(t, entities)
	})

	t.Run("Handles context cancellation", func(t *testing.T) {
		// Setup
		ctx, cancel := context.WithCancel(context.Background())
		targets := []string{"192.168.1.1", "192.168.1.2"}

		// Create crawler with mock client
		c := crawler.NewCrawler(ctx, logger, mockClient, targets, NewNullSNMPWalker)

		// Cancel context immediately
		cancel()

		// Execute
		entities, err := c.CrawlTargets()

		// Assert - even with cancelled context, the method should complete
		assert.NoError(t, err)
		assert.NotNil(t, entities)
	})

	t.Run("Handles duplicate targets", func(t *testing.T) {
		// Setup
		ctx := context.Background()
		targets := []string{"192.168.1.1", "192.168.1.1"}

		// Create crawler with mock client
		c := crawler.NewCrawler(ctx, logger, mockClient, targets, NewNullSNMPWalker)

		// Execute
		entities, err := c.CrawlTargets()

		// Assert - should only process the IP once
		assert.NoError(t, err)

		// Count the number of unique IP addresses
		ipSet := make(map[string]bool)
		for _, entity := range entities {
			if ipAddress, ok := entity.(*diode.IPAddress); ok {
				ipSet[string(*ipAddress.Address)] = true
			}
		}

		assert.Equal(t, 1, len(ipSet))
	})
}
