package data

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDevices(t *testing.T) {
	// Create a temporary test YAML file
	testYAML := `
manufacturers:
  - pen: 123
    name: "Test Manufacturer 1"
  - pen: 456
    name: "Test Manufacturer 2"
devices:
  - id: 1
    oid: "1.3.6.1.4.1.123.1"
    name: "Test Device 1"
  - id: 2
    oid: "1.3.6.1.4.1.456.1"
    name: "Test Device 2"
`
	// Create invalid YAML content
	invalidYAML := `
manufacturers:
  - pen: "not_a_number"  # This should be a number
    name: "Test Manufacturer 1"
devices:
  - id: 1
    oid: "1.3.6.1.4.1.123.1"
    name: "Test Device 1"
`

	tmpFile, err := os.CreateTemp("", "test-devices-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		_ = os.Remove(tmpFile.Name())
	}()

	if _, err := tmpFile.Write([]byte(testYAML)); err != nil {
		t.Fatalf("Failed to write test YAML: %v", err)
	}
	_ = tmpFile.Close()

	// Create a temporary file with invalid YAML
	invalidTmpFile, err := os.CreateTemp("", "test-devices-invalid-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer func() {
		_ = os.Remove(invalidTmpFile.Name())
	}()

	if _, err := invalidTmpFile.Write([]byte(invalidYAML)); err != nil {
		t.Fatalf("Failed to write invalid test YAML: %v", err)
	}
	_ = invalidTmpFile.Close()

	tests := []struct {
		name     string
		filePath string
		wantErr  bool
	}{
		{
			name:     "successful load",
			filePath: tmpFile.Name(),
			wantErr:  false,
		},
		{
			name:     "file not found",
			filePath: "nonexistent.yaml",
			wantErr:  true,
		},
		{
			name:     "invalid yaml content",
			filePath: invalidTmpFile.Name(),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devices, err := NewDevices(tt.filePath)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, devices)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, devices)
			}
		})
	}
}

func TestGetManufacturer(t *testing.T) {
	devices := &Devices{
		manufacturers: map[int]Manufacturer{
			123: {PrivateEnterpriseNumber: 123, Name: "Test Manufacturer 1"},
			456: {PrivateEnterpriseNumber: 456, Name: "Test Manufacturer 2"},
		},
	}

	tests := []struct {
		name    string
		id      int
		want    string
		wantErr bool
	}{
		{
			name:    "existing manufacturer",
			id:      123,
			want:    "Test Manufacturer 1",
			wantErr: false,
		},
		{
			name:    "non-existing manufacturer",
			id:      789,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := devices.GetManufacturer(tt.id)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "", got)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestNewEmptyDevicesList(t *testing.T) {
	devices := NewEmptyDevicesList()
	assert.NotNil(t, devices)

	// Test that the empty list returns error for any manufacturer lookup
	_, err := devices.GetManufacturer(123)
	assert.Error(t, err)
}
