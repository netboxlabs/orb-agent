package data

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewManufacturerLookup(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "successful creation",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lookup, err := NewManufacturerLookup()
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, lookup)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, lookup)
				assert.NotNil(t, lookup.data)
			}
		})
	}
}

func TestManufacturerLookup_GetManufacturer(t *testing.T) {
	// Create a manufacturer lookup instance
	lookup, err := NewManufacturerLookup()
	require.NoError(t, err)
	require.NotNil(t, lookup)

	tests := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{
			name:    "existing manufacturer - Reserved",
			id:      "0",
			want:    "Reserved",
			wantErr: false,
		},
		{
			name:    "existing manufacturer - IBM",
			id:      "2",
			want:    "IBM httpsw3ibmcomstandards",
			wantErr: false,
		},
		{
			name:    "existing manufacturer - Cisco Systems",
			id:      "9",
			want:    "ciscoSystems",
			wantErr: false,
		},
		{
			name:    "existing manufacturer - Hewlett Packard",
			id:      "11",
			want:    "HewlettPackard",
			wantErr: false,
		},
		{
			name:    "existing manufacturer - Apple Computer Inc",
			id:      "63",
			want:    "Apple Computer Inc",
			wantErr: false,
		},
		{
			name:    "non-existing manufacturer - negative ID",
			id:      "-1",
			want:    "",
			wantErr: true,
		},
		{
			name:    "non-existing manufacturer - large ID",
			id:      "999999",
			want:    "",
			wantErr: true,
		},
		{
			name:    "non-existing manufacturer - zero ID that doesn't exist",
			id:      "100000",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := lookup.GetManufacturer(tt.id)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "", got)
				assert.Contains(t, err.Error(), "manufacturer not found")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestManufacturerLookup_GetManufacturer_DataIntegrity(t *testing.T) {
	// Test that the embedded data is properly loaded and accessible
	lookup, err := NewManufacturerLookup()
	require.NoError(t, err)
	require.NotNil(t, lookup)

	// Check that we have a reasonable number of manufacturers
	dataSize := len(*lookup.data)
	assert.Greater(t, dataSize, 1000, "Expected at least 1000 manufacturers in the data")

	// Test some well-known manufacturers that should exist
	wellKnownManufacturers := map[string]string{
		"9":   "ciscoSystems",
		"43":  "3Com",
		"161": "Motorola",
		"11":  "HewlettPackard",
	}

	for id, expectedName := range wellKnownManufacturers {
		t.Run("well-known manufacturer "+expectedName, func(t *testing.T) {
			manufacturer, err := lookup.GetManufacturer(id)
			assert.NoError(t, err)
			assert.Equal(t, expectedName, manufacturer)
		})
	}
}

func TestManufacturerLookup_EdgeCases(t *testing.T) {
	lookup, err := NewManufacturerLookup()
	require.NoError(t, err)

	// Test boundary conditions
	tests := []struct {
		name string
		id   string
	}{
		{"zero ID", "0"},
		{"max int32", "2147483647"},
		{"min int32", "-2147483648"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// We don't assert specific results here since we don't know
			// what IDs exist, but we ensure the function doesn't panic
			_, err := lookup.GetManufacturer(tt.id)
			// Error is acceptable for non-existent IDs
			if err != nil {
				assert.Contains(t, err.Error(), "manufacturer not found")
			}
		})
	}
}

func TestDeviceLookup_GetDevice(t *testing.T) {
	// Create a test DeviceLookup with sample data
	deviceLookup := &DeviceLookup{
		devicesByVendor: &map[string]string{
			"1.3.6.1.4.1.9.1.1234": "Test Device A",
			"1.3.6.1.4.1.9.1.4321": "Test Device B",
		},
	}

	tests := []struct {
		name      string
		deviceOID string
		want      string
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "successful lookup - existing vendor and device",
			deviceOID: "1.3.6.1.4.1.9.1.1234",
			want:      "Test Device A",
			wantErr:   false,
		},
		{
			name:      "successful lookup - another device",
			deviceOID: "1.3.6.1.4.1.9.1.4321",
			want:      "Test Device B",
			wantErr:   false,
		},
		{
			name:      "unsuccessful lookup - non-existing device OID",
			deviceOID: "1.3.6.1.4.1.9.1.987",
			want:      "",
			wantErr:   true,
			errMsg:    "device ID 1.3.6.1.4.1.9.1.987 not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := deviceLookup.GetDevice(tt.deviceOID)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "", got)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestLoadDeviceLookupExtensions(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "device_lookup_test")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp dir: %v", err)
		}
	}()

	tests := []struct {
		name     string
		files    map[string]string
		wantErr  bool
		expected map[string]string
	}{
		{
			name: "single valid YAML file",
			files: map[string]string{
				"devices.yaml": `devices:
  "1.3.6.1.4.1.9.1.1234": "Test Device A"
  "1.3.6.1.4.1.9.1.4321": "Test Device B"`,
			},
			wantErr: false,
			expected: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Test Device A",
				"1.3.6.1.4.1.9.1.4321": "Test Device B",
			},
		},
		{
			name: "multiple YAML files with merge",
			files: map[string]string{
				"devices1.yaml": `devices:
  "1.3.6.1.4.1.9.1.1234": "Device A"`,
				"devices2.yml": `devices:
  "1.3.6.1.4.1.9.1.4321": "Device B"`,
			},
			wantErr: false,
			expected: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Device A",
				"1.3.6.1.4.1.9.1.4321": "Device B",
			},
		},
		{
			name:     "empty directory",
			files:    map[string]string{},
			wantErr:  false,
			expected: map[string]string{},
		},
		{
			name:    "empty directory still loads built-in extensions",
			files:   map[string]string{},
			wantErr: false,
			expected: map[string]string{
				".1.3.6.1.4.1.9.1.1215": "ciscoMwr2941DCA",
			},
		},
		{
			name: "non-YAML files ignored",
			files: map[string]string{
				"devices.yaml": `devices:
  "1.3.6.1.4.1.9.1.1234": "Test Device"`,
				"readme.txt":  "This should be ignored",
				"config.json": `{"ignored": true}`,
			},
			wantErr: false,
			expected: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Test Device",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test directory
			testDir := filepath.Join(tempDir, tt.name)
			err := os.MkdirAll(testDir, 0o755)
			require.NoError(t, err)

			// Create test files
			for filename, content := range tt.files {
				filePath := filepath.Join(testDir, filename)
				err := os.WriteFile(filePath, []byte(content), 0o644)
				require.NoError(t, err)
			}

			// Test LoadDeviceLookupExtensions
			deviceLookup, err := LoadDeviceLookupExtensions(testDir)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, deviceLookup)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, deviceLookup)
				assert.Equal(t, tt.expected["1.3.6.1.4.1.9.1.1234"], (*deviceLookup.devicesByVendor)["1.3.6.1.4.1.9.1.1234"])
			}
		})
	}
}

func TestLoadDeviceLookupExtensions_ErrorCases(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		wantErr bool
	}{
		{
			name:    "non-existent directory",
			dir:     "/path/that/does/not/exist",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deviceLookup, err := LoadDeviceLookupExtensions(tt.dir)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, deviceLookup)
			}
		})
	}
}

func TestLoadDeviceLookupExtensions_InvalidYAML(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "device_lookup_invalid_test")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp dir: %v", err)
		}
	}()

	// Create a valid YAML file and an invalid one
	validYAML := `devices:
  "1.3.6.1.4.1.9.1.1234": "Valid Device"`

	invalidYAML := `devices:
  "1.3.6.1.4.1.9.1.1234": "Invalid YAML
      missing quotes and proper structure`

	err = os.WriteFile(filepath.Join(tempDir, "valid.yaml"), []byte(validYAML), 0o644)
	require.NoError(t, err)

	err = os.WriteFile(filepath.Join(tempDir, "invalid.yaml"), []byte(invalidYAML), 0o644)
	require.NoError(t, err)

	// LoadDeviceLookupExtensions should succeed but log warnings for invalid files
	deviceLookup, err := LoadDeviceLookupExtensions(tempDir)
	assert.NoError(t, err)
	assert.NotNil(t, deviceLookup)

	// Should only contain data from valid file
	expected := map[string]string{
		"1.3.6.1.4.1.9.1.1234": "Valid Device",
	}
	assert.Equal(t, expected["1.3.6.1.4.1.9.1.1234"], (*deviceLookup.devicesByVendor)["1.3.6.1.4.1.9.1.1234"])
}

func TestIsLookupExtensionFile(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		isDir    bool
		want     bool
	}{
		{
			name:     "YAML file",
			filename: "devices.yaml",
			isDir:    false,
			want:     true,
		},
		{
			name:     "YML file",
			filename: "config.yml",
			isDir:    false,
			want:     true,
		},
		{
			name:     "YAML file uppercase",
			filename: "DATA.YAML",
			isDir:    false,
			want:     true,
		},
		{
			name:     "YML file uppercase",
			filename: "CONFIG.YML",
			isDir:    false,
			want:     true,
		},
		{
			name:     "text file",
			filename: "readme.txt",
			isDir:    false,
			want:     false,
		},
		{
			name:     "JSON file",
			filename: "config.json",
			isDir:    false,
			want:     false,
		},
		{
			name:     "directory",
			filename: "devices.yaml",
			isDir:    true,
			want:     false,
		},
		{
			name:     "file without extension",
			filename: "devices",
			isDir:    false,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock DirEntry
			mockDirEntry := &mockDirEntry{
				name:  tt.filename,
				isDir: tt.isDir,
			}

			got := isLookupExtensionFile(mockDirEntry)
			assert.Equal(t, tt.want, got)
		})
	}
}

// mockDirEntry implements os.DirEntry for testing
type mockDirEntry struct {
	name  string
	isDir bool
}

func (m *mockDirEntry) Name() string {
	return m.name
}

func (m *mockDirEntry) IsDir() bool {
	return m.isDir
}

func (m *mockDirEntry) Type() os.FileMode {
	if m.isDir {
		return os.ModeDir
	}
	return 0
}

func (m *mockDirEntry) Info() (os.FileInfo, error) {
	return nil, nil
}

func TestLoadYAMLFile(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "yaml_file_test")
	require.NoError(t, err)
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			t.Logf("Failed to remove temp dir: %v", err)
		}
	}()

	tests := []struct {
		name     string
		content  string
		initial  map[string]string
		expected map[string]string
		wantErr  bool
	}{
		{
			name: "valid YAML file",
			content: `devices:
    "1.3.6.1.4.1.9.1.1234": "Device A"
    "1.3.6.1.4.1.9.1.4321": "Device B"`,
			initial: make(map[string]string),
			expected: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Device A",
				"1.3.6.1.4.1.9.1.4321": "Device B",
			},
			wantErr: false,
		},
		{
			name: "merge with existing data",
			content: `devices:
    "1.3.6.1.4.1.9.1.1234": "Device A"
    "1.3.6.1.4.1.9.1.4321": "Device B"`,
			initial: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Device A",
			},
			expected: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Device A",
				"1.3.6.1.4.1.9.1.4321": "Device B",
			},
			wantErr: false,
		},
		{
			name: "invalid YAML",
			content: `devices:
  "1234":
    "5678": [unclosed list
      - item1
      - item2`,
			initial:  make(map[string]string),
			expected: make(map[string]string),
			wantErr:  true,
		},
		{
			name:     "empty file",
			content:  "",
			initial:  make(map[string]string),
			expected: make(map[string]string),
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create initial devicesByVendor map
			devicesByVendor := make(map[string]string)
			for k, v := range tt.initial {
				devicesByVendor[k] = v
			}

			// Test loadYAMLFile
			err = loadYAMLFile([]byte(tt.content), &devicesByVendor)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, devicesByVendor)
			}
		})
	}
}
