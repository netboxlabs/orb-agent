package data

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
		devicesByVendor: map[string]deviceRef{
			"1.3.6.1.4.1.9.1.1234": {kind: devRefStatic, literal: "Test Device A"},
			"1.3.6.1.4.1.9.1.4321": {kind: devRefStatic, literal: "Test Device B"},
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
				if wantModel, ok := tt.expected["1.3.6.1.4.1.9.1.1234"]; ok {
					got, getErr := deviceLookup.GetDevice("1.3.6.1.4.1.9.1.1234")
					assert.NoError(t, getErr)
					assert.Equal(t, wantModel, got)
				}
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
	got, getErr := deviceLookup.GetDevice("1.3.6.1.4.1.9.1.1234")
	assert.NoError(t, getErr)
	assert.Equal(t, "Valid Device", got)
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

func TestEmbeddedLookupExtensions_DataIntegrity(t *testing.T) {
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)
	require.NotNil(t, deviceLookup)

	count := len(deviceLookup.devicesByVendor)
	assert.Greater(t, count, 500, "Expected at least 500 device entries across all embedded lookup files")
}

func TestEmbeddedLookupExtensions_CiscoCatalyst1200And1300(t *testing.T) {
	// The Catalyst 1200/1300 smart-switch family (CISCO-PRODUCTS-MIB
	// ciscoProducts 3210-3253) shipped after this table was last refreshed, so
	// these sysObjectIDs resolved to "device ID not found" and the model fell
	// back to the raw OID string.
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)

	for oid, want := range map[string]string{
		".1.3.6.1.4.1.9.1.3213": "ciscoC12008FP2G",   // C1200-8FP-2G
		".1.3.6.1.4.1.9.1.3216": "ciscoC120024T4G",   // C1200-24T-4G
		".1.3.6.1.4.1.9.1.3225": "ciscoC120048P4X",   // C1200-48P-4X
		".1.3.6.1.4.1.9.1.3226": "ciscoC13008TE2G",   // C1300-8T-E-2G
		".1.3.6.1.4.1.9.1.3247": "ciscoC130048MGP4X", // C1300-48MGP-4X
		// Entries past the Catalyst 1200/1300 block, from the same refresh.
		".1.3.6.1.4.1.9.1.3293": "ciscoC935048U", // Catalyst 9350-48U
		".1.3.6.1.4.1.9.1.3542": "ciscoC8475G2",  // highest suffix in the MIB
		// ciscoProducts 229 carries a live ciscoMGX8830 plus a commented-out
		// ciscoMGX8820 alias. A generator that ignores ASN.1 comments picks up
		// the dead name, so pin the live one.
		".1.3.6.1.4.1.9.1.229": "ciscoMGX8830",
	} {
		model, err := deviceLookup.GetDeviceModel(oid, map[string]string{})
		assert.NoError(t, err, "OID %s should resolve", oid)
		assert.Equal(t, want, model, "OID %s", oid)
	}
}

func TestEmbeddedLookupExtensions_NoDuplicateOIDs(t *testing.T) {
	oidSources := make(map[string]string) // oid -> first file it was seen in

	files, err := lookupExtensionsData.ReadDir("lookup_extensions")
	require.NoError(t, err)

	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}

		filePath := path.Join("lookup_extensions", file.Name())
		data, err := lookupExtensionsData.ReadFile(filePath)
		require.NoError(t, err, "file %s should be readable", file.Name())

		var fileData struct {
			Devices map[string]string `yaml:"devices"`
		}
		require.NoError(t, yaml.Unmarshal(data, &fileData), "file %s should parse without error", file.Name())

		for oid := range fileData.Devices {
			if firstFile, exists := oidSources[oid]; exists {
				t.Errorf("duplicate OID %s found in %s (already defined in %s)", oid, file.Name(), firstFile)
			} else {
				oidSources[oid] = file.Name()
			}
		}
	}
}

func TestEmbeddedLookupExtensions_AllOIDsMappedCorrectly(t *testing.T) {
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)
	require.NotNil(t, deviceLookup)

	files, err := lookupExtensionsData.ReadDir("lookup_extensions")
	require.NoError(t, err)

	for _, file := range files {
		if !isLookupExtensionFile(file) {
			continue
		}

		filePath := path.Join("lookup_extensions", file.Name())
		data, err := lookupExtensionsData.ReadFile(filePath)
		require.NoError(t, err, "file %s should be readable", file.Name())

		var fileData struct {
			Devices map[string]string `yaml:"devices"`
		}
		require.NoError(t, yaml.Unmarshal(data, &fileData), "file %s should parse without error", file.Name())

		for oid, expectedModel := range fileData.Devices {
			oid, expectedModel := oid, expectedModel // capture loop vars
			// Dynamic entries (YAML value is itself an OID) cannot be
			// resolved by GetDevice alone; skip them here.
			if oidPattern.MatchString(expectedModel) {
				continue
			}
			t.Run(fmt.Sprintf("%s/%s", file.Name(), oid), func(t *testing.T) {
				got, err := deviceLookup.GetDevice(oid)
				assert.NoError(t, err, "OID %s from %s should be found in the lookup", oid, file.Name())
				assert.Equal(t, expectedModel, got, "OID %s should map to model %q", oid, expectedModel)
			})
		}
	}
}

func TestManufacturerResolver_UserOverrideWins(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
manufacturers:
  "9": "Cisco Systems"
  "14823": "Aruba"
`), 0o644)
	require.NoError(t, err)

	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)

	resolver, err := NewManufacturerResolver(builtin, dir, nil)
	require.NoError(t, err)

	got, err := resolver.GetManufacturer("9")
	require.NoError(t, err)
	assert.Equal(t, "Cisco Systems", got)

	got, err = resolver.GetManufacturer("14823")
	require.NoError(t, err)
	assert.Equal(t, "Aruba", got)
}

func TestManufacturerResolver_FallsBackToBuiltin(t *testing.T) {
	dir := t.TempDir()
	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)

	resolver, err := NewManufacturerResolver(builtin, dir, nil)
	require.NoError(t, err)

	// PEN 14 (BBN Technologies) has no canonical override and no user
	// override was written, so the built-in IANA value must flow through.
	got, err := resolver.GetManufacturer("14")
	require.NoError(t, err)
	assert.Equal(t, "BBN Technologies", got)
}

func TestManufacturerResolver_NoUserDirFallsBackToBuiltinCatalog(t *testing.T) {
	// With no user override directory, a PEN that no override covers
	// (PEN 14 is absent from the shipped _manufacturers_ndx.yaml block)
	// must still resolve from the base IANA catalog. This guards against
	// the resolver wrapping the base catalog in a way that hides its
	// entries.
	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)

	resolver, err := NewManufacturerResolver(builtin, "", nil)
	require.NoError(t, err)

	got, err := resolver.GetManufacturer("14")
	require.NoError(t, err)
	assert.Equal(t, "BBN Technologies", got)
}

func TestManufacturerResolver_UnknownPENBubblesError(t *testing.T) {
	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)
	resolver, err := NewManufacturerResolver(builtin, "", nil)
	require.NoError(t, err)

	_, err = resolver.GetManufacturer("999999999")
	require.Error(t, err)
}

func TestManufacturerResolver_MissingUserDirIsSoftError(t *testing.T) {
	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)

	// A directory that does not exist must not fail construction —
	// the resolver should degrade to built-in-only.
	resolver, err := NewManufacturerResolver(builtin, "/this/path/does/not/exist/snmp-discovery-test", nil)
	require.NoError(t, err)
	require.NotNil(t, resolver)

	// Built-in catalog still works.
	got, err := resolver.GetManufacturer("14")
	require.NoError(t, err)
	assert.Equal(t, "BBN Technologies", got)
}

func TestManufacturerResolver_CanonicalNDXOverrides(t *testing.T) {
	// The shipped _manufacturers_ndx.yaml extension rewrites raw IANA PEN
	// names to canonical NetBox DeviceType-Library manufacturer names with no
	// user override directory. Spot-check representative entries, including
	// multi-PEN vendors (Dell via Force10/OS10, Cisco via Meraki) and the
	// secondary PENs that bundled device files use (Aruba CX, Unisphere, etc.).
	builtin, err := NewManufacturerLookup()
	require.NoError(t, err)
	resolver, err := NewManufacturerResolver(builtin, "", nil)
	require.NoError(t, err)

	cases := map[string]string{
		"9":     "Cisco",            // ciscoSystems
		"29671": "Cisco",            // Meraki -> Cisco
		"30065": "Arista",           // Arista Networks Inc
		"2636":  "Juniper",          // Juniper Networks Inc
		"4874":  "Juniper",          // Juniper Unisphere/ERX
		"6027":  "Dell",             // Force10 Networks Inc
		"19746": "Dell",             // Dell EMC OS10
		"11":    "HPE",              // HewlettPackard
		"14823": "HPE",              // Aruba
		"47196": "HPE",              // Aruba CX
		"232":   "HPE",              // Compaq
		"37447": "HPE",              // Nimble Storage
		"6527":  "Nokia",            // Nokia formerly AlcatelLucent
		"2011":  "Huawei",           // HUAWEI Technology CoLtd
		"25461": "Palo Alto",        // PALO ALTO NETWORKS
		"50114": "Palo Alto",        // CloudGenix (Prisma SD-WAN)
		"5528":  "APC",              // NetBotz
		"476":   "Vertiv",           // Emerson Computer Power
		"1916":  "Extreme Networks", // Extreme Networks
		"248":   "Hirschmann",       // Richard Hirschmann GmbH Co
		"10704": "Barracuda",        // Barracuda AG (ex-phion)
		"26866": "Gigamon",          // Gigamon Systems LLC
		"116":   "HITACHI",          // Hitachi Ltd
		"89":    "Radware",          // RND (Radware origin)
		"4329":  "Siemens",          // Siemens AG
		"15004": "RuggedCOM",        // RuggedCom Inc (Siemens-owned, distinct NDX manufacturer)
		"7244":  "QCT",              // Quanta Computer Inc
		"2":     "IBM",              // IBM
		"31746": "Thales",           // Thales DIS (second PEN)
		"3697":  "Quantum",          // Quantum Corporation (second PEN)
	}
	for pen, want := range cases {
		got, err := resolver.GetManufacturer(pen)
		require.NoErrorf(t, err, "PEN %s", pen)
		assert.Equalf(t, want, got, "PEN %s", pen)
	}
}

func TestDeviceLookup_GetDeviceModel_Static(t *testing.T) {
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)

	got, err := deviceLookup.GetDeviceModel(".1.3.6.1.4.1.3375.2.1.3.4.113", nil)
	require.NoError(t, err)
	assert.Equal(t, "f5BIGIPi10800", got)
}

func TestDeviceLookup_GetDeviceModel_DynamicRef(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99999.1": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	walked := map[string]string{
		".1.3.6.1.2.1.1.1.0": "RouterOS CCR2004-16G-2S+",
	}
	got, err := deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99999.1", walked)
	require.NoError(t, err)
	assert.Equal(t, "RouterOS CCR2004-16G-2S+", got)
}

func TestDeviceLookup_GetDeviceModel_DynamicRefMissingFallsBack(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99998.1": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	_, err = deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99998.1", map[string]string{})
	require.Error(t, err)
}

func TestDeviceLookup_GetDeviceModel_DynamicRefEmptyValueFallsBack(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99997.1": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	walked := map[string]string{".1.3.6.1.2.1.1.1.0": "   \x00  "}
	_, err = deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99997.1", walked)
	require.Error(t, err, "whitespace/null-only source value must not be returned as a model")
}

func TestDeviceLookup_GetDeviceModel_StripsLeadingNullByte(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99996.1": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	walked := map[string]string{".1.3.6.1.2.1.1.1.0": "\x00\x00RouterOS 7.18"}
	got, err := deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99996.1", walked)
	require.NoError(t, err)
	assert.Equal(t, "RouterOS 7.18", got)
}

func TestDeviceLookup_GetDeviceModel_DynamicRefLeadingDotNormalization(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99995.1": .1.3.6.1.2.1.1.1.0
  ".1.3.6.1.4.1.99995.2": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	walkedNoDot := map[string]string{"1.3.6.1.2.1.1.1.0": "RouterOS A"}
	got, err := deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99995.1", walkedNoDot)
	require.NoError(t, err, "resolver must find walked entry whose key lacks the leading dot present in YAML")
	assert.Equal(t, "RouterOS A", got)

	walkedWithDot := map[string]string{".1.3.6.1.2.1.1.1.0": "RouterOS B"}
	got, err = deviceLookup.GetDeviceModel(".1.3.6.1.4.1.99995.2", walkedWithDot)
	require.NoError(t, err)
	assert.Equal(t, "RouterOS B", got)
}

func TestDeviceLookup_GetDevice_BackwardCompatibleLiteral(t *testing.T) {
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)
	got, err := deviceLookup.GetDevice(".1.3.6.1.4.1.3375.2.1.3.4.113")
	require.NoError(t, err)
	assert.Equal(t, "f5BIGIPi10800", got)
}

// Embedded YAML keys carry leading dots (e.g. ".1.3.6.1.4.1...") but
// callers may pass either spelling depending on how their SNMP layer
// formats OIDs. Both Get* methods must normalize.
func TestDeviceLookup_GetDevice_NoLeadingDotMatches(t *testing.T) {
	deviceLookup, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)
	got, err := deviceLookup.GetDevice("1.3.6.1.4.1.3375.2.1.3.4.113")
	require.NoError(t, err, "GetDevice should accept the no-leading-dot spelling for a YAML key written with a leading dot")
	assert.Equal(t, "f5BIGIPi10800", got)
}

func TestDeviceLookup_GetDeviceModel_DeviceOIDNoLeadingDotMatches(t *testing.T) {
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(`
devices:
  ".1.3.6.1.4.1.99994.1": .1.3.6.1.2.1.1.1.0
`), 0o644)
	require.NoError(t, err)

	deviceLookup, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	walked := map[string]string{".1.3.6.1.2.1.1.1.0": "RouterOS X"}
	// Caller passes deviceOID *without* the leading dot present in YAML.
	got, err := deviceLookup.GetDeviceModel("1.3.6.1.4.1.99994.1", walked)
	require.NoError(t, err, "GetDeviceModel must normalize deviceOID dot spelling against the loaded keys")
	assert.Equal(t, "RouterOS X", got)
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
		name            string
		content         string
		initialLiterals map[string]string // pre-seeded static entries
		expectedLiteral map[string]string // oid -> expected literal for static entries
		wantErr         bool
	}{
		{
			name: "valid YAML file",
			content: `devices:
    "1.3.6.1.4.1.9.1.1234": "Device A"
    "1.3.6.1.4.1.9.1.4321": "Device B"`,
			initialLiterals: make(map[string]string),
			expectedLiteral: map[string]string{
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
			initialLiterals: map[string]string{
				"1.3.6.1.4.1.9.1.1234": "Device A",
			},
			expectedLiteral: map[string]string{
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
			initialLiterals: make(map[string]string),
			expectedLiteral: make(map[string]string),
			wantErr:         true,
		},
		{
			name:            "empty file",
			content:         "",
			initialLiterals: make(map[string]string),
			expectedLiteral: make(map[string]string),
			wantErr:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create initial devicesByVendor map using the internal type.
			devicesByVendor := make(map[string]deviceRef)
			for k, v := range tt.initialLiterals {
				devicesByVendor[k] = deviceRef{kind: devRefStatic, literal: v}
			}

			// Test loadYAMLFile
			err = loadYAMLFile([]byte(tt.content), devicesByVendor)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify each expected static entry.
				for oid, want := range tt.expectedLiteral {
					ref, ok := devicesByVendor[oid]
					if assert.True(t, ok, "OID %s should be present", oid) {
						assert.Equal(t, devRefStatic, ref.kind)
						assert.Equal(t, want, ref.literal)
					}
				}
			}
		})
	}
}

func TestResolveDefault_Literal(t *testing.T) {
	v, ok := ResolveDefault("DC1-Building-A", nil)
	assert.True(t, ok)
	assert.Equal(t, "DC1-Building-A", v)
}

func TestResolveDefault_LiteralTrimsWhitespace(t *testing.T) {
	v, ok := ResolveDefault("  DC1  ", nil)
	assert.True(t, ok)
	assert.Equal(t, "DC1", v)
}

func TestResolveDefault_LiteralEmptyAfterTrim(t *testing.T) {
	_, ok := ResolveDefault("   ", nil)
	assert.False(t, ok)
}

func TestResolveDefault_EmptyRaw(t *testing.T) {
	_, ok := ResolveDefault("", nil)
	assert.False(t, ok)
}

func TestResolveDefault_NonSNMPDottedDecimalIsLiteral(t *testing.T) {
	v, ok := ResolveDefault("3.14.159", map[string]string{".1.3.6.1.2.1.1.6.0": "ignored"})
	assert.True(t, ok)
	assert.Equal(t, "3.14.159", v)
}

func TestResolveDefault_IPLikeLiteralIsLiteral(t *testing.T) {
	v, ok := ResolveDefault("10.0.0.1", nil)
	assert.True(t, ok)
	assert.Equal(t, "10.0.0.1", v)
}

func TestResolveDefault_OIDReferenceHit(t *testing.T) {
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "Data Center 01"}
	v, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", walked)
	assert.True(t, ok)
	assert.Equal(t, "Data Center 01", v)
}

func TestResolveDefault_OIDReferenceBothSpellingsTolerated(t *testing.T) {
	walked := map[string]string{"1.3.6.1.2.1.1.6.0": "Data Center 01"}
	v, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", walked)
	assert.True(t, ok)
	assert.Equal(t, "Data Center 01", v)
}

func TestResolveDefault_OIDReferenceMissing(t *testing.T) {
	_, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", map[string]string{})
	assert.False(t, ok)
}

func TestResolveDefault_OIDReferenceEmptyValue(t *testing.T) {
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "   "}
	_, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", walked)
	assert.False(t, ok)
}

func TestResolveDefault_OIDReferenceStripsLeadingNullByte(t *testing.T) {
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "\x00Data Center 01"}
	v, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", walked)
	assert.True(t, ok)
	assert.Equal(t, "Data Center 01", v)
}

func TestResolveDefault_OIDReferenceStripsTrailingNullByte(t *testing.T) {
	walked := map[string]string{".1.3.6.1.2.1.1.6.0": "Data Center 01\x00"}
	v, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", walked)
	assert.True(t, ok)
	assert.Equal(t, "Data Center 01", v)
}

func TestResolveDefault_OIDReferenceNilWalked(t *testing.T) {
	_, ok := ResolveDefault(".1.3.6.1.2.1.1.6.0", nil)
	assert.False(t, ok)
}

func TestResolveDefault_ExistingOIDPatternUnchanged(t *testing.T) {
	// Regression guard: the looser oidPattern used by GetDeviceModel must
	// not be tightened by this change.
	assert.True(t, oidPattern.MatchString(".1.3.6.1.4.1.14988.1"))
	assert.True(t, oidPattern.MatchString("3.14.159"))
}

// A user file can be read successfully and still contribute nothing: a wrong
// top-level key or bad indentation yields an empty devices map with no error.
// Before this report existed the loader reported plain success in that case, so
// an operator whose custom OID was ignored had no way to tell from the logs
// (issue #486). Each file's contribution is now recorded for the caller to log.
func TestLoadDeviceLookupExtensions_UserFileReport(t *testing.T) {
	const oid = ".1.3.6.1.4.1.52642.1.439.0"
	tests := []struct {
		name        string
		body        string
		wantEntries int
		wantErr     bool
		wantResolve bool
	}{
		{
			name:        "well-formed file",
			body:        "devices:\n  " + oid + ": S3400-24T4FP\n",
			wantEntries: 1,
			wantResolve: true,
		},
		{
			name:        "tab indentation is a parse error",
			body:        "devices:\n\t" + oid + ": S3400-24T4FP\n",
			wantEntries: 0,
			wantErr:     true,
		},
		{
			name:        "wrong top-level key parses to nothing",
			body:        "device:\n  " + oid + ": S3400-24T4FP\n",
			wantEntries: 0,
		},
		{
			name:        "no devices key at all",
			body:        "  " + oid + ": S3400-24T4FP\n",
			wantEntries: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "fs_custom.yaml"), []byte(tt.body), 0o600))

			dl, err := LoadDeviceLookupExtensions(dir)
			require.NoError(t, err, "a bad user file must not fail the whole load")

			files := dl.UserExtensionFiles()
			require.Len(t, files, 1, "the file must be reported either way")
			assert.Equal(t, "fs_custom.yaml", files[0].Name)
			assert.Equal(t, tt.wantEntries, files[0].Entries)
			if tt.wantErr {
				assert.Error(t, files[0].Err, "a parse failure must be reported, not swallowed")
			} else {
				assert.NoError(t, files[0].Err)
			}

			_, lookupErr := dl.GetDeviceModel(oid, map[string]string{})
			assert.Equal(t, tt.wantResolve, lookupErr == nil)
		})
	}
}

func TestLoadDeviceLookupExtensions_NoUserDirReportsNoFiles(t *testing.T) {
	dl, err := LoadDeviceLookupExtensions("")
	require.NoError(t, err)
	assert.Empty(t, dl.UserExtensionFiles(), "built-in-only load has no user files to report")
}

func TestLoadDeviceLookupExtensions_ReportSkipsNonYAML(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("ignore me"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ok.yaml"),
		[]byte("devices:\n  .1.3.6.1.4.1.9.1.1: someModel\n"), 0o600))

	dl, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)
	files := dl.UserExtensionFiles()
	require.Len(t, files, 1, "only YAML files are loaded, so only they are reported")
	assert.Equal(t, "ok.yaml", files[0].Name)
	assert.Equal(t, 1, files[0].Entries)
}

// A lookup-extension file may legitimately carry only a manufacturers: block.
// The same directory is read by NewManufacturerResolver, where such a file is
// valid and its overrides are applied, so the report must not present it as
// contributing nothing.
func TestLoadDeviceLookupExtensions_ManufacturerOnlyFileIsReported(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "mfr.yaml"),
		[]byte("manufacturers:\n  52642: FS\n  664: Adtran\n"), 0o600))

	dl, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)

	files := dl.UserExtensionFiles()
	require.Len(t, files, 1)
	assert.Equal(t, 0, files[0].Entries, "it declares no devices")
	assert.Equal(t, 2, files[0].ManufacturerEntries, "but it does declare manufacturers")
	assert.NoError(t, files[0].Err)
}

func TestLoadDeviceLookupExtensions_ReportCountsBothSections(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "both.yaml"), []byte(
		"devices:\n  .1.3.6.1.4.1.52642.1.439.0: S3400-24T4FP\nmanufacturers:\n  52642: FS\n"), 0o600))

	dl, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)
	files := dl.UserExtensionFiles()
	require.Len(t, files, 1)
	assert.Equal(t, 1, files[0].Entries)
	assert.Equal(t, 1, files[0].ManufacturerEntries)
}

func TestLoadDeviceLookupExtensions_FileWithNeitherSectionReportsNothing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "empty.yaml"),
		[]byte("device:\n  .1.3.6.1.4.1.52642.1.439.0: S3400\n"), 0o600))

	dl, err := LoadDeviceLookupExtensions(dir)
	require.NoError(t, err)
	files := dl.UserExtensionFiles()
	require.Len(t, files, 1)
	assert.Equal(t, 0, files[0].Entries)
	assert.Equal(t, 0, files[0].ManufacturerEntries)
}
