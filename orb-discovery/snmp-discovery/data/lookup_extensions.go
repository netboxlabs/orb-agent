package data

import (
	"bufio"
	"embed"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed manufacturers.yaml
var manufacturersData embed.FS

// ManufacturerRetriever is an interface that provides a method to retrieve a manufacturer by ID
type ManufacturerRetriever interface {
	GetManufacturer(id string) (string, error)
}

// ManufacturerLookup represents a manufacturer lookup service
type ManufacturerLookup struct {
	data *map[string]string
}

// NewManufacturerLookup creates a new manufacturer lookup service
func NewManufacturerLookup() (*ManufacturerLookup, error) {
	file, err := manufacturersData.Open("manufacturers.yaml")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Println("Error closing file:", err)
		}
	}()

	manufacturers := make(map[string]string)
	// Don't use yaml.Unmarshal because it is way too slow for a large file
	scanner := bufio.NewScanner(file)

	// Skip the first line which is "manufacturers:"
	_ = scanner.Scan()

	// Parse each line
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Parse lines in format "  ID: Name"
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		id := strings.TrimSpace(parts[0])
		name := strings.TrimSpace(parts[1])

		manufacturers[id] = name
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &ManufacturerLookup{
		data: &manufacturers,
	}, nil
}

// GetManufacturer returns the manufacturer name for a given ID
func (m *ManufacturerLookup) GetManufacturer(id string) (string, error) {
	if name, ok := (*m.data)[id]; ok {
		return name, nil
	}
	return "", fmt.Errorf("manufacturer not found")
}

// DeviceRetriever is an interface that provides a method to retrieve device information by device OID
type DeviceRetriever interface {
	GetDevice(deviceOID string) (string, error)
}

// DeviceLookup represents a device lookup service
type DeviceLookup struct {
	devicesByVendor map[string]string
}

// GetDevice returns the device name for given device OID
func (d *DeviceLookup) GetDevice(deviceOID string) (string, error) {
	if device, ok := d.devicesByVendor[deviceOID]; ok {
		return device, nil
	}
	return "", fmt.Errorf("device ID %s not found", deviceOID)
}

// LoadDeviceLookupExtensions loads device data from YAML files in the specified directory
func LoadDeviceLookupExtensions(dir string) (*DeviceLookup, error) {
	// Read all files in the directory
	files, err := os.ReadDir(dir)
	if err != nil {
		return &DeviceLookup{
			devicesByVendor: make(map[string]string),
		}, fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	devicesByVendor := make(map[string]string)

	for _, file := range files {
		if !isLookupExtensionFile(file) {
			log.Printf("Warning: skipping file %s", file.Name())
			continue
		}

		filePath := filepath.Join(dir, file.Name())
		if err := loadYAMLFile(filePath, &devicesByVendor); err != nil {
			safeFilePath := strings.ReplaceAll(filePath, "\n", "")
			safeFilePath = strings.ReplaceAll(safeFilePath, "\r", "")
			safeErr := strings.ReplaceAll(err.Error(), "\n", "")
			safeErr = strings.ReplaceAll(safeErr, "\r", "")
			log.Printf("Warning: failed to load YAML file %s: %s", safeFilePath, safeErr)
			continue
		}
	}

	return &DeviceLookup{
		devicesByVendor: devicesByVendor,
	}, nil
}

func isLookupExtensionFile(file os.DirEntry) bool {
	return !file.IsDir() &&
		(strings.HasSuffix(strings.ToLower(file.Name()), ".yaml") ||
			strings.HasSuffix(strings.ToLower(file.Name()), ".yml"))
}

// loadYAMLFile loads a single YAML file and merges its data into devicesByVendor
func loadYAMLFile(filePath string, devicesByVendor *map[string]string) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	var fileData struct {
		Devices map[string]string `yaml:"devices"`
	}

	if err := yaml.Unmarshal(data, &fileData); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	// Merge the data into devicesByVendor
	for deviceOID, deviceName := range fileData.Devices {
		(*devicesByVendor)[deviceOID] = deviceName
	}

	return nil
}
