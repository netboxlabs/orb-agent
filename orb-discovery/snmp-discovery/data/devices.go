package data

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type deviceConfig struct {
	Manufacturers []Manufacturer `yaml:"manufacturers"`
	Devices       []Device       `yaml:"devices"`
}

// Manufacturer represents a manufacturer
type Manufacturer struct {
	PrivateEnterpriseNumber int    `yaml:"pen"`
	Name                    string `yaml:"name"`
}

// Device represents a device
type Device struct {
	ID   int    `yaml:"id"`
	OID  string `yaml:"oid"`
	Name string `yaml:"name"`
}

// DeviceDataRetreiver is a type that can retrieve device data
type DeviceDataRetreiver interface {
	GetManufacturer(id int) (string, error)
	GetDeviceModel(id int) (string, error)
}

// Devices represents a collection of manufacturers
type Devices struct {
	manufacturers map[int]Manufacturer
	devices       map[int]Device
}

// NewDevices returns a new Devices
func NewDevices(filePath string) (DeviceDataRetreiver, error) {
	devices := deviceConfig{}
	yamlFile, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	err = yaml.Unmarshal(yamlFile, &devices)
	if err != nil {
		return nil, err
	}

	manufacturersData := make(map[int]Manufacturer)
	for _, manufacturer := range devices.Manufacturers {
		manufacturersData[manufacturer.PrivateEnterpriseNumber] = manufacturer
	}
	devicesData := make(map[int]Device)
	for _, device := range devices.Devices {
		devicesData[device.ID] = device
	}
	return &Devices{
		manufacturers: manufacturersData,
		devices:       devicesData,
	}, nil
}

// GetManufacturer returns a manufacturer by its private enterprise number
func (d *Devices) GetManufacturer(id int) (string, error) {
	device, ok := d.manufacturers[id]
	if !ok {
		return "", fmt.Errorf("manufacturer not found")
	}
	return device.Name, nil
}

// GetDeviceModel returns a device model by its id
func (d *Devices) GetDeviceModel(id int) (string, error) {
	device, ok := d.devices[id]
	if !ok {
		return "", fmt.Errorf("device not found")
	}
	return device.Name, nil
}

// NewEmptyDevicesList returns a new empty Devices
func NewEmptyDevicesList() DeviceDataRetreiver {
	return &Devices{
		manufacturers: make(map[int]Manufacturer),
		devices:       make(map[int]Device),
	}
}
