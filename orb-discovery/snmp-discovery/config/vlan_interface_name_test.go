package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateVlanInterfaceNamePrefix(t *testing.T) {
	for _, ok := range []string{"", "Vlan", "vlan", "vlan ", "VLAN ID ", "vlan-", "Vlan_", strings.Repeat("v", 60)} {
		assert.NoError(t, ValidateVlanInterfaceNamePrefix(ok), "%q", ok)
	}
	for _, bad := range []string{
		" vlan",                   // leading space
		"vlan  ",                  // two trailing spaces
		"vlan  id",                // two spaces inside
		"vlan\t",                  // not a space
		"Vlan1",                   // a digit runs into the VID
		"Vl4n",                    // a digit anywhere
		"-vlan",                   // must start with a letter
		"vlan.",                   // a dot reads as a subinterface
		"vlan:",                   // so does a colon
		"vlan/",                   // a slash reads as a stack member
		"vl.an", "vl:an", "vl/an", // between words too
		"vlan{vid}",             // not a template
		"vlän",                  // letters are ASCII
		strings.Repeat("v", 61), // with 4094 that is past NetBox's 64
	} {
		assert.Error(t, ValidateVlanInterfaceNamePrefix(bad), "%q", bad)
	}
}

func TestMergeDefaults_VlanInterfaceNamePrefix(t *testing.T) {
	policy := &Defaults{VlanInterfaceNamePrefix: "Vlan"}
	assert.Equal(t, "vlan ", MergeDefaults(policy, &Defaults{VlanInterfaceNamePrefix: "vlan "}).VlanInterfaceNamePrefix)
	assert.Equal(t, "Vlan", MergeDefaults(policy, &Defaults{}).VlanInterfaceNamePrefix)
	assert.Equal(t, "Vlan", MergeDefaults(policy, nil).VlanInterfaceNamePrefix)
}
