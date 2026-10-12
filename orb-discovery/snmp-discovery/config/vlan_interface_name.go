package config

import (
	"errors"
	"regexp"
)

// vlanInterfaceNamePrefixRe allows ASCII words of letters, - and _, joined by
// single spaces, with at most one trailing space. Digits would run into the
// VID, and a dot, colon or slash makes the name read as a subinterface or a
// stack member.
var vlanInterfaceNamePrefixRe = regexp.MustCompile(`^[A-Za-z][A-Za-z_-]*(?: [A-Za-z_-]+)* ?$`)

// maxVlanInterfaceNamePrefix keeps prefix + "4094" within NetBox's 64
// characters.
const maxVlanInterfaceNamePrefix = 60

// ValidateVlanInterfaceNamePrefix checks a vlan_interface_name_prefix. Empty is
// valid and keeps the device's names.
func ValidateVlanInterfaceNamePrefix(prefix string) error {
	if prefix == "" {
		return nil
	}
	if !vlanInterfaceNamePrefixRe.MatchString(prefix) {
		return errors.New("must start with an ASCII letter and hold only ASCII letters, - and _, " +
			"in words joined by single spaces, optionally ending in one space")
	}
	if len(prefix) > maxVlanInterfaceNamePrefix {
		return errors.New("must be at most 60 characters, so VLAN 4094 fits NetBox's 64")
	}
	return nil
}
