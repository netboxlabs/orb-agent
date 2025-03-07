package pktvisor

import (
	"github.com/spf13/viper"
)

// RegisterBackendSpecificVariables registers the backend specific variables for the pktvisor backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.pktvisor.binary", "/usr/local/bin/pktvisord")
	v.SetDefault("orb.backends.pktvisor.host", "localhost")
	v.SetDefault("orb.backends.pktvisor.port", "10853")
}
