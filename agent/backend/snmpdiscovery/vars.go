package snmpdiscovery

import (
	"github.com/spf13/viper"
)

// RegisterBackendSpecificVariables registers the backend specific variables for the network discovery backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.snmp_discovery.host", defaultAPIHost)
	v.SetDefault("orb.backends.snmp_discovery.port", defaultAPIPort)
}
