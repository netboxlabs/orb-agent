package networkdiscovery

import (
	"github.com/spf13/viper"
)

// RegisterBackendSpecificVariables registers the backend specific variables for the network discovery backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.network_discovery.host", defaultAPIHost)
	v.SetDefault("orb.backends.network_discovery.port", defaultAPIPort)
}
