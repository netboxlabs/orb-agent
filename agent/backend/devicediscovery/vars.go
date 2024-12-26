package devicediscovery

import (
	"github.com/spf13/viper"
)

// RegisterBackendSpecificVariables registers the backend specific variables for the device discovery backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.device_discovery.host", defaultAPIHost)
	v.SetDefault("orb.backends.device_discovery.port", defaultAPIPort)
}
