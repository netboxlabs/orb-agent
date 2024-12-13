package devicediscovery

import (
	"github.com/spf13/viper"
)

func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.device_discovery.host", "localhost")
	v.SetDefault("orb.backends.device_discovery.port", "8072")
}
