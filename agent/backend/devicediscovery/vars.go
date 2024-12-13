package devicediscovery

import (
	"github.com/spf13/viper"
)

func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.device_discovery.host", DefaultAPIHost)
	v.SetDefault("orb.backends.device_discovery.port", DefaultAPIPort)
}
