package networkdiscovery

import (
	"github.com/spf13/viper"
)

func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.network_discovery.host", DefaultAPIHost)
	v.SetDefault("orb.backends.network_discovery.port", DefaultAPIPort)
}
