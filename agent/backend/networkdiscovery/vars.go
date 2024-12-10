package networkdiscovery

import (
	"github.com/spf13/viper"
)

func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.network_discovery.config_file", "/opt/orb/agent.yaml")
}
