package worker

import (
	"github.com/spf13/viper"
)

// RegisterBackendSpecificVariables registers the backend specific variables for the worker backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.worker.host", defaultAPIHost)
	v.SetDefault("orb.backends.worker.port", defaultAPIPort)
}
