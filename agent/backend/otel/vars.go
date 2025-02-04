package otel

import "github.com/spf13/viper"

// RegisterBackendSpecificVariables registers the backend specific variables for the otel backend
func RegisterBackendSpecificVariables(v *viper.Viper) {
	v.SetDefault("orb.backends.otel.server_port", "10222")
}
