package metrics

import "strings"

// maskedLogin replaces the login of a collector URL where a line writes it.
const maskedLogin = "********"

// MaskedEndpoint returns endpoint, a collector URL or host:port, with the
// login it carries, as grpc://user:password@host:port or
// user:password@host:port, masked as ********, for a line that reports it.
// The exporter is given endpoint as written.
func MaskedEndpoint(endpoint string) string {
	return maskLogin(endpoint, endpoint)
}

// maskLogin returns text with the login endpoint carries masked wherever
// text writes it before an @.
func maskLogin(text, endpoint string) string {
	login := endpointLogin(endpoint)
	if login == "" {
		return text
	}
	return strings.ReplaceAll(text, login+"@", maskedLogin+"@")
}

// endpointLogin returns the login endpoint carries, as written, or "": what
// comes before its last @, after its scheme's :// or its //, and after the
// third / of an empty authority, as gRPC's dns:/// writes one; or from its
// start, when it is written without //.
func endpointLogin(endpoint string) string {
	start := 0
	if i := strings.Index(endpoint, "//"); i >= 0 {
		start = i + len("//")
	}
	for start < len(endpoint) && endpoint[start] == '/' {
		start++
	}
	at := strings.LastIndex(endpoint, "@")
	if at <= start {
		return ""
	}
	return endpoint[start:at]
}
