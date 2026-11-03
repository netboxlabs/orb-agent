package policy

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// lineWith returns the first log line containing msg, or "".
func lineWith(out, msg string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, msg) {
			return l
		}
	}
	return ""
}

// The parse-time target warnings name the policy: one payload carries several
// policies, and a host alone does not say which of them to fix.
func TestParseTimeTargetWarningsNameThePolicy(t *testing.T) {
	var logs bytes.Buffer
	m := newManagerWithLogger(t, slog.New(slog.NewTextHandler(&logs, nil)))
	_, err := m.ParsePolicies([]byte(`
policies:
  ports:
    scope:
      targets:
        - host: 192.0.2.1:6030
          port: 57400
  unverified:
    config:
      send_credentials_to_unverified_targets: true
    scope:
      username: admin
      password: lab-secret
      tls:
        skip_verify: true
      targets:
        - host: 198.51.100.0/28
`))
	require.NoError(t, err)

	inline := lineWith(logs.String(), "the inline port wins")
	require.NotEmpty(t, inline)
	require.Contains(t, inline, "policy=ports")

	unauth := lineWith(logs.String(), "not authenticated")
	require.NotEmpty(t, unauth)
	require.Contains(t, unauth, "policy=unverified")
}
