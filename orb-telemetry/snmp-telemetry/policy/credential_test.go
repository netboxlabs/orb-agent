package policy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/collector"
	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// erringCollector fails every collection with err.
type erringCollector struct {
	failingCollector
	err error
}

func (e *erringCollector) CollectTarget(context.Context, config.Target, *config.Authentication, string, collector.DialOptions) error {
	return e.err
}

// A device that refuses an SNMPv3 credential answers with a report PDU, so the
// policy's error says it refused the credential and which setting to check,
// keeping what gosnmp said; a device that does not answer still reads as a
// timeout. No credential value is in either.
func TestRunMetrics_NamesARefusedSNMPv3Credential(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"unknown user": {
			err:  gosnmp.ErrUnknownUsername,
			want: "the device refused the SNMPv3 credential (the device does not know the username): getting sysObjectID from 10.0.0.1: unknown username",
		},
		"wrong digest": {
			err:  gosnmp.ErrWrongDigest,
			want: "the device refused the SNMPv3 credential (check the auth_protocol and auth_passphrase): getting sysObjectID from 10.0.0.1: wrong digest",
		},
		"decryption": {
			err:  gosnmp.ErrDecryption,
			want: "the device refused the SNMPv3 credential (check the priv_protocol and priv_passphrase): getting sysObjectID from 10.0.0.1: decryption error",
		},
		"security level": {
			err:  gosnmp.ErrUnknownSecurityLevel,
			want: "the device refused the SNMPv3 credential (the device does not accept the security_level for the username): getting sysObjectID from 10.0.0.1: unknown security level",
		},
		"timeout": {
			err:  errors.New("request timeout (after 1 retries)"),
			want: "getting sysObjectID from 10.0.0.1: request timeout (after 1 retries)",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := &erringCollector{err: fmt.Errorf("getting sysObjectID from 10.0.0.1: %w", tc.err)}
			r, err := NewRunner(t.Context(), testLogger, "p1", policyWithDial(60, 5, 0), c, nil)
			require.NoError(t, err)

			r.runMetrics(config.Target{Host: "10.0.0.1", Port: 161})
			_, lastErr := r.GetLastError()
			require.Error(t, lastErr)
			assert.Equal(t, "metrics collection failed: 10.0.0.1:161: "+tc.want, lastErr.Error())
			assert.ErrorIs(t, credentialRefusal(c.err), tc.err, "what gosnmp said is kept")
		})
	}
}
