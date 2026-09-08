package snmp

import (
	"errors"
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// feed builds a walk function that delivers the given rows in order.
func feed(names ...string) func(fn gosnmp.WalkFunc) error {
	return func(fn gosnmp.WalkFunc) error {
		for _, n := range names {
			if err := fn(gosnmp.SnmpPDU{Name: n, Type: gosnmp.Integer, Value: 1}); err != nil {
				return err
			}
		}
		return nil
	}
}

// Rows an agent returns out of index order are all kept: the check that
// refused them ended the table and, with it, the target, for a quirk no
// operator can correct from our side.
func TestCollectWalkKeepsRowsOutOfOrder(t *testing.T) {
	rows, err := collectWalk(feed(".1.3.6.1.2.1.17.7.1.4.5.1.1.18", ".1.3.6.1.2.1.17.7.1.4.5.1.1.48", ".1.3.6.1.2.1.17.7.1.4.5.1.1.19"), 1)
	require.NoError(t, err)
	assert.Len(t, rows, 3)
	assert.Equal(t, 1, rows[".1.3.6.1.2.1.17.7.1.4.5.1.1.48"].IdentifierSize)
}

// A repeated OID is the one way a walk without the ordering check can loop,
// so it ends the table with the rows collected before it.
func TestCollectWalkEndsTheTableOnARepeatedOID(t *testing.T) {
	rows, err := collectWalk(feed(".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2.2", ".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2.3"), 1)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "the walk stops at the repeat; nothing after it is read")
}

// Any other error the walk reports still fails the table.
func TestCollectWalkReportsOtherErrors(t *testing.T) {
	boom := errors.New("request timeout")
	_, err := collectWalk(func(fn gosnmp.WalkFunc) error {
		_ = fn(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.Integer, Value: 1})
		return boom
	}, 1)
	assert.ErrorIs(t, err, boom)
}
