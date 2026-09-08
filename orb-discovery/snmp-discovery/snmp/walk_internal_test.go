package snmp

import (
	"context"
	"errors"
	"fmt"
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
	rows, err := collectWalk(context.Background(), feed(".1.3.6.1.2.1.17.7.1.4.5.1.1.18", ".1.3.6.1.2.1.17.7.1.4.5.1.1.48", ".1.3.6.1.2.1.17.7.1.4.5.1.1.19"), 1)
	require.NoError(t, err)
	assert.Len(t, rows, 3)
	assert.Equal(t, 1, rows[".1.3.6.1.2.1.17.7.1.4.5.1.1.48"].IdentifierSize)
}

// A repeated OID is the one way a walk without the ordering check can loop,
// so it ends the table with the rows collected before it.
func TestCollectWalkEndsTheTableOnARepeatedOID(t *testing.T) {
	rows, err := collectWalk(context.Background(), feed(".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2.2", ".1.3.6.1.2.1.2.2.1.2.1", ".1.3.6.1.2.1.2.2.1.2.3"), 1)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "the walk stops at the repeat; nothing after it is read")
}

// Any other error the walk reports still fails the table.
func TestCollectWalkReportsOtherErrors(t *testing.T) {
	boom := errors.New("request timeout")
	_, err := collectWalk(context.Background(), func(fn gosnmp.WalkFunc) error {
		_ = fn(gosnmp.SnmpPDU{Name: ".1.3.6.1.2.1.2.2.1.2.1", Type: gosnmp.Integer, Value: 1})
		return boom
	}, 1)
	assert.ErrorIs(t, err, boom)
}

// A repeated OID is not the only shape of a runaway walk: an agent can hand
// back a new, non-increasing OID on every request, and the ordering check
// that would have ended it is off. A table therefore ends at a hard row cap,
// with what was collected and the truncation reported, never failing.
func TestCollectWalkEndsTheTableAtTheRowCap(t *testing.T) {
	endless := func(fn gosnmp.WalkFunc) error {
		// Every row a new OID, each below the one before, none repeated.
		for i := 2_000_000_000; ; i-- {
			name := fmt.Sprintf(".1.3.6.1.2.1.17.1.4.1.2.%d", i)
			if err := fn(gosnmp.SnmpPDU{Name: name, Type: gosnmp.Integer, Value: 1}); err != nil {
				return err
			}
		}
	}
	rows, err := collectWalk(context.Background(), endless, 1)
	require.ErrorIs(t, err, ErrWalkTruncated)
	assert.Len(t, rows, maxWalkRows, "the rows collected before the cap are kept")
}

// The policy's context reaches the walk and ends it: a row delivered after
// the context ended is not collected, and the table reports the context's
// error, so a runaway agent costs at most the policy's timeout plus one
// request, and the runner's timeout actually stops the walker.
func TestCollectWalkStopsWhenTheContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	delivered := 0
	endless := func(fn gosnmp.WalkFunc) error {
		for i := 2_000_000_000; ; i-- {
			delivered++
			if delivered == 3 {
				cancel()
			}
			if err := fn(gosnmp.SnmpPDU{Name: fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i), Type: gosnmp.Integer, Value: 1}); err != nil {
				return err
			}
		}
	}
	_, err := collectWalk(ctx, endless, 1)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 3, delivered, "the walk ends on the first row after the context ended")
}

// A walk that delivers no rows never reaches the row callback, so the
// context is checked once the walk returns as well: a table that ended
// empty after the deadline reports the context's error, not success.
func TestCollectWalkChecksTheContextAfterAnEmptyWalk(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := collectWalk(ctx, func(gosnmp.WalkFunc) error { return nil }, 1)
	require.ErrorIs(t, err, context.Canceled)
}
