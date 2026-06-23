package gnmi

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeSubscribeReplaysStream(t *testing.T) {
	f := &FakeSession{
		OnChangeSupport: true,
		OnChangeStream: []Notification{
			{Updates: []Update{{Path: "/system/state/hostname", Value: "r1"}}},
			{SyncDone: true},
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	notes, _, err := f.Subscribe(ctx, OnChange, []string{"/system"}, 0)
	require.NoError(t, err)
	first := <-notes
	require.Equal(t, "r1", first.Updates[0].Value)
	second := <-notes
	require.True(t, second.SyncDone)
}

func TestFakeSubscribeOnChangeUnsupported(t *testing.T) {
	f := &FakeSession{OnChangeSupport: false}
	_, _, err := f.Subscribe(context.Background(), OnChange, nil, 0)
	require.Error(t, err)
}
