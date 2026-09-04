package gnmi

import (
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConvertNotificationKeepsTheDeviceTimestamp(t *testing.T) {
	n := convertNotification(&gnmiproto.Notification{
		Timestamp: 1788550104870000000,
		Update: []*gnmiproto.Update{{
			Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "interfaces"}, {Name: "interface", Key: map[string]string{"name": "e1"}}, {Name: "state"}, {Name: "counters"}, {Name: "in-octets"}}},
			Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_UintVal{UintVal: 1394}},
		}},
	})
	assert.Equal(t, int64(1788550104870000000), n.Timestamp)
	require.Len(t, n.Updates, 1)
	assert.Equal(t, "/interfaces/interface[name=e1]/state/counters/in-octets", n.Updates[0].Path)
	assert.Equal(t, uint64(1394), n.Updates[0].Value, "counters stay unsigned 64-bit")
}

func TestBuildSubscribeRequestCarriesEachSubscriptionsModeAndOrigin(t *testing.T) {
	req, err := buildSubscribeRequest("PROTO", []Subscription{
		{Path: "/interfaces/interface[name=*]/state/counters", Origin: "openconfig", Mode: Sample, SampleIntervalMs: 30000},
		{Path: "/interfaces/interface[name=*]/state/oper-status", Origin: "openconfig", Mode: OnChange},
		{Path: "/platform/control[slot=*]/memory", Origin: "", Mode: Sample, SampleIntervalMs: 30000},
	})
	require.NoError(t, err)
	subs := req.GetSubscribe().GetSubscription()
	require.Len(t, subs, 3)
	assert.Equal(t, gnmiproto.SubscriptionMode_SAMPLE, subs[0].GetMode())
	assert.Equal(t, uint64(30_000_000_000), subs[0].GetSampleInterval())
	assert.Equal(t, "openconfig", subs[0].GetPath().GetOrigin())
	assert.Equal(t, gnmiproto.SubscriptionMode_ON_CHANGE, subs[1].GetMode())
	assert.Equal(t, "", subs[2].GetPath().GetOrigin(), "an empty origin is the native schema")
	assert.Equal(t, gnmiproto.Encoding_PROTO, req.GetSubscribe().GetEncoding())
}

func TestBuildSubscribeRequestRejectsAnUnknownMode(t *testing.T) {
	_, err := buildSubscribeRequest("PROTO", []Subscription{{Path: "/x", Mode: Get}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), `mode "get" is not a stream mode`)
}

func TestMergeGetResultsKeepsTheLatestDeviceTimestamp(t *testing.T) {
	var merged Notification
	merged.SyncDone = true
	mergeGetResults(&merged, Notification{Timestamp: 5, Updates: []Update{{Path: "/a", Value: uint64(1)}}})
	mergeGetResults(&merged, Notification{Timestamp: 9, Updates: []Update{{Path: "/b", Value: uint64(2)}}, Deletes: []string{"/c"}})
	mergeGetResults(&merged, Notification{Timestamp: 0, Updates: []Update{{Path: "/d", Value: uint64(3)}}})
	assert.Equal(t, int64(9), merged.Timestamp, "the latest device time stamps the merged snapshot, and an unstamped notification does not lower it")
	require.Len(t, merged.Updates, 3)
	assert.Equal(t, []string{"/c"}, merged.Deletes)
}
