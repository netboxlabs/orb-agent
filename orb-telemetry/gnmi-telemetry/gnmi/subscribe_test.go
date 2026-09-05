package gnmi

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	gapi "github.com/openconfig/gnmic/pkg/api"
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

// A JSON payload carries its numbers as digits, and a float64 holds only 53 of
// them: a counter64 past that rounds on the way in, so 9007199254740993 would
// be exported as 9007199254740992. The decoded number keeps the digits the
// device sent, and the value converters read them.
func TestJSONNumbersDecodeWithoutRounding(t *testing.T) {
	for name, tv := range map[string]*gnmiproto.TypedValue{
		"json_ietf": {Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte("9007199254740993")}},
		"json":      {Value: &gnmiproto.TypedValue_JsonVal{JsonVal: []byte("9007199254740993")}},
	} {
		decoded := decodeTypedValue(tv)
		n, ok := decoded.(json.Number)
		require.True(t, ok, "%s: a JSON number decodes as a json.Number, got %T", name, decoded)
		assert.Equal(t, "9007199254740993", n.String(), name)
	}
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

// A pruned path is a routine device condition, so it belongs to whatever logger
// the deployment configured: through the package-level slog it printed a text
// line on stderr at info level even under --log-level error, and beside the JSON
// stream everywhere else.
func TestLogPrunedWritesToTheSessionsLogger(t *testing.T) {
	var configured, fallback bytes.Buffer
	saved := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&fallback, nil)))
	t.Cleanup(func() { slog.SetDefault(saved) })

	logPruned(slog.New(slog.NewTextHandler(&configured, nil)),
		Subscription{Path: "/platform/component[name=*]/state/temperature", Origin: "openconfig"},
		errors.New("unknown path"))

	assert.Contains(t, configured.String(), "gnmi subscription path pruned")
	assert.Contains(t, configured.String(), "/platform/component[name=*]/state/temperature")
	assert.Empty(t, fallback.String(), "the configured logger receives it, not the default")

	// A session dialed by a GnmicDialer with no logger of its own still logs.
	logPruned(nil, Subscription{Path: "/x"}, errors.New("unknown path"))
	assert.Contains(t, fallback.String(), "gnmi subscription path pruned")
}

// gnmic's attemptSubscription defers StopSubscription(name), which cancels and
// deletes whatever the target holds under that name. The auto ladder stops one
// attempt and opens the next on the same session, so an attempt registered
// under the name the previous one still owns is torn down by the previous
// producer's own cleanup as it exits, and a target that rejects ON_CHANGE
// skips the SAMPLE rung it does support. Each attempt therefore registers
// under a name of its own.
func TestEachSubscriptionAttemptRegistersUnderItsOwnName(t *testing.T) {
	s := &gnmicSession{}
	first, second := s.nextSubscriptionName(), s.nextSubscriptionName()

	assert.NotEqual(t, first, second, "a second attempt must not reuse the name the first still owns")
	for _, name := range []string{first, second} {
		assert.True(t, strings.HasPrefix(name, subscriptionPrefix+"-"),
			"a subscription name carries the backend's prefix, got %q", name)
	}
}

// StopSubscribe stops the name of the attempt this session registered and
// releases it, so it never reaches into a name a later attempt owns. A session
// that registered nothing stops nothing: there is no name of ours on the
// target, and no target to stop it on either.
func TestStopSubscribeStopsOnlyTheNameThisSessionRegistered(t *testing.T) {
	assert.NotPanics(t, (&gnmicSession{}).StopSubscribe, "a session that never subscribed stops nothing")

	tg, err := gapi.NewTarget(gapi.Name("t"), gapi.Address("127.0.0.1:57400"), gapi.Insecure(true))
	require.NoError(t, err)
	s := &gnmicSession{tg: tg}
	s.subName = s.nextSubscriptionName()
	s.StopSubscribe()
	assert.Empty(t, s.subName, "the stopped attempt's name is released with it")
	assert.NotPanics(t, s.StopSubscribe, "stopping again is a no-op")
}
