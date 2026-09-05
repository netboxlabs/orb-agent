package gnmi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	gapi "github.com/openconfig/gnmic/pkg/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// A decoder reads one value and stops where a whole-payload unmarshal refuses
// what follows it, so a payload that is not one JSON value would have decoded to
// its own prefix: "123garbage" would have been the number 123, and "123]" the
// same, since the bracket closes nothing the decoder opened. The caller keeps
// such a payload as the string the device sent.
func TestAPayloadThatIsNotOneJSONValueStaysAString(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  string
		want any
	}{
		"trailing text":    {raw: "123garbage", want: "123garbage"},
		"hex":              {raw: "0x10", want: "0x10"},
		"two objects":      {raw: `{"a":1}{"b":2}`, want: `{"a":1}{"b":2}`},
		"closing bracket":  {raw: "123]", want: "123]"},
		"closed object":    {raw: "{}]", want: "{}]"},
		"two numbers":      {raw: "123 456", want: "123 456"},
		"number":           {raw: "123", want: json.Number("123")},
		"trailing newline": {raw: "123\n", want: json.Number("123")},
		"object":           {raw: `{"a":1}`, want: map[string]any{"a": json.Number("1")}},
		"array":            {raw: "[1,2]", want: []any{json.Number("1"), json.Number("2")}},
		"string":           {raw: `"text"`, want: "text"},
	} {
		got := decodeTypedValue(&gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_JsonIetfVal{JsonIetfVal: []byte(tc.raw)}})
		assert.Equal(t, tc.want, got, name)
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

// getServer answers a gNMI Get for the paths it holds and fails for any other,
// which is how a target behaves toward an optional subtree it does not model.
// A multi-path request is refused outright when multi is false, the atomic
// failure GetOnce recovers from one path at a time. A path in blocks is never
// answered at all: the request waits for its own cancellation, which is how a
// target that accepts a connection and then goes silent under one subtree
// behaves.
type getServer struct {
	gnmiproto.UnimplementedGNMIServer
	holds  map[string]bool
	blocks map[string]bool
	multi  bool
	// capsBlocks holds the Capabilities RPC the same way blocks holds a Get:
	// the request waits for its own cancellation, which is how a target that
	// accepts a connection and then says nothing at all behaves.
	capsBlocks bool
}

// Capabilities answers the RPC that opens every session, with the empty
// advertisement of a target that names no encoding, or holds it for ever when
// the server is told to.
func (g *getServer) Capabilities(ctx context.Context, _ *gnmiproto.CapabilityRequest) (*gnmiproto.CapabilityResponse, error) {
	if g.capsBlocks {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &gnmiproto.CapabilityResponse{}, nil
}

func (g *getServer) Get(ctx context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
	if len(req.GetPath()) > 1 && !g.multi {
		return nil, status.Error(codes.Unimplemented, "one path per request")
	}
	var notifications []*gnmiproto.Notification
	for _, p := range req.GetPath() {
		rendered := pathToString(p)
		if g.blocks[rendered] {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		if !g.holds[rendered] {
			return nil, status.Errorf(codes.NotFound, "unknown path %s", rendered)
		}
		notifications = append(notifications, &gnmiproto.Notification{
			Update: []*gnmiproto.Update{{
				Path: p,
				Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_UintVal{UintVal: 1}},
			}},
		})
	}
	return &gnmiproto.GetResponse{Notification: notifications}, nil
}

// serveGet serves the given server on loopback and returns its address.
func serveGet(t *testing.T, srv *getServer) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	grpcServer := grpc.NewServer()
	gnmiproto.RegisterGNMIServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(ln) }()
	t.Cleanup(grpcServer.Stop)
	return ln.Addr().String()
}

// getSession serves the given server on loopback and returns a session dialed
// to it, the way GnmicDialer dials a plaintext target.
func getSession(t *testing.T, srv *getServer) *gnmicSession {
	t.Helper()
	tg, err := gapi.NewTarget(gapi.Name("t"), gapi.Address(serveGet(t, srv)), gapi.Insecure(true))
	require.NoError(t, err)
	t.Cleanup(func() { _ = tg.Close() })
	require.NoError(t, tg.CreateGNMIClient(context.Background()))
	return &gnmicSession{tg: tg}
}

// A Get that recovers per path returns what it managed to fetch and calls that
// success, so the snapshot alone cannot say which paths answered. It reports
// them, because the caller reconciles the series of the paths a snapshot speaks
// for and a path whose Get failed is one it says nothing about.
func TestGetOnceReportsThePathsItFetched(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"

	whole := getSession(t, &getServer{holds: map[string]bool{memory: true, interfaces: true}, multi: true})
	n, err := whole.GetOnce(context.Background(), []string{memory, interfaces})
	require.NoError(t, err)
	assert.Equal(t, []string{memory, interfaces}, n.Paths, "a target that answered the whole request fetched every path")
	assert.Len(t, n.Updates, 2)

	partial := getSession(t, &getServer{holds: map[string]bool{memory: true}})
	n, err = partial.GetOnce(context.Background(), []string{memory, interfaces})
	require.NoError(t, err, "one unsupported path does not fail the snapshot")
	assert.Equal(t, []string{memory}, n.Paths, "only the path that answered is reported as fetched")
	require.Len(t, n.Updates, 1)
	assert.Equal(t, memory, n.Updates[0].Path)

	none := getSession(t, &getServer{})
	_, err = none.GetOnce(context.Background(), []string{memory, interfaces})
	require.Error(t, err, "a target that answers nothing is a failure, not an empty snapshot")
}

// Subscribe answers with the sync response that closes a stream's initial dump
// and then holds the stream open, the way a target behaves toward a
// subscription it carries nothing under yet.
func (g *getServer) Subscribe(stream gnmiproto.GNMI_SubscribeServer) error {
	if _, err := stream.Recv(); err != nil {
		return err
	}
	if err := stream.Send(&gnmiproto.SubscribeResponse{
		Response: &gnmiproto.SubscribeResponse_SyncResponse{SyncResponse: true},
	}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// A subscription is atomic on a strict target, so a path the target rejects is
// pruned and the stream that opens carries less than the request asked for. The
// sync response says which subscriptions it carries, because a caller
// reconciling against the dump must not withdraw a series under a path that
// never streamed.
func TestSubscribeManySyncNamesTheAcceptedPaths(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	s := getSession(t, &getServer{holds: map[string]bool{memory: true}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, _, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Mode: Sample, SampleIntervalMs: 1000},
		{Path: interfaces, Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)

	select {
	case n, ok := <-notes:
		require.True(t, ok, "the stream delivers its sync response")
		require.True(t, n.SyncDone, "the first notification is the sync response")
		assert.Equal(t, []string{memory}, n.Paths, "the sync names the subscriptions the stream carries, not the pruned one")
	case <-time.After(10 * time.Second):
		t.Fatal("no sync response from the stream")
	}
}

// A path probe is a Get, and it ran under the context the loop hands
// SubscribeMany, which lives as long as the policy does. A target that answers
// Capabilities and then never answers the Get held that probe for ever: no
// stream, no ladder, no reconnect, until the policy was deleted. Each probe
// carries a deadline of its own, and a path that misses it is pruned like one
// the target refused.
func TestASubscriptionPathProbeThatNeverAnswersIsPruned(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	addr := serveGet(t, &getServer{
		holds:  map[string]bool{memory: true, interfaces: true},
		blocks: map[string]bool{interfaces: true},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Dialed the way a target is, so the timeout travels the whole way: the
	// policy's spec, the session it dials, and the probe that session runs.
	s, err := (&GnmicDialer{}).Dial(ctx, TargetSpec{Host: addr, Insecure: true, ProbeTimeout: 100 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	type opened struct {
		notes <-chan Notification
		err   error
	}
	done := make(chan opened, 1)
	go func() {
		notes, _, err := s.SubscribeMany(ctx, []Subscription{
			{Path: memory, Mode: Sample, SampleIntervalMs: 1000},
			{Path: interfaces, Mode: Sample, SampleIntervalMs: 1000},
		})
		done <- opened{notes: notes, err: err}
	}()

	var got opened
	select {
	case got = <-done:
	case <-time.After(time.Second):
		t.Fatal("SubscribeMany never returned: a probe of a silent path is unbounded")
	}
	require.NoError(t, got.err)

	select {
	case n, ok := <-got.notes:
		require.True(t, ok, "the stream delivers its sync response")
		require.True(t, n.SyncDone, "the first notification is the sync response")
		assert.Equal(t, []string{memory}, n.Paths, "the path that never answered its probe is pruned, the one that did is kept")
	case <-time.After(10 * time.Second):
		t.Fatal("no sync response from the stream")
	}
}

// Capabilities opens every session, and it ran under the context the loop
// hands runOnce, which lives as long as the policy. A target that accepts the
// connection and then never answers held that loop for ever: no profile, no
// subscription, no error to back off from and no reconnect, until the policy
// was deleted. The call carries the session's probe deadline, and a target
// that misses it fails like any other.
func TestACapabilitiesCallThatNeverAnswersIsBounded(t *testing.T) {
	addr := serveGet(t, &getServer{capsBlocks: true})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Dialed the way a target is, so the timeout travels the whole way: the
	// policy's spec, the session it dials, and the call that session opens on.
	s, err := (&GnmicDialer{}).Dial(ctx, TargetSpec{Host: addr, Insecure: true, ProbeTimeout: 100 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	done := make(chan error, 1)
	go func() {
		_, capsErr := s.Capabilities(ctx)
		done <- capsErr
	}()

	select {
	case capsErr := <-done:
		require.Error(t, capsErr, "a target that never answers Capabilities fails the call, it does not succeed")
	case <-time.After(time.Second):
		t.Fatal("Capabilities never returned: a call to a silent target is unbounded")
	}
}

// A caller that bounded its own context keeps that bound. The sweep probes an
// address under a context of its own and reads whether that context ended the
// Capabilities call as the difference between a silent address and one that
// answered, since a peer may send DeadlineExceeded itself and the code alone
// says nothing. A deadline of the session's firing first left the sweep's
// context unexpired, and every silent address in a range under a policy whose
// probe timeout ran past the session's default was admitted as a device.
func TestACallerThatBoundedItsContextKeepsItsOwnDeadline(t *testing.T) {
	addr := serveGet(t, &getServer{capsBlocks: true})
	// Shorter than the caller's, so a session that applied its own deadline
	// regardless would be the one to end the call.
	s, err := (&GnmicDialer{}).Dial(context.Background(), TargetSpec{Host: addr, Insecure: true, ProbeTimeout: 50 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	type answered struct {
		capsErr   error
		callerErr error
	}
	done := make(chan answered, 1)
	go func() {
		_, capsErr := s.Capabilities(ctx)
		done <- answered{capsErr: capsErr, callerErr: ctx.Err()}
	}()

	select {
	case got := <-done:
		require.Error(t, got.capsErr, "a target that never answers Capabilities fails the call")
		assert.Error(t, got.callerErr, "the caller's own context is what ended the call, which is how a sweep tells silence from an answer")
	case <-time.After(time.Second):
		t.Fatal("Capabilities never returned: a call to a silent target is unbounded")
	}
}

// A spec that named no probe timeout takes the package default. Zero cannot be
// used as the deadline itself: a context with a zero timeout is already expired,
// which would prune every path of every subscription on sight.
func TestAProbeWithoutASpecTimeoutTakesThePackageDefault(t *testing.T) {
	assert.Equal(t, defaultProbeTimeout, (&gnmicSession{}).probeDeadline())
	assert.Equal(t, 250*time.Millisecond, (&gnmicSession{probeTimeout: 250 * time.Millisecond}).probeDeadline(),
		"a spec that named one is used as it stands")
}
