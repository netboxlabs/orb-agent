package gnmi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	s.streams = append(s.streams, streamHandle{cancel: func() {}, name: s.nextSubscriptionName()})
	s.StopSubscribe()
	assert.Empty(t, s.streams, "the stopped attempt's name is released with it")
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
	// delay is how long every answered request takes, which is how a target
	// that is slow but answers behaves.
	delay time.Duration
	// multiBlocks holds every request for more than one path and answers the
	// single-path ones, which is how a target that hangs on an aggregate
	// request and answers path by path behaves.
	multiBlocks bool
	// blocksFirst holds a path's first Get and answers every later one, which
	// is how a target that was busy under one subtree and then recovered
	// behaves.
	blocksFirst map[string]bool
	// rejects answers a path with the status the target sets on it, for a
	// refusal of a code other than the NotFound an unheld path gets.
	rejects map[string]codes.Code
	// encodings is what Capabilities advertises and what Get accepts: a target
	// that names its encodings refuses a request made in any other, which is
	// what makes asking for one it never named a failure rather than a detail.
	// Empty advertises none and accepts every request, as the servers that
	// care about something else do.
	encodings []gnmiproto.Encoding
	// inflight counts the Gets being answered right now, and maxInflight the
	// most there ever were at once, which is what shows a bounded fan-out.
	inflight, maxInflight atomic.Int32
	// mu guards gets, which the Get handler writes and a test reads.
	mu sync.Mutex
	// gets counts the requests made for each path, which is what tells a probe
	// the session ran again from a verdict it answered out of its cache.
	gets map[string]int
	// oneOriginPerRPC refuses a Subscribe request that mixes origins, the way
	// SR Linux does.
	oneOriginPerRPC bool
	// refuseOrigin refuses every Subscribe request under the origins it names.
	refuseOrigin map[string]bool
	// syncDelay holds back the sync response of a request under an origin.
	syncDelay map[string]time.Duration
	// pushAfterSync sends one update after the sync response under an origin,
	// the way a target with something under the path behaves.
	pushAfterSync map[string]bool
	// refuseAfter refuses a request under an origin once that long has
	// passed, so another stream has served something first.
	refuseAfter map[string]time.Duration
	// neverSync holds a request under an origin open without ever answering
	// its sync response, the way a target that accepted the RPC and then went
	// quiet behaves; with pushBeforeSync it first sends one update.
	neverSync      map[string]bool
	pushBeforeSync map[string]bool
	// endAfterSync ends a request under an origin with the given status once
	// it has answered its sync response and whatever pushAfterSync sends,
	// the way a target evicting a subscription it had accepted behaves.
	endAfterSync map[string]codes.Code
	// refuseAfterData refuses a request under an origin after it has sent one
	// update, the way a target that starts serving and then rejects behaves.
	refuseAfterData map[string]bool
	// subscribes is the origins each Subscribe request carried, in order.
	subscribes [][]string
	// streamsOpen counts the subscriptions the server is holding open.
	streamsOpen atomic.Int32
}

// countGet records one request for a path and reports how many there have been.
func (g *getServer) countGet(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gets == nil {
		g.gets = map[string]int{}
	}
	g.gets[path]++
	return g.gets[path]
}

// getsFor reports how many requests the server answered for one path.
func (g *getServer) getsFor(path string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.gets[path]
}

// Capabilities answers the RPC that opens every session, with the empty
// advertisement of a target that names no encoding, or holds it for ever when
// the server is told to.
func (g *getServer) Capabilities(ctx context.Context, _ *gnmiproto.CapabilityRequest) (*gnmiproto.CapabilityResponse, error) {
	if g.capsBlocks {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	return &gnmiproto.CapabilityResponse{SupportedEncodings: g.encodings}, nil
}

// advertises reports whether the target named this encoding, which is the only
// kind of request it answers.
func (g *getServer) advertises(enc gnmiproto.Encoding) bool {
	for _, e := range g.encodings {
		if e == enc {
			return true
		}
	}
	return false
}

func (g *getServer) Get(ctx context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
	cur := g.inflight.Add(1)
	defer g.inflight.Add(-1)
	for {
		m := g.maxInflight.Load()
		if cur <= m || g.maxInflight.CompareAndSwap(m, cur) {
			break
		}
	}
	if len(g.encodings) > 0 && !g.advertises(req.GetEncoding()) {
		return nil, status.Errorf(codes.InvalidArgument, "encoding %s was not advertised", req.GetEncoding())
	}
	if len(req.GetPath()) > 1 && !g.multi {
		return nil, status.Error(codes.Unimplemented, "one path per request")
	}
	if len(req.GetPath()) > 1 && g.multiBlocks {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	var notifications []*gnmiproto.Notification
	for _, p := range req.GetPath() {
		rendered := pathToString(p)
		asked := g.countGet(rendered)
		if code, ok := g.rejects[rendered]; ok {
			return nil, status.Errorf(code, "refused path %s", rendered)
		}
		if g.blocks[rendered] || (g.blocksFirst[rendered] && asked == 1) {
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		if !g.holds[rendered] {
			return nil, status.Errorf(codes.NotFound, "unknown path %s", rendered)
		}
		if g.delay > 0 {
			select {
			case <-time.After(g.delay):
			case <-ctx.Done():
				return nil, status.FromContextError(ctx.Err()).Err()
			}
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

// The per-path recovery runs the paths together: a path the target hangs on
// costs the others nothing, and the one that answers is fetched.
func TestGetOnceRecoversTheOtherPathsBesideAHangingOne(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	s := getSession(t, &getServer{holds: map[string]bool{interfaces: true}, blocks: map[string]bool{memory: true}})
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	n, err := s.GetOnce(ctx, []string{memory, interfaces})
	require.NoError(t, err, "the path beside the hanging one is fetched")
	assert.Equal(t, []string{interfaces}, n.Paths)
}

// The recovery Gets run concurrently under the whole remaining deadline, not
// one after another on shares of it: four paths a slow target answers in a
// hundred and fifty milliseconds each are all fetched inside four hundred,
// where sequential shares of a hundred would have timed every one out.
func TestGetOnceRecoversPathsConcurrently(t *testing.T) {
	paths := []string{"/system/memory/state", "/system/cpus/cpu[index=*]/state", "/interfaces/interface[name=*]/state/counters", "/system/state/hostname"}
	holds := map[string]bool{}
	for _, p := range paths {
		holds[p] = true
	}
	s := getSession(t, &getServer{holds: holds, delay: 150 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	n, err := s.GetOnce(ctx, paths)
	require.NoError(t, err)
	assert.Equal(t, paths, n.Paths, "every path is fetched, in the order asked")
	assert.Len(t, n.Updates, len(paths))
}

// A bracket or a backslash in a key value is escaped in the rendered path, so
// the matcher reads it as part of the value and not as a key delimiter.
func TestPathToStringEscapesDelimitersInKeyValues(t *testing.T) {
	p := &gnmiproto.Path{Elem: []*gnmiproto.PathElem{
		{Name: "interfaces"},
		{Name: "interface", Key: map[string]string{"name": `a]/b[c\d`}},
		{Name: "state"},
	}}
	assert.Equal(t, `/interfaces/interface[name=a\]/b\[c\\d]/state`, pathToString(p))
}

// The per-path recovery runs with a live deadline: the whole request takes
// half of what the caller left, so a target that hangs on the aggregate request
// and answers path by path is collected instead of failing every recovery on a
// spent context.
func TestGetOnceKeepsTimeForThePerPathRecovery(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	s := getSession(t, &getServer{holds: map[string]bool{memory: true, interfaces: true}, multi: true, multiBlocks: true})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	n, err := s.GetOnce(ctx, []string{memory, interfaces})
	require.NoError(t, err, "the paths answer one at a time within the half of the deadline the whole request left")
	assert.Equal(t, []string{memory, interfaces}, n.Paths)
	assert.Len(t, n.Updates, 2)
}

// Subscribe answers with the sync response that closes a stream's initial dump
// and then holds the stream open, the way a target behaves toward a
// subscription it carries nothing under yet. With oneOriginPerRPC it refuses a
// request whose subscriptions carry more than one origin, the way SR Linux
// does; refuseOrigin refuses a request under that origin outright; syncDelay
// holds an origin's sync response back, so two streams sync apart.
func (g *getServer) Subscribe(stream gnmiproto.GNMI_SubscribeServer) error {
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	origins := map[string]bool{}
	for _, sub := range req.GetSubscribe().GetSubscription() {
		origins[sub.GetPath().GetOrigin()] = true
	}
	g.recordSubscribe(origins)
	if g.oneOriginPerRPC && len(origins) > 1 {
		return status.Error(codes.Unimplemented, "Mixing of different origins is not supported for Subscribe RPC")
	}
	update := func(origin string) error {
		return stream.Send(&gnmiproto.SubscribeResponse{
			Response: &gnmiproto.SubscribeResponse_Update{Update: &gnmiproto.Notification{
				Update: []*gnmiproto.Update{{
					Path: &gnmiproto.Path{Origin: origin, Elem: []*gnmiproto.PathElem{{Name: "system"}, {Name: "state"}, {Name: "uptime"}}},
					Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_UintVal{UintVal: 1}},
				}},
			}},
		})
	}
	for origin := range origins {
		if d := g.refuseAfter[origin]; d > 0 {
			select {
			case <-time.After(d):
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
			return status.Errorf(codes.Unimplemented, "origin %q is not served", origin)
		}
		if g.refuseOrigin != nil && g.refuseOrigin[origin] {
			return status.Errorf(codes.Unimplemented, "origin %q is not served", origin)
		}
		if g.refuseAfterData[origin] {
			if err := update(origin); err != nil {
				return err
			}
			return status.Errorf(codes.Unimplemented, "origin %q rejected after serving", origin)
		}
		if g.neverSync[origin] {
			if g.pushBeforeSync[origin] {
				if err := update(origin); err != nil {
					return err
				}
			}
			g.streamsOpen.Add(1)
			defer g.streamsOpen.Add(-1)
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		if d := g.syncDelay[origin]; d > 0 {
			select {
			case <-time.After(d):
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}
	}
	if err := stream.Send(&gnmiproto.SubscribeResponse{
		Response: &gnmiproto.SubscribeResponse_SyncResponse{SyncResponse: true},
	}); err != nil {
		return err
	}
	for origin := range origins {
		if g.pushAfterSync[origin] {
			if err := update(origin); err != nil {
				return err
			}
		}
		if code, ok := g.endAfterSync[origin]; ok {
			return status.Errorf(code, "origin %q ended", origin)
		}
	}
	g.streamsOpen.Add(1)
	defer g.streamsOpen.Add(-1)
	<-stream.Context().Done()
	return stream.Context().Err()
}

// recordSubscribe notes one Subscribe RPC and the origins its request carried.
func (g *getServer) recordSubscribe(origins map[string]bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var list []string
	for o := range origins {
		list = append(list, o)
	}
	sort.Strings(list)
	g.subscribes = append(g.subscribes, list)
}

// subscribeRequests is the origins of every Subscribe RPC the server answered,
// in the order they arrived.
func (g *getServer) subscribeRequests() [][]string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([][]string(nil), g.subscribes...)
}

// syncPaths is the paths a stream's sync response names, which is the
// subscriptions the target ended up carrying.
func syncPaths(t *testing.T, notes <-chan Notification) []string {
	t.Helper()
	select {
	case n, ok := <-notes:
		require.True(t, ok, "the stream delivers its sync response")
		require.True(t, n.SyncDone, "the first notification is the sync response")
		return n.Paths
	case <-time.After(10 * time.Second):
		t.Fatal("no sync response from the stream")
		return nil
	}
}

// A subscription is atomic on a strict target, so a path the target rejects is
// pruned and the stream that opens carries less than the request asked for. The
// sync response says which subscriptions it carries, because a caller
// reconciling against the dump must not withdraw a series under a path that
// never streamed.
func TestSubscribeManySyncNamesTheAcceptedPaths(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	s := getSession(t, &getServer{
		holds:   map[string]bool{memory: true},
		rejects: map[string]codes.Code{interfaces: codes.InvalidArgument},
	})
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
// carries a deadline of its own, and a path that misses it still goes into the
// subscription: the probe asked and got no answer, so it is the stream that
// decides. A target that truly does not model the path rejects it there, which
// the ladder and the reconnect handle; one that was merely slow serves it,
// where dropping it left a healthy partial stream never asking again.
// One deadline bounds the whole probe phase: twenty paths a target never
// answers are all probed inside one probe deadline, not one per batch of the
// pool, and every path is kept since no probe reached a verdict.
func TestTheProbePhaseRunsUnderOneDeadline(t *testing.T) {
	holds, blocks := map[string]bool{}, map[string]bool{}
	var subs []Subscription
	for i := 0; i < 20; i++ {
		p := fmt.Sprintf("/system/cpus/cpu[index=%d]/state", i)
		holds[p], blocks[p] = true, true
		subs = append(subs, Subscription{Path: p, Mode: OnChange})
	}
	s := getSession(t, &getServer{holds: holds, blocks: blocks})
	s.probeTimeout = 300 * time.Millisecond
	start := time.Now()
	kept := s.acceptedSubscriptions(context.Background(), subs)
	elapsed := time.Since(start)
	assert.Len(t, kept, 20, "no verdict prunes nothing")
	assert.Less(t, elapsed, 700*time.Millisecond, "the phase took one deadline, not one per batch")
}

// The fan-out is bounded: twenty paths are probed, and recovered, from at
// most eight Gets in flight at once, so a large profile never
// opens one RPC per path against a device.
func TestGetFanOutIsBounded(t *testing.T) {
	holds := map[string]bool{}
	var paths []string
	var subs []Subscription
	for i := 0; i < 20; i++ {
		p := fmt.Sprintf("/system/cpus/cpu[index=%d]/state", i)
		holds[p] = true
		paths = append(paths, p)
		subs = append(subs, Subscription{Path: p, Mode: OnChange})
	}
	srv := &getServer{holds: holds, delay: 30 * time.Millisecond}
	s := getSession(t, srv)
	s.probeTimeout = 5 * time.Second
	kept := s.acceptedSubscriptions(context.Background(), subs)
	assert.Len(t, kept, 20)
	assert.LessOrEqual(t, srv.maxInflight.Load(), int32(8), "the probes are bounded")
	srv.maxInflight.Store(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	n, err := s.GetOnce(ctx, paths)
	require.NoError(t, err)
	assert.Equal(t, paths, n.Paths)
	assert.LessOrEqual(t, srv.maxInflight.Load(), int32(8), "the recovery is bounded")
}

// The subscription probes run together: four paths a slow target answers in
// a hundred and fifty milliseconds each are probed inside one such wait, not
// four, so a target that hangs on Get costs one deadline per connection
// rather than one per path.
func TestSubscriptionProbesRunConcurrently(t *testing.T) {
	paths := []string{"/system/memory/state", "/system/cpus/cpu[index=*]/state", "/interfaces/interface[name=*]/state/counters", "/system/state/hostname"}
	holds := map[string]bool{}
	subs := make([]Subscription, 0, len(paths))
	for _, p := range paths {
		holds[p] = true
		subs = append(subs, Subscription{Path: p, Mode: OnChange})
	}
	s := getSession(t, &getServer{holds: holds, delay: 150 * time.Millisecond})
	s.probeTimeout = time.Second
	start := time.Now()
	kept := s.acceptedSubscriptions(context.Background(), subs)
	elapsed := time.Since(start)
	assert.Len(t, kept, len(paths), "every path is accepted")
	assert.Less(t, elapsed, 450*time.Millisecond, "the probes ran together, not one after another")
}

func TestASubscriptionPathProbeThatNeverAnswersKeepsThePath(t *testing.T) {
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
		assert.Equal(t, []string{memory, interfaces}, n.Paths, "the path whose probe never answered is carried anyway, and the stream is what would reject it")
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
	assert.Equal(t, DefaultProbeTimeout, (&gnmicSession{}).probeDeadline())
	assert.Equal(t, 250*time.Millisecond, (&gnmicSession{probeTimeout: 250 * time.Millisecond}).probeDeadline(),
		"a spec that named one is used as it stands")
}

// A probe that never reached a verdict is not one. The session remembers what
// each path probe found so a rung change does not probe them all again, but a
// probe that timed out, or found the target unavailable, says nothing about the
// path it asked for: remembering that pruned the path for the life of the
// session, and a stream that stayed up never carried it again. Only the codes a
// target refuses a path under are a verdict worth keeping, and only such a
// refusal takes the path out of the subscription; an inconclusive probe leaves
// it in and probes it again next time.
func TestOnlyADefinitiveProbeRejectionIsRemembered(t *testing.T) {
	const memory, busy, refused = "/system/memory/state", "/components/component[name=*]/state", "/interfaces/interface[name=*]/state/counters"
	// A path the target models and holds nothing under yet, which is what a
	// list with no entries in it looks like: the Get finds nothing there and
	// answers NotFound, and the subscription over it is accepted all the same.
	const empty = "/network-instances/network-instance[name=*]/state"
	srv := &getServer{
		holds:       map[string]bool{memory: true, busy: true},
		blocksFirst: map[string]bool{busy: true},
		rejects:     map[string]codes.Code{refused: codes.InvalidArgument},
	}
	addr := serveGet(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s, err := (&GnmicDialer{}).Dial(ctx, TargetSpec{Host: addr, Insecure: true, ProbeTimeout: 100 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	subs := []Subscription{
		{Path: memory, Mode: Sample, SampleIntervalMs: 1000},
		{Path: busy, Mode: Sample, SampleIntervalMs: 1000},
		{Path: empty, Mode: Sample, SampleIntervalMs: 1000},
		{Path: refused, Mode: Sample, SampleIntervalMs: 1000},
	}
	notes, _, err := s.SubscribeMany(ctx, subs)
	require.NoError(t, err)
	assert.Equal(t, []string{memory, busy, empty}, syncPaths(t, notes),
		"the busy path missed its probe deadline and the empty one holds nothing yet, and both are carried anyway; only the refused one was turned down")

	// A rung change subscribes again on the same session, which is where a
	// verdict remembered from the attempt before it is spent.
	notes, _, err = s.SubscribeMany(ctx, subs)
	require.NoError(t, err)
	assert.Equal(t, []string{memory, busy, empty}, syncPaths(t, notes),
		"the path whose probe reached no verdict is probed again and carried, and so is the one that holds nothing yet")
	assert.Equal(t, 1, srv.getsFor(memory), "a path the target answered is remembered, not probed again")
	assert.Equal(t, 2, srv.getsFor(busy), "a probe that reached no verdict leaves nothing to answer from")
	assert.Equal(t, 2, srv.getsFor(empty), "a path that holds nothing yet is no verdict either, so it is asked again")
	assert.Equal(t, 1, srv.getsFor(refused), "a path the target refused is remembered")
}

// A Get is made in an encoding the target advertised. Asking a target that
// named PROTO alone for JSON_IETF is a request it refuses, so every path probe
// and the Get rung itself fail on it: a device that cannot stream reconnects
// for ever rather than settling into a poll. JSON_IETF stays the preference
// where it is offered, JSON next, and PROTO only when neither is, since the
// first two carry a leaf's value unambiguously across targets.
func TestTheGetEncodingIsOneTheTargetAdvertised(t *testing.T) {
	for name, tc := range map[string]struct {
		advertised []string
		want       string
	}{
		"json_ietf and proto": {advertised: []string{"JSON_IETF", "PROTO"}, want: "json_ietf"},
		"proto only":          {advertised: []string{"PROTO"}, want: "proto"},
		"json only":           {advertised: []string{"JSON"}, want: "json"},
		"proto ahead of json": {advertised: []string{"PROTO", "JSON"}, want: "json"},
		"nothing usable":      {advertised: []string{"ASCII"}, want: "json_ietf"},
		"none at all":         {advertised: nil, want: "json_ietf"},
	} {
		assert.Equal(t, tc.want, negotiateEncoding(tc.advertised), name)
	}
}

// The poll a PROTO-only target answers. Capabilities negotiates the encoding
// every later Get is made in, and a target that named PROTO alone turns down a
// request in any other, which left such a device with no probe that could
// succeed and no Get rung to fall to. A PROTO scalar reaches the caller as the
// number the device sent, the same way one off a stream does.
func TestAPROTOOnlyTargetAnswersItsGet(t *testing.T) {
	const memory = "/system/memory/state"
	s := getSession(t, &getServer{
		holds:     map[string]bool{memory: true},
		encodings: []gnmiproto.Encoding{gnmiproto.Encoding_PROTO},
	})

	caps, err := s.Capabilities(context.Background())
	require.NoError(t, err)
	require.Equal(t, []string{"PROTO"}, caps.Encodings, "the target names PROTO and nothing else")

	n, err := s.GetOnce(context.Background(), []string{memory})
	require.NoError(t, err, "a PROTO-only target answers a Get made in PROTO")
	assert.Equal(t, []string{memory}, n.Paths)
	require.Len(t, n.Updates, 1)
	assert.Equal(t, memory, n.Updates[0].Path)
	assert.Equal(t, uint64(1), n.Updates[0].Value, "a PROTO scalar decodes to the number the target sent")
}

// The vendor mapping knows a handful of organizations and derives nothing from
// any other, so a device of an unlisted vendor reports its name and the result
// carries no vendor at all. Keeping the organizations it reported is what
// leaves a profile written for that vendor something to be selected by.
// A vendor or NOS token is a whole word of the organization, never a substring
// of one: the canonical vendor outranks the reported organizations in profile
// selection, so a substring match would hand a device to the wrong overlay.
func TestCapabilitiesMatchesVendorTokensAsWholeWords(t *testing.T) {
	got := mapCapabilities(&gnmiproto.CapabilityResponse{SupportedModels: []*gnmiproto.ModelData{
		{Name: "acme-interfaces", Organization: "Francisco Networks"},
		{Name: "acme-system", Organization: "Supersonic Labs"},
	}})
	assert.Empty(t, got.Vendor, "cisco inside Francisco is not the vendor")
	assert.Empty(t, got.NOS, "sonic inside Supersonic is not the network OS")

	got = mapCapabilities(&gnmiproto.CapabilityResponse{SupportedModels: []*gnmiproto.ModelData{
		{Name: "vendor-interfaces", Organization: "Cisco Systems, Inc."},
		{Name: "sonic-system", Organization: "SONiC"},
	}})
	assert.Equal(t, "Cisco", got.Vendor, "the token as a word of the organization")
	assert.Equal(t, "SONiC", got.NOS, "the token as the whole organization")
}

func TestCapabilitiesKeepsTheOrganizationsTheTargetReported(t *testing.T) {
	resp := &gnmiproto.CapabilityResponse{SupportedModels: []*gnmiproto.ModelData{
		{Name: "acme-interfaces", Organization: " Acme Networks, Inc. "},
		{Name: "acme-system", Organization: "Acme Networks, Inc."},
		{Name: "openconfig-interfaces", Organization: "OpenConfig working group"},
	}}
	got := mapCapabilities(resp)
	assert.Empty(t, got.Vendor, "an organization the mapping does not know sets no vendor")
	assert.Equal(t, []string{"Acme Networks, Inc.", "OpenConfig working group"}, got.Organizations,
		"every organization is kept as the target wrote it, trimmed, in order and once")
}

// A target takes one origin per Subscribe RPC: SR Linux refuses a request that
// mixes the OpenConfig paths with a native one. The subscriptions of an
// attempt are grouped by origin and each group streams on its own RPC, and
// the attempt still delivers one sync response, once every stream has
// answered its own, naming every path they carry between them.
func TestSubscribeManyOpensOneStreamPerOrigin(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		syncDelay:       map[string]time.Duration{"openconfig": 300 * time.Millisecond},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)

	select {
	case n, ok := <-notes:
		require.True(t, ok, "the attempt delivers its sync response")
		require.True(t, n.SyncDone, "the first notification is the sync response")
		assert.ElementsMatch(t, []string{memory, native}, n.Paths, "the sync names the paths of every stream")
	case err := <-errs:
		t.Fatalf("the attempt failed: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no sync response from the attempt")
	}
	select {
	case n := <-notes:
		t.Fatalf("a second sync was delivered: %+v", n)
	case <-time.After(200 * time.Millisecond):
	}
	assert.Equal(t, [][]string{{""}, {"openconfig"}}, sortedRequests(srv.subscribeRequests()),
		"each origin went on a request of its own")
	assert.Len(t, s.streams, 2, "the session holds one stream per origin")
}

// sortedRequests orders recorded Subscribe requests so a test can compare
// them without depending on which stream the target answered first.
func sortedRequests(reqs [][]string) [][]string {
	out := append([][]string(nil), reqs...)
	sort.Slice(out, func(i, j int) bool { return strings.Join(out[i], ",") < strings.Join(out[j], ",") })
	return out
}

// Subscriptions under one origin still go on one request, as before.
func TestSubscribeManyKeepsOneOriginOnOneStream(t *testing.T) {
	const memory, interfaces = "/system/memory/state", "/interfaces/interface[name=*]/state/counters"
	srv := &getServer{holds: map[string]bool{memory: true, interfaces: true}, oneOriginPerRPC: true}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, _, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: interfaces, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{memory, interfaces}, syncPaths(t, notes))
	assert.Equal(t, [][]string{{"openconfig"}}, srv.subscribeRequests(), "one origin, one request")
	assert.Len(t, s.streams, 1)
}

// The attempt is atomic across its streams: a target that refuses one origin
// has refused the attempt, so its error is the attempt's, the other stream is
// torn down rather than left serving half a profile, and the channels close.
func TestSubscribeManyEndsTheAttemptWhenOneStreamFails(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		refuseOrigin:    map[string]bool{"": true},
		syncDelay:       map[string]time.Duration{"openconfig": 100 * time.Millisecond},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err, "the refusal is reported on the stream, not on the call")

	refusal := func(err error) {
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not served", "the refusing stream's error is the attempt's")
	}
	select {
	case err := <-errs:
		refusal(err)
	case n, ok := <-notes:
		if ok {
			t.Fatalf("a notification arrived before the refusal: %+v", n)
		}
		// The channels closed first: the error was queued before they did.
		refusal(<-errs)
	case <-time.After(10 * time.Second):
		t.Fatal("the refusal never reached the caller")
	}
	select {
	case _, ok := <-notes:
		assert.False(t, ok, "the notification channel closes with the attempt")
	case <-time.After(10 * time.Second):
		t.Fatal("the notification channel stayed open")
	}
	assert.Eventually(t, func() bool { return srv.streamsOpen.Load() == 0 }, 10*time.Second, 20*time.Millisecond,
		"the surviving stream is torn down with the attempt")
}

// StopSubscribe closes every stream of the attempt on the target and releases
// every handle.
func TestStopSubscribeClosesEveryStreamOnTheTarget(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{holds: map[string]bool{memory: true, native: true}, oneOriginPerRPC: true}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, _, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)
	syncPaths(t, notes)
	require.Eventually(t, func() bool { return srv.streamsOpen.Load() == 2 }, 10*time.Second, 20*time.Millisecond)

	s.StopSubscribe()
	assert.Empty(t, s.streams, "every registered stream is released")
	assert.Eventually(t, func() bool { return srv.streamsOpen.Load() == 0 }, 10*time.Second, 20*time.Millisecond,
		"both streams are closed on the target")
	assert.NotPanics(t, s.StopSubscribe, "stopping again is a no-op")
}

// A caller that stops reading leaves the attempt's forwarders waiting to
// deliver; StopSubscribe and Close release them along with the streams, so
// nothing is left behind.
func TestStopSubscribeAndCloseReleaseForwardersNobodyIsReading(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	for name, release := range map[string]func(*gnmicSession){
		"StopSubscribe": func(s *gnmicSession) { s.StopSubscribe() },
		"Close":         func(s *gnmicSession) { _ = s.Close() },
	} {
		t.Run(name, func(t *testing.T) {
			srv := &getServer{
				holds:           map[string]bool{memory: true, native: true},
				oneOriginPerRPC: true,
				pushAfterSync:   map[string]bool{"openconfig": true, "": true},
			}
			s := getSession(t, srv)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// The count is process-wide: start from a quiet baseline so an
			// earlier test's attempt still unwinding is not read as ours.
			require.Eventually(t, func() bool { return attemptGoroutines() == 0 }, 10*time.Second, 50*time.Millisecond)

			_, _, err := s.SubscribeMany(ctx, []Subscription{
				{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
				{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
			})
			require.NoError(t, err)
			require.Eventually(t, func() bool { return srv.streamsOpen.Load() == 2 }, 10*time.Second, 20*time.Millisecond)
			// Nobody reads the attempt's channel: the sync and the pushed
			// updates are waiting to be delivered.
			time.Sleep(200 * time.Millisecond)
			require.Greater(t, attemptGoroutines(), 0, "the attempt runs forwarders of its own")

			release(s)
			// Closure of the channel cannot be observed without receiving, and
			// receiving is what would release a stuck forwarder, so watch the
			// goroutines the attempt started go away instead.
			assert.Eventually(t, func() bool { return attemptGoroutines() == 0 }, 10*time.Second, 50*time.Millisecond,
				"a forwarder is still waiting to deliver after %s", name)
		})
	}
}

// attemptGoroutines counts the goroutines SubscribeMany started for an
// attempt: the forwarders merging its streams and the one closing its
// channels behind them.
func attemptGoroutines() int {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return strings.Count(string(buf[:n]), "(*gnmicSession).SubscribeMany.func")
		}
		buf = make([]byte, 2*len(buf))
	}
}

// A stream that rejects before it has served anything has refused the
// attempt's mode, whatever another stream delivered meanwhile. The consumer
// reads a refusal from how much it has seen, which across streams it cannot
// tell, so the error says it: it is marked as coming before that stream's
// data, with the target's code kept for the consumer to read.
func TestAStreamRefusingBeforeItsDataIsMarkedSo(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		pushAfterSync:   map[string]bool{"openconfig": true},
		refuseAfter:     map[string]time.Duration{"": 300 * time.Millisecond},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)

	var data int
	deadline := time.After(10 * time.Second)
	for {
		select {
		case n, ok := <-notes:
			if ok && !n.SyncDone {
				data++
			}
			if !ok {
				notes = nil
			}
		case err := <-errs:
			require.Error(t, err)
			assert.Greater(t, data, 0, "the other stream served data before the refusal")
			assert.True(t, errors.Is(err, ErrBeforeData), "the refusal is marked as before the stream's data: %v", err)
			assert.Equal(t, codes.Unimplemented, status.Code(err), "the target's code is kept for the consumer to read")
			return
		case <-deadline:
			t.Fatal("the refusal never reached the caller")
		}
	}
}

// A stream that answers neither data nor its sync within the probe deadline
// ends the attempt, as the consumer's own dump deadline would have, which the
// swallowed per-stream syncs and another stream's data keep it from seeing.
// One that served nothing at all is reported as silent, the refusal the
// ladder advances through; one that served data and then stalled is a plain
// failure the same rung reconnects through.
func TestAStreamThatNeverSyncsEndsTheAttempt(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	for name, tc := range map[string]struct {
		pushBeforeSync bool
		silent         bool
	}{
		"silent":  {pushBeforeSync: false, silent: true},
		"stalled": {pushBeforeSync: true, silent: false},
	} {
		t.Run(name, func(t *testing.T) {
			srv := &getServer{
				holds:           map[string]bool{memory: true, native: true},
				oneOriginPerRPC: true,
				pushAfterSync:   map[string]bool{"openconfig": true},
				neverSync:       map[string]bool{"": true},
				pushBeforeSync:  map[string]bool{"": tc.pushBeforeSync},
			}
			s := getSession(t, srv)
			s.probeTimeout = 300 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			notes, errs, err := s.SubscribeMany(ctx, []Subscription{
				{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
				{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
			})
			require.NoError(t, err)

			deadline := time.After(5 * time.Second)
			for {
				select {
				case n, ok := <-notes:
					if ok {
						assert.False(t, n.SyncDone, "no sync while a stream has not answered its own")
					} else {
						notes = nil
					}
				case err := <-errs:
					require.Error(t, err)
					assert.Equal(t, tc.silent, errors.Is(err, ErrStreamSilent), "silence is reported as such and a stall is not: %v", err)
					assert.Eventually(t, func() bool { return srv.streamsOpen.Load() == 0 }, 10*time.Second, 20*time.Millisecond,
						"the attempt is torn down")
					return
				case <-deadline:
					t.Fatal("the attempt outlived the probe deadline with a stream that never synced")
				}
			}
		})
	}
}

// A stream the target ends after answering its sync is a stream closing, not
// a silent one: the target accepted the subscription, and the same rung
// reconnects through the close, as the consumer does for a single stream
// that closes after its sync. gnmic reports a Canceled end as a bare close.
func TestAStreamEndedAfterItsSyncIsNotSilent(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		pushAfterSync:   map[string]bool{"openconfig": true},
		syncDelay:       map[string]time.Duration{"": 200 * time.Millisecond},
		endAfterSync:    map[string]codes.Code{"": codes.Canceled},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)

	assertOrdinaryClose(t, notes, errs)
}

// assertOrdinaryClose reads an attempt to its end and requires that it ended
// with an error that is neither silence nor a mode rejection: a stream the
// target ended after accepting it reconnects on the same rung, and the
// consumer reads that from the error, since a bare close would be judged
// from its own view of the attempt, which never saw the swallowed sync.
func assertOrdinaryClose(t *testing.T, notes <-chan Notification, errs <-chan error) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-notes:
			if !ok {
				notes = nil
			}
		case err, ok := <-errs:
			if !ok {
				t.Fatal("the attempt ended with no error at all: the consumer would judge the close from its own view")
			}
			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrStreamSilent), "a stream that synced is not silent: %v", err)
			assert.Equal(t, codes.Unknown, status.Code(err), "the close carries no code a consumer reads as a refusal: %v", err)
			return
		case <-deadline:
			t.Fatal("the attempt never ended")
		}
	}
}

// The same close when the ending stream synced first and the other is still
// in its dump: the combined sync never went out, so the consumer has seen
// nothing, and a bare close would be judged a refusal from that nothing.
func TestAStreamEndedAfterItsSyncBeforeTheOthersIsNotSilent(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		syncDelay:       map[string]time.Duration{"openconfig": 400 * time.Millisecond},
		endAfterSync:    map[string]codes.Code{"": codes.Canceled},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)
	assertOrdinaryClose(t, notes, errs)
}

// An error a stream reports after it has served data is marked as after it,
// not before: the target accepted the mode and served it, so the same rung
// reconnects through the failure, and the consumer reads that from the mark
// rather than from what reached it, since the notification in flight when
// the attempt ends may never arrive.
func TestAStreamRefusingAfterItsDataIsMarkedAfter(t *testing.T) {
	const memory, native = "/system/memory/state", "/platform/control[slot=*]/memory"
	srv := &getServer{
		holds:           map[string]bool{memory: true, native: true},
		oneOriginPerRPC: true,
		refuseAfterData: map[string]bool{"": true},
	}
	s := getSession(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	notes, errs, err := s.SubscribeMany(ctx, []Subscription{
		{Path: memory, Origin: "openconfig", Mode: Sample, SampleIntervalMs: 1000},
		{Path: native, Origin: "", Mode: Sample, SampleIntervalMs: 1000},
	})
	require.NoError(t, err)

	deadline := time.After(10 * time.Second)
	for {
		select {
		case _, ok := <-notes:
			if !ok {
				notes = nil
			}
		case err := <-errs:
			require.Error(t, err)
			assert.False(t, errors.Is(err, ErrBeforeData), "the stream served before it was refused: %v", err)
			assert.True(t, errors.Is(err, ErrAfterData), "the refusal is marked as after the stream's data: %v", err)
			assert.Equal(t, codes.Unimplemented, status.Code(err), "the target's code is kept")
			return
		case <-deadline:
			t.Fatal("the refusal never reached the caller")
		}
	}
}
