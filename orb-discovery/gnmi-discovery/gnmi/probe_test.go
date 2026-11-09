package gnmi

import (
	"cmp"
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/tap"
)

const (
	probeHostname = "/system/state/hostname"
	probeMTU      = "/interfaces/interface[name=*]/state/mtu"
	probeSerial   = "/components/component[name=*]/state/serial-no"
)

var probePaths = []string{probeHostname, probeMTU, probeSerial}

// probeTarget answers Get per path through getErr, and records the paths of
// every Subscribe; subErr refuses a subscription by its paths.
//
// It numbers the Subscribe streams as the server reads them, which on one
// connection is the order the client opened them: their handlers run
// concurrently, so one can record its paths after a later stream's. gnmic,
// whose retry timer is 0, can send a refused subscription again at once, and
// the session can retry without a path before that resend is recorded.
type probeTarget struct {
	srv    *testGNMIServer
	addr   string
	getErr func(path string) error
	subErr func(paths []string) error
	// failAfterData ends each stream with this error once its data is sent.
	failAfterData error
	// beforeRecord, when set, runs before a subscription is recorded.
	beforeRecord func(paths []string)
	gets         atomic.Int32
	opened       atomic.Int32 // Subscribe streams the server has read

	mu         sync.Mutex
	subReqs    []subscription
	sampleReqs [][]string // the SAMPLE subscriptions among subReqs
}

// subscription is the paths of the Subscribe on stream n.
type subscription struct {
	n     int32
	paths []string
}

// streamNumber keys a Subscribe stream's number in its context.
type streamNumber struct{}

func newProbeTarget(t *testing.T) (*probeTarget, Session) {
	t.Helper()
	pt := &probeTarget{srv: &testGNMIServer{}}
	pt.srv.getHandler = func(_ context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
		pt.gets.Add(1)
		for _, p := range req.GetPath() {
			if pt.getErr != nil {
				if err := pt.getErr(pathToString(p)); err != nil {
					return nil, err
				}
			}
		}
		return &gnmiproto.GetResponse{}, nil
	}
	pt.srv.subscribeHandler = func(stream gnmiproto.GNMI_SubscribeServer) error {
		req, err := stream.Recv()
		if err != nil {
			return err
		}
		n, ok := stream.Context().Value(streamNumber{}).(int32)
		if !ok {
			return status.Error(codes.Internal, "probe target: a Subscribe stream without a number")
		}
		var paths []string
		for _, s := range req.GetSubscribe().GetSubscription() {
			paths = append(paths, pathToString(s.GetPath()))
		}
		if pt.beforeRecord != nil {
			pt.beforeRecord(paths)
		}
		pt.mu.Lock()
		pt.subReqs = append(pt.subReqs, subscription{n: n, paths: paths})
		if subs := req.GetSubscribe().GetSubscription(); len(subs) > 0 && subs[0].GetMode() == gnmiproto.SubscriptionMode_SAMPLE {
			pt.sampleReqs = append(pt.sampleReqs, paths)
		}
		pt.mu.Unlock()
		if pt.subErr != nil {
			if err := pt.subErr(paths); err != nil {
				return err
			}
		}
		hostname, _ := hostnameJSONVal("sw1")
		if err := stream.Send(&gnmiproto.SubscribeResponse{Response: &gnmiproto.SubscribeResponse_Update{
			Update: &gnmiproto.Notification{Update: []*gnmiproto.Update{{
				Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: "system"}, {Name: "state"}, {Name: "hostname"}}},
				Val:  hostname,
			}}},
		}}); err != nil {
			return err
		}
		if err := stream.Send(&gnmiproto.SubscribeResponse{Response: &gnmiproto.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
			return err
		}
		if pt.failAfterData != nil {
			return pt.failAfterData
		}
		<-stream.Context().Done()
		return nil
	}
	// A tap runs as the server reads each new stream, in order.
	number := grpc.InTapHandle(func(ctx context.Context, info *tap.Info) (context.Context, error) {
		if info.FullMethodName != gnmiproto.GNMI_Subscribe_FullMethodName {
			return ctx, nil
		}
		return context.WithValue(ctx, streamNumber{}, pt.opened.Add(1)), nil
	})
	pt.addr = startTestGNMIServer(t, pt.srv, number)
	return pt, dialPlaintext(t, pt.addr)
}

// subscriptions is the paths of every Subscribe, in the order the client
// opened them.
func (pt *probeTarget) subscriptions() [][]string {
	return pt.subscriptionsAfter(0)
}

// subscriptionsAfter is the paths of the Subscribes opened after the first n
// streams, in the order the client opened them.
func (pt *probeTarget) subscriptionsAfter(n int32) [][]string {
	pt.mu.Lock()
	subs := slices.Clone(pt.subReqs)
	pt.mu.Unlock()
	slices.SortFunc(subs, func(a, b subscription) int { return cmp.Compare(a.n, b.n) })
	var out [][]string
	for _, s := range subs {
		if s.n > n {
			out = append(out, s.paths)
		}
	}
	return out
}

// lastSubscription is the paths of the latest Subscribe, sorted.
func (pt *probeTarget) lastSubscription(t *testing.T) []string {
	t.Helper()
	subs := pt.subscriptions()
	require.NotEmpty(t, subs)
	got := slices.Clone(subs[len(subs)-1])
	slices.Sort(got)
	return got
}

func sorted(paths ...string) []string {
	out := slices.Clone(paths)
	slices.Sort(out)
	return out
}

// The probe target reads its subscriptions in the order the client opened
// them, though a stream can be recorded after a later one.
func TestProbeTargetReadsSubscriptionsInTheOrderTheyWereOpened(t *testing.T) {
	pt, _ := newProbeTarget(t)
	held, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	free := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(free)
	var streams atomic.Int32
	pt.beforeRecord = func([]string) {
		if streams.Add(1) == 1 {
			close(held)
			<-release
		}
	}
	conn, err := grpc.NewClient(pt.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	subscribe := func(name string) gnmiproto.GNMI_SubscribeClient {
		stream, err := gnmiproto.NewGNMIClient(conn).Subscribe(ctx)
		require.NoError(t, err)
		require.NoError(t, stream.Send(&gnmiproto.SubscribeRequest{Request: &gnmiproto.SubscribeRequest_Subscribe{
			Subscribe: &gnmiproto.SubscriptionList{Subscription: []*gnmiproto.Subscription{
				{Path: &gnmiproto.Path{Elem: []*gnmiproto.PathElem{{Name: name}}}},
			}},
		}}))
		return stream
	}

	subscribe("first")
	select {
	case <-held:
	case <-ctx.Done():
		t.Fatal("the first stream never reached the target")
	}
	_, err = subscribe("second").Recv() // answered, so recorded
	require.NoError(t, err)
	free()
	require.Eventually(t, func() bool { return len(pt.subscriptions()) == 2 }, 5*time.Second, 10*time.Millisecond)

	assert.Equal(t, [][]string{{"/first"}, {"/second"}}, pt.subscriptions())
	assert.Equal(t, []string{"/second"}, pt.lastSubscription(t))
}

// subscribeAndRead subscribes and returns the first notification, failing on
// a stream error.
func subscribeAndRead(t *testing.T, sess Session) Notification {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	notes, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
	require.NoError(t, err)
	select {
	case n, ok := <-notes:
		require.True(t, ok, "stream closed before any data")
		return n
	case e := <-errs:
		t.Fatalf("stream failed: %v", e)
	case <-ctx.Done():
		t.Fatal("no data")
	}
	return Notification{}
}

// A probe that gets no answer keeps the paths and reports them, for the whole
// connection: the next Subscribe on the session does not probe again.
func TestProbeWithoutAnAnswerKeepsThePathsForTheConnection(t *testing.T) {
	pt, sess := newProbeTarget(t)
	var refusing atomic.Bool
	refusing.Store(true)
	pt.getErr = func(string) error {
		if refusing.Load() {
			return status.Error(codes.Unauthenticated, "AAA server timeout")
		}
		return nil
	}

	subscribeAndRead(t, sess)
	assert.Equal(t, sorted(probePaths...), pt.lastSubscription(t), "every path kept")
	assert.ElementsMatch(t, probePaths, sess.InconclusivePaths())

	refusing.Store(false)
	before := pt.gets.Load()
	subscribeAndRead(t, sess)
	assert.Equal(t, before, pt.gets.Load(), "the session did not probe again")
	assert.ElementsMatch(t, probePaths, sess.InconclusivePaths())
	assert.Equal(t, sorted(probePaths...), pt.lastSubscription(t))
}

// A login the target refuses is refused for every path alike, so the probe
// does not ask about each one.
func TestProbeSkipsThePerPathGetsWhenTheLoginIsRefused(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(string) error { return status.Error(codes.Unauthenticated, "bad credentials") }

	subscribeAndRead(t, sess)
	assert.EqualValues(t, 1, pt.gets.Load(), "only the multi-path Get")
	assert.ElementsMatch(t, probePaths, sess.InconclusivePaths())
	assert.Equal(t, sorted(probePaths...), pt.lastSubscription(t))
}

// PermissionDenied can be one path's: a device may authorize per path. The
// probe still asks about each, and prunes only the denied one.
func TestProbeStillAsksPerPathAfterAPermissionDenied(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeSerial {
			return status.Error(codes.PermissionDenied, "not authorized for this path")
		}
		return nil
	}

	subscribeAndRead(t, sess)
	assert.Equal(t, sorted(probeHostname, probeMTU), pt.lastSubscription(t))
}

// NotFound is a modelled path with nothing under it yet: it stays in the
// subscription, so what appears there later is streamed.
func TestProbeKeepsANotFoundPath(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeMTU {
			return status.Error(codes.NotFound, "no data")
		}
		return nil
	}

	subscribeAndRead(t, sess)
	assert.Equal(t, sorted(probePaths...), pt.lastSubscription(t))
	assert.Empty(t, sess.InconclusivePaths(), "a NotFound is an answer")
}

// A path the target refuses outright is pruned, as before.
func TestProbePrunesARefusedPath(t *testing.T) {
	for _, c := range []codes.Code{codes.InvalidArgument, codes.Unimplemented, codes.FailedPrecondition, codes.PermissionDenied, codes.Internal} {
		t.Run(c.String(), func(t *testing.T) {
			pt, sess := newProbeTarget(t)
			pt.getErr = func(p string) error {
				if p == probeMTU {
					return status.Error(c, "unsupported path")
				}
				return nil
			}

			subscribeAndRead(t, sess)
			assert.Equal(t, sorted(probeHostname, probeSerial), pt.lastSubscription(t))
			assert.EqualValues(t, 1+len(probePaths), pt.gets.Load(), "a refused path is not asked again")
		})
	}
}

// A kept path that makes the target refuse the subscription is pruned, and
// the subscription retried once without it.
func TestKeptPathRefusedBySubscribeIsPrunedAndRetried(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeMTU {
			return status.Error(codes.NotFound, "no data")
		}
		return nil
	}
	pt.subErr = func(paths []string) error {
		if slices.Contains(paths, probeMTU) {
			return status.Error(codes.InvalidArgument, "unknown path")
		}
		return nil
	}

	n := subscribeAndRead(t, sess)
	require.Len(t, n.Updates, 1)
	subs := pt.subscriptions()
	assert.True(t, slices.Contains(subs[0], probeMTU), "first attempt carried the kept path")
	assert.Equal(t, sorted(probeHostname, probeSerial), pt.lastSubscription(t), "the retry did not")

	// Pruned for the session: the next subscription goes without it at once.
	opened := pt.opened.Load()
	subscribeAndRead(t, sess)
	assert.Equal(t, sorted(probeHostname, probeSerial), pt.lastSubscription(t))
	for _, s := range pt.subscriptionsAfter(opened) {
		assert.NotContains(t, s, probeMTU)
	}
}

// A subscription refused with a transient code is not the kept path's doing:
// the error goes to the caller and nothing is retried or pruned.
func TestTransientSubscribeRefusalIsNotRetried(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeMTU {
			return status.Error(codes.NotFound, "no data")
		}
		return nil
	}
	pt.subErr = func([]string) error { return status.Error(codes.Unavailable, "busy") }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
	require.NoError(t, err)
	select {
	case e := <-errs:
		require.Equal(t, codes.Unavailable, status.Code(e))
	case <-ctx.Done():
		t.Fatal("no error")
	}
	for _, s := range pt.subscriptions() {
		assert.Contains(t, s, probeMTU, "no retry without the kept path")
	}
}

// The probe ends at its deadline, keeping what it could not ask about.
func TestProbeEndsAtItsDeadline(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.srv.getHandler = func(ctx context.Context, _ *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
		pt.gets.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	sess.(*gnmicSession).setupTimeout = 100 * time.Millisecond

	start := time.Now()
	subscribeAndRead(t, sess)
	assert.Less(t, time.Since(start), 2*time.Second)
	assert.Equal(t, sorted(probePaths...), pt.lastSubscription(t))
	assert.ElementsMatch(t, probePaths, sess.InconclusivePaths())
}

// A stream that served data and then failed was not refused for its paths:
// the error goes to the caller and the kept path stays.
func TestStreamFailingAfterDataIsNotRetried(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeMTU {
			return status.Error(codes.NotFound, "no data")
		}
		return nil
	}
	pt.failAfterData = status.Error(codes.InvalidArgument, "stream ended")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	notes, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
	require.NoError(t, err)
	var gotErr error
	for gotErr == nil {
		select {
		case <-notes:
		case e, ok := <-errs:
			require.True(t, ok, "stream closed without its error")
			gotErr = e
		case <-ctx.Done():
			t.Fatal("no error")
		}
	}
	require.Equal(t, codes.InvalidArgument, status.Code(gotErr))
	for _, s := range pt.subscriptions() {
		assert.Contains(t, s, probeMTU, "no retry without the kept path")
	}
}

// A subscription that follows a refused one on the same session is served:
// the refused attempt's teardown must not stop it. Looped, as the teardown
// races the next Subscribe.
func TestSubscribeAfterARefusedOneIsServed(t *testing.T) {
	for i := range 50 {
		pt, sess := newProbeTarget(t)
		var calls atomic.Int32
		pt.subErr = func([]string) error {
			if calls.Add(1) == 1 {
				return status.Error(codes.InvalidArgument, "on_change not supported")
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
		require.NoError(t, err)
		select {
		case e := <-errs:
			require.Equal(t, codes.InvalidArgument, status.Code(e), "iteration %d", i)
		case <-ctx.Done():
			t.Fatalf("iteration %d: no refusal", i)
		}
		notes, errs2, err := sess.Subscribe(ctx, Sample, probePaths, 100)
		require.NoError(t, err)
		select {
		case n, ok := <-notes:
			require.True(t, ok, "iteration %d: stream closed before any data", i)
			require.NotEmpty(t, n.Updates, "iteration %d", i)
		case e := <-errs2:
			t.Fatalf("iteration %d: stream failed: %v", i, e)
		case <-ctx.Done():
			t.Fatalf("iteration %d: no data", i)
		}
		cancel()
		_ = sess.Close()
	}
}

// Hung paths cannot hold the probe's workers until the deadline: each Get has
// its own, so a path queued behind them is still asked, and answered.
func TestProbeAsksEveryPathDespiteHungOnes(t *testing.T) {
	const answered = "/system/state/hostname"
	var paths []string
	for i := range 9 {
		paths = append(paths, fmt.Sprintf("/components/component[name=*]/state/leaf-%d", i))
	}
	paths = append(paths, answered) // probed last
	pt := &probeTarget{srv: &testGNMIServer{}}
	pt.srv.getHandler = func(ctx context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
		for _, p := range req.GetPath() {
			if pathToString(p) != answered {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return &gnmiproto.GetResponse{}, nil
	}
	addr := startTestGNMIServer(t, pt.srv)
	sess, err := (&GnmicDialer{}).Dial(context.Background(), TargetSpec{Host: addr, Insecure: true, SetupTimeout: 900 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })

	got := sess.(*gnmicSession).acceptedPaths(context.Background(), paths)
	assert.ElementsMatch(t, paths, got, "nothing refused, so nothing pruned")
	assert.NotContains(t, sess.InconclusivePaths(), answered)
	assert.Len(t, sess.InconclusivePaths(), 9)
}

// The retry drops only the paths the target answered NotFound for: never one
// whose probe got no answer, and never a pinned path such as the hostname.
func TestRetryDropsOnlyNotFoundPaths(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		switch p {
		case probeHostname, probeMTU:
			return status.Error(codes.NotFound, "no data")
		case probeSerial:
			return status.Error(codes.Unavailable, "busy")
		}
		return nil
	}
	pt.subErr = func(paths []string) error {
		if slices.Contains(paths, probeMTU) {
			return status.Error(codes.InvalidArgument, "unknown path")
		}
		return nil
	}
	sess.PinPaths(probeHostname)

	subscribeAndRead(t, sess)
	assert.Equal(t, sorted(probeHostname, probeSerial), pt.lastSubscription(t))
}

// When the retry is refused as well, the dropped paths were not the cause:
// they stay for the session, and the caller sees the original refusal.
func TestRetryRefusedTooRestoresThePaths(t *testing.T) {
	pt, sess := newProbeTarget(t)
	pt.getErr = func(p string) error {
		if p == probeMTU {
			return status.Error(codes.NotFound, "no data")
		}
		return nil
	}
	var calls atomic.Int32
	var refusing atomic.Bool
	refusing.Store(true)
	pt.subErr = func([]string) error {
		if !refusing.Load() {
			return nil
		}
		return status.Error(codes.InvalidArgument, fmt.Sprintf("on_change refused, call %d", calls.Add(1)))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
	require.NoError(t, err)
	select {
	case e := <-errs:
		require.Contains(t, e.Error(), "call 1", "the original refusal")
	case <-ctx.Done():
		t.Fatal("no error")
	}

	// gnmic may still send the refused subscription once more in the
	// background, so the next one is told apart by its mode.
	refusing.Store(false)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	notes, errs2, err := sess.Subscribe(ctx2, Sample, probePaths, 100)
	require.NoError(t, err)
	select {
	case <-notes:
	case e := <-errs2:
		t.Fatalf("stream failed: %v", e)
	case <-ctx2.Done():
		t.Fatal("no data")
	}
	pt.mu.Lock()
	defer pt.mu.Unlock()
	require.Len(t, pt.sampleReqs, 1)
	got := slices.Clone(pt.sampleReqs[0])
	slices.Sort(got)
	assert.Equal(t, sorted(probePaths...), got, "the NotFound path stays for the session")
}

// The retry is served every time: it waits for the refused attempt to wind
// down, whose teardown would otherwise stop it. Looped, as that teardown races
// the retry.
func TestRetryIsServedEveryTime(t *testing.T) {
	for i := range 50 {
		pt, sess := newProbeTarget(t)
		pt.getErr = func(p string) error {
			if p == probeMTU {
				return status.Error(codes.NotFound, "no data")
			}
			return nil
		}
		pt.subErr = func(paths []string) error {
			if slices.Contains(paths, probeMTU) {
				return status.Error(codes.InvalidArgument, "unknown path")
			}
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		notes, errs, err := sess.Subscribe(ctx, OnChange, probePaths, 0)
		require.NoError(t, err)
		select {
		case n, ok := <-notes:
			require.True(t, ok, "iteration %d: stream closed before any data", i)
			require.NotEmpty(t, n.Updates, "iteration %d", i)
		case e := <-errs:
			t.Fatalf("iteration %d: stream failed: %v", i, e)
		case <-ctx.Done():
			t.Fatalf("iteration %d: no data", i)
		}
		cancel()
		_ = sess.Close()
	}
}

// A device that refuses every Get with a transient code gives the probe no
// definite answer, so nothing suggests a concurrency limit: each path is asked
// once, as without the concurrent pass.
func TestProbeDoesNotAskAgainWithoutADefiniteAnswer(t *testing.T) {
	for _, c := range []codes.Code{codes.Unavailable, codes.ResourceExhausted, codes.Aborted} {
		t.Run(c.String(), func(t *testing.T) {
			pt, sess := newProbeTarget(t)
			pt.getErr = func(string) error { return status.Error(c, "refused") }

			subscribeAndRead(t, sess)
			assert.EqualValues(t, 1+len(probePaths), pt.gets.Load())
			assert.ElementsMatch(t, probePaths, sess.InconclusivePaths())
		})
	}
}

// The one-at-a-time pass stays within the probe deadline: with one path
// answered and four hung, the probe returns at the deadline, not after a
// per-Get deadline for each hung path.
func TestProbeAskingAgainStaysWithinTheDeadline(t *testing.T) {
	const answered = "/system/state/hostname"
	paths := []string{answered}
	for i := range 4 {
		paths = append(paths, fmt.Sprintf("/components/component[name=*]/state/leaf-%d", i))
	}
	srv := &testGNMIServer{}
	srv.getHandler = func(ctx context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
		for _, p := range req.GetPath() {
			if pathToString(p) != answered {
				<-ctx.Done()
				return nil, ctx.Err()
			}
		}
		return &gnmiproto.GetResponse{}, nil
	}
	addr := startTestGNMIServer(t, srv)
	sess, err := (&GnmicDialer{}).Dial(context.Background(), TargetSpec{Host: addr, Insecure: true, SetupTimeout: 300 * time.Millisecond})
	require.NoError(t, err)
	t.Cleanup(func() { _ = sess.Close() })

	start := time.Now()
	got := sess.(*gnmicSession).acceptedPaths(context.Background(), paths)
	assert.Less(t, time.Since(start), 300*time.Millisecond+80*time.Millisecond)
	assert.ElementsMatch(t, paths, got)
	assert.Len(t, sess.InconclusivePaths(), 4)
}

// A NotFound or a refusal is a definite answer too: a device with a concurrency
// limit whose paths all answer that way still has the rest asked again, and
// none is left without a verdict.
func TestProbeAsksAgainAfterAnyDefiniteAnswer(t *testing.T) {
	for _, c := range []codes.Code{codes.NotFound, codes.InvalidArgument} {
		t.Run(c.String(), func(t *testing.T) {
			pt := &probeTarget{srv: &testGNMIServer{}}
			var inflight atomic.Int32
			pt.srv.getHandler = func(context.Context, *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
				defer inflight.Add(-1)
				if inflight.Add(1) > 1 {
					return nil, status.Error(codes.ResourceExhausted, "too many concurrent RPCs")
				}
				time.Sleep(30 * time.Millisecond)
				return nil, status.Error(c, "answered")
			}
			sess := dialPlaintext(t, startTestGNMIServer(t, pt.srv))

			sess.(*gnmicSession).acceptedPaths(context.Background(), probePaths)
			assert.Empty(t, sess.InconclusivePaths())
		})
	}
}
