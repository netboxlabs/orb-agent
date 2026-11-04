package policy

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/netboxlabs/diode-sdk-go/diode"
	gnmiproto "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/gnmi"
	"github.com/netboxlabs/orb-agent/orb-discovery/gnmi-discovery/mapping"
)

// gnmiTarget is an in-process gNMI device reached through the real gnmic
// transport. Each RPC answers with the device below unless its hook returns an
// error; a nil hook always answers.
type gnmiTarget struct {
	gnmiproto.UnimplementedGNMIServer

	capsErr  func(call int32) error
	capsHang bool
	getErr   func(paths []string) error
	subErr   func(paths []string) error
	// encodings the device advertises; JSON_IETF when empty.
	encodings []gnmiproto.Encoding
	// serial is the chassis serial number the device reports.
	serial atomic.Value

	caps, gets, subs atomic.Int32
	sawSample        atomic.Bool // a SAMPLE subscription was requested

	mu      sync.Mutex
	subEncs []gnmiproto.Encoding
	subReqs [][]string
	events  strings.Builder // C per Capabilities, G per Get, S per Subscribe
	stop    chan struct{}   // closed by dropStreams to end the open streams
}

func (s *gnmiTarget) Capabilities(ctx context.Context, _ *gnmiproto.CapabilityRequest) (*gnmiproto.CapabilityResponse, error) {
	n := s.caps.Add(1)
	s.mu.Lock()
	s.events.WriteString("C")
	s.mu.Unlock()
	if s.capsHang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.capsErr != nil {
		if err := s.capsErr(n); err != nil {
			return nil, err
		}
	}
	encs := s.encodings
	if len(encs) == 0 {
		encs = []gnmiproto.Encoding{gnmiproto.Encoding_JSON_IETF}
	}
	return &gnmiproto.CapabilityResponse{
		SupportedModels:    []*gnmiproto.ModelData{{Name: "openconfig-system", Organization: "Example Org"}},
		SupportedEncodings: encs,
	}, nil
}

func (s *gnmiTarget) Get(_ context.Context, req *gnmiproto.GetRequest) (*gnmiproto.GetResponse, error) {
	s.gets.Add(1)
	s.mu.Lock()
	s.events.WriteString("G")
	s.mu.Unlock()
	paths := requestPaths(req.GetPath())
	if s.getErr != nil {
		if err := s.getErr(paths); err != nil {
			return nil, err
		}
	}
	return &gnmiproto.GetResponse{Notification: []*gnmiproto.Notification{{Update: s.device(paths)}}}, nil
}

func (s *gnmiTarget) Subscribe(stream gnmiproto.GNMI_SubscribeServer) error {
	s.subs.Add(1)
	req, err := stream.Recv()
	if err != nil {
		return err
	}
	var reqPaths []*gnmiproto.Path
	for _, sub := range req.GetSubscribe().GetSubscription() {
		reqPaths = append(reqPaths, sub.GetPath())
		if sub.GetMode() == gnmiproto.SubscriptionMode_SAMPLE {
			s.sawSample.Store(true)
		}
	}
	paths := requestPaths(reqPaths)
	s.mu.Lock()
	s.events.WriteString("S")
	s.subEncs = append(s.subEncs, req.GetSubscribe().GetEncoding())
	s.subReqs = append(s.subReqs, paths)
	s.mu.Unlock()
	if s.subErr != nil {
		if err := s.subErr(paths); err != nil {
			return err
		}
	}
	if err := stream.Send(&gnmiproto.SubscribeResponse{Response: &gnmiproto.SubscribeResponse_Update{
		Update: &gnmiproto.Notification{Update: s.device(paths)},
	}}); err != nil {
		return err
	}
	if err := stream.Send(&gnmiproto.SubscribeResponse{Response: &gnmiproto.SubscribeResponse_SyncResponse{SyncResponse: true}}); err != nil {
		return err
	}
	select {
	case <-stream.Context().Done():
		return nil
	case <-s.stopped():
		return status.Error(codes.Unavailable, "stream reset")
	}
}

// stopped is closed when the streams open now are dropped.
func (s *gnmiTarget) stopped() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop == nil {
		s.stop = make(chan struct{})
	}
	return s.stop
}

// dropStreams ends every open stream with Unavailable.
func (s *gnmiTarget) dropStreams() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stop != nil {
		close(s.stop)
	}
	s.stop = make(chan struct{})
}

// device returns the leaves under the requested paths: a hostname and one
// chassis with its model and serial.
func (s *gnmiTarget) device(paths []string) []*gnmiproto.Update {
	serial := "SN-0001"
	if v, ok := s.serial.Load().(string); ok {
		serial = v
	}
	chassis := map[int]map[string]string{1: {"name": "chassis1"}}
	all := []*gnmiproto.Update{
		targetLeaf([]string{"system", "state", "hostname"}, nil, "sw1"),
		targetLeaf([]string{"components", "component", "state", "type"}, chassis, "openconfig-platform-types:CHASSIS"),
		targetLeaf([]string{"components", "component", "state", "part-no"}, chassis, "MODEL-1"),
		targetLeaf([]string{"components", "component", "state", "serial-no"}, chassis, serial),
		targetLeaf([]string{"components", "component", "state", "mfg-name"}, chassis, "Example Mfg"),
	}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
	}
	var out []*gnmiproto.Update
	for _, u := range all {
		if want[elemNames(u.GetPath())] {
			out = append(out, u)
		}
	}
	return out
}

func (s *gnmiTarget) subscribeEncodings() []gnmiproto.Encoding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]gnmiproto.Encoding(nil), s.subEncs...)
}

func (s *gnmiTarget) eventLog() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.events.String()
}

func (s *gnmiTarget) subscribeRequests() [][]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]string(nil), s.subReqs...)
}

func targetLeaf(names []string, keys map[int]map[string]string, v string) *gnmiproto.Update {
	elems := make([]*gnmiproto.PathElem, 0, len(names))
	for i, n := range names {
		elems = append(elems, &gnmiproto.PathElem{Name: n, Key: keys[i]})
	}
	return &gnmiproto.Update{
		Path: &gnmiproto.Path{Elem: elems},
		Val:  &gnmiproto.TypedValue{Value: &gnmiproto.TypedValue_StringVal{StringVal: v}},
	}
}

// elemNames renders a path by element names alone, keys dropped.
func elemNames(p *gnmiproto.Path) string {
	names := make([]string, 0, len(p.GetElem()))
	for _, e := range p.GetElem() {
		names = append(names, e.GetName())
	}
	return "/" + strings.Join(names, "/")
}

func requestPaths(ps []*gnmiproto.Path) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, elemNames(p))
	}
	return out
}

func startGNMITarget(t *testing.T, s *gnmiTarget) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	g := grpc.NewServer()
	gnmiproto.RegisterGNMIServer(g, s)
	go func() { _ = g.Serve(lis) }()
	t.Cleanup(g.Stop)
	return lis.Addr().String()
}

// countingGnmicDialer is the real dialer, counting its dials.
type countingGnmicDialer struct {
	gnmi.GnmicDialer
	dials atomic.Int32
}

func (d *countingGnmicDialer) Dial(ctx context.Context, spec gnmi.TargetSpec) (gnmi.Session, error) {
	d.dials.Add(1)
	return d.GnmicDialer.Dial(ctx, spec)
}

// runAgainst starts a one-target runner against srv in mode, with quick
// reconnects. tune adjusts the runner before it starts.
func runAgainst(t *testing.T, srv *gnmiTarget, mode string, tune func(*Runner)) (*Runner, *recordingClient, *countingGnmicDialer, *syncBuf) {
	t.Helper()
	dialer := &countingGnmicDialer{}
	r, client, _, logs := runAgainstWith(t, startGNMITarget(t, srv), dialer, mode, tune)
	return r, client, dialer, logs
}

// runAgainstWith is runAgainst for a target already listening at addr, dialled
// through dialer.
func runAgainstWith(t *testing.T, addr string, dialer gnmi.Dialer, mode string, tune func(*Runner)) (*Runner, *recordingClient, gnmi.Dialer, *syncBuf) {
	t.Helper()
	store, err := mapping.LoadProfiles("")
	require.NoError(t, err)
	user, pass := "user", "secret"
	tg := config.Target{Host: addr, TLS: &config.TLSConfig{Insecure: true}, Username: &user, Password: &pass}
	pol := config.Policy{
		Config: config.PolicyConfig{
			Mode: mode, DebounceMs: 20, SampleIntervalMs: 60000, GetIntervalMs: 60000,
			Defaults: config.Defaults{Site: "lab", Role: "router"},
		},
		Scope: config.Scope{Targets: []config.Target{tg}},
	}
	logs := &syncBuf{}
	client := &recordingClient{}
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, err := NewRunner(context.Background(), logger, "p1", pol, client, dialer, store)
	require.NoError(t, err)
	r.backoffBase = 10 * time.Millisecond
	if tune != nil {
		tune(r)
	}
	r.Start()
	t.Cleanup(func() { _ = r.Stop() })
	return r, client, dialer, logs
}

// ingestedDevice is the Device of the latest ingest.
func ingestedDevice(t *testing.T, c *recordingClient) *diode.Device {
	t.Helper()
	for _, e := range c.lastIngested() {
		if d, ok := e.(*diode.Device); ok {
			return d
		}
	}
	t.Fatal("no device ingested")
	return nil
}

// targetStatus is the runner's only target.
func targetStatus(t *testing.T, r *Runner) TargetStatus {
	t.Helper()
	st := r.TargetStatuses()
	require.Len(t, st, 1)
	return st[0]
}

// requireSettled asserts the target ingests after exactly dials connections
// and then stops redialling.
func requireSettled(t *testing.T, client *recordingClient, d *countingGnmicDialer, dials int32) {
	t.Helper()
	require.Eventually(t, func() bool { return client.count() > 0 }, 5*time.Second, 10*time.Millisecond, "never ingested")
	require.Equal(t, dials, d.dials.Load())
	time.Sleep(300 * time.Millisecond)
	require.Equal(t, dials, d.dials.Load(), "the target kept redialling after it ingested")
}
