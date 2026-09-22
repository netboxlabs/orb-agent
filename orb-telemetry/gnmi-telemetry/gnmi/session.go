package gnmi

import (
	"context"
	"errors"
	"time"
)

// Update is a single normalized leaf update from a gNMI notification.
// Path is the absolute OpenConfig path; Value is the decoded scalar/string.
type Update struct {
	Path  string
	Value any
}

// Notification is our transport-agnostic view of a gNMI SubscribeResponse,
// Get response, or sampled snapshot.
type Notification struct {
	Updates  []Update
	Deletes  []string // absolute paths removed
	SyncDone bool     // true on the sync_response boundary / end of a Get
	// Timestamp is the device's notification time in nanoseconds since the
	// Unix epoch, zero when the target sent none.
	Timestamp int64
	// Paths are the request paths this notification speaks for: on a Get
	// snapshot, every path of a request the target answered whole and only the
	// ones that answered when the Get recovered path by path; on an attempt's
	// sync response, the subscriptions its streams carry between them, in
	// the order the streams synced, which is fewer than the request when a
	// path was pruned. It is transport-level, like
	// Timestamp, and only a snapshot or a sync response carries it. A caller
	// that reconciles what a dump restates speaks only for these: a path whose
	// Get failed, or whose subscription never opened, is a path the dump says
	// nothing about. Nil names no path in particular, and the caller then
	// speaks for its whole request.
	Paths []string
}

// CapabilitiesResult is the subset of a gNMI Capabilities response we use.
// Note: gNMI Capabilities does not reliably advertise ON_CHANGE support per
// path, so we do not model it here — the runner attempts ON_CHANGE and falls
// back on the Subscribe rejection instead.
type CapabilitiesResult struct {
	// Vendor is the canonical hardware-vendor (manufacturer) display name derived
	// from a SupportedModel Organization token (e.g. "Cisco", "Dell"). It feeds
	// both the device Manufacturer fallback and profile selection.
	Vendor string
	// NOS is the canonical network-OS name when one is detected (e.g. "SONiC").
	// A NOS is NOT a hardware manufacturer, so it never sets Vendor; it is used
	// ONLY to bias profile selection (a Dell-built SONiC box selects the sonic
	// overlay while its manufacturer still resolves to the hardware OEM, Dell).
	NOS string
	// Organizations are the SupportedModel Organization strings the target
	// reported, as it wrote them and in the order it listed them. Vendor is
	// derived only from the organizations the mapping knows, so a target of any
	// other vendor arrives with an empty Vendor and these are the only thing a
	// profile written for that vendor has to match on.
	Organizations []string
	Models        []string
	Encodings     []string
}

// ErrBeforeData marks an error a stream reported before it had served any
// data of its own. An attempt over several streams may be productive on one
// while another rejects the mode, and the consumer, which reads a refusal
// from how much it has seen, cannot tell that from a failure after the target
// accepted; so the session says it, with the target's own code wrapped for
// the consumer to read.
var ErrBeforeData = errors.New("before the stream served data")

// ErrStreamSilent marks a stream that served nothing at all: it answered
// neither data nor its sync response within the probe deadline, or ended
// before answering either. There is no code to read, and the ladder
// advances through it as it does through a stream the consumer saw send
// nothing.
var ErrStreamSilent = errors.New("the stream served nothing")

// Mode is a delivery mode.
type Mode string

const (
	// OnChange requests a gNMI ON_CHANGE subscription (event-driven updates).
	OnChange Mode = "on_change"
	// Sample requests a gNMI SAMPLE subscription (periodic snapshots).
	Sample Mode = "sample"
	// Get requests a one-shot gNMI Get (polled delivery).
	Get Mode = "get"
)

// Subscription is one path in a stream: its origin, delivery mode, and, for
// Sample, the interval. Origin is used as given; "" is the native schema.
type Subscription struct {
	Path             string
	Origin           string
	Mode             Mode
	SampleIntervalMs int
}

// Session is one connection to a gNMI target.
// Close must be called when a session's stream ends or errors, to release transport resources.
type Session interface {
	// Capabilities runs the gNMI Capabilities RPC.
	Capabilities(ctx context.Context) (*CapabilitiesResult, error)
	// Subscribe opens a stream for mode (OnChange or Sample) over paths and
	// returns a notifications channel and an errors channel. The channels
	// close when ctx is cancelled or the stream ends.
	Subscribe(ctx context.Context, mode Mode, paths []string, sampleIntervalMs int) (<-chan Notification, <-chan error, error)
	// SubscribeMany opens the streams carrying every subscription with its
	// own mode and origin, one stream per origin, since a target takes one
	// origin per Subscribe RPC. It tears down a previous attempt first, like
	// Subscribe. Its channels carry every stream's notifications, deliver one
	// sync response once every stream has answered its own, naming every
	// path they carry, and close when ctx is cancelled or the attempt ends,
	// which the first stream to fail or end does for all of them. A path the
	// target refuses on a Get probe is pruned, once per session; a probe that
	// reached no verdict keeps its path, which the stream then decides on; a
	// target that refuses every probe gets the full request.
	SubscribeMany(ctx context.Context, subs []Subscription) (<-chan Notification, <-chan error, error)
	// GetOnce performs a single gNMI Get over paths.
	GetOnce(ctx context.Context, paths []string) (Notification, error)
	// GetConfig fetches the target's CONFIG datastore as a serialized JSON_IETF
	// document: a single Get with DataType=CONFIG over the origin-prefixed root
	// path "/". Returns the raw JSON bytes. Used only when capture_config is on.
	GetConfig(ctx context.Context) ([]byte, error)
	// StopSubscribe tears down the active subscription (producer goroutine + gRPC
	// stream) without closing the session, so the caller can switch to a Get poll
	// on the same connection without leaking the prior subscription. No-op if
	// there is no active subscription; idempotent.
	StopSubscribe()
	// Close releases the connection.
	Close() error
}

// Dialer builds Sessions from a target spec.
type Dialer interface {
	Dial(ctx context.Context, target TargetSpec) (Session, error)
}

// TargetSpec is the minimal connection info the dialer needs.
type TargetSpec struct {
	Host       string
	Username   string
	Password   string
	SkipVerify bool
	Insecure   bool   // explicit opt-in to plaintext (no TLS); default is TLS
	Origin     string // gNMI request-path origin (e.g. "openconfig"); "" = origin-less
	CAFile     string
	CertFile   string
	KeyFile    string
	// ProbeTimeout bounds each probe the session runs under a caller's
	// unbounded context: the Capabilities call that opens it and the Get it
	// runs per path before it opens a stream. Either would otherwise run under
	// the loop's context, which lives as long as the policy, so a target that
	// goes silent would hold the session open for ever. A caller that bounded
	// its own context keeps that bound instead. Zero takes the package
	// default.
	ProbeTimeout time.Duration
}
