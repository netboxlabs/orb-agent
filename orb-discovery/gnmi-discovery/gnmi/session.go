package gnmi

import "context"

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
	NOS       string
	Models    []string
	Encodings []string
}

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

// Session is one connection to a gNMI target.
// Close must be called when a session's stream ends or errors, to release transport resources.
type Session interface {
	// Capabilities runs the gNMI Capabilities RPC.
	Capabilities(ctx context.Context) (*CapabilitiesResult, error)
	// Subscribe opens a stream for mode (OnChange or Sample) over paths and
	// returns a notifications channel and an errors channel. The channels
	// close when ctx is cancelled or the stream ends.
	Subscribe(ctx context.Context, mode Mode, paths []string, sampleIntervalMs int) (<-chan Notification, <-chan error, error)
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
}
