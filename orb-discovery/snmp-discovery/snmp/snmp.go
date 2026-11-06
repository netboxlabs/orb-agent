package snmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// redactedCommunity stands in for the community in every line gosnmp logs.
const redactedCommunity = "[REDACTED]"

// SlogAdapter adapts slog.Logger to implement gosnmp.LoggerInterface.
//
// gosnmp logs whole packets at debug level, and the community is the
// credential of a v1 or v2c session: its packet format prints the community
// verbatim, it prints again the one it parses out of every reply, and it dumps
// every reply's bytes. The adapter removes the value from every line it
// forwards, matching on the community itself rather than on the library's
// format strings, so a gosnmp release that renames or moves a field cannot
// reopen the disclosure. The agent relays this process's log into its own.
type SlogAdapter struct {
	logger *slog.Logger
	// community is the value to redact. Empty for v3, which carries none.
	community string
}

// redact removes the community from a line gosnmp is about to log: as text,
// and from the packet dumps in it (see redactHex), where gosnmp's parse errors
// quote a malformed reply's bytes.
func (s *SlogAdapter) redact(line string) string {
	if s.community == "" {
		return line
	}
	return redactHex(strings.ReplaceAll(line, s.community, redactedCommunity), s.community)
}

// hexBytes renders each byte slice among a line's arguments as hex, so redact
// finds it as a dump. gosnmp logs every reply it reads as a byte slice
// ("GET RESPONSE OK: %+v"), which would print as decimal numbers, carrying a
// v1 or v2c reply's community in a form neither match sees.
func (s *SlogAdapter) hexBytes(v []any) []any {
	if s.community == "" {
		return v
	}
	out := slices.Clone(v)
	for i, arg := range out {
		if b, ok := arg.([]byte); ok {
			out[i] = hex.EncodeToString(b)
		}
	}
	return out
}

// Print implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Print(v ...any) {
	s.logger.Debug(s.redact(fmt.Sprint(s.hexBytes(v)...)))
}

// Printf implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Printf(format string, v ...any) {
	s.logger.Debug(s.redact(fmt.Sprintf(format, s.hexBytes(v)...)))
}

// hexDump matches a run of lowercase hex long enough to be packet bytes. The
// shortest dump that ends inside the community, its tag, its length and one
// byte of it, is six characters. A shorter run is a word or a number of the
// message, such as an address's octet or a port, where a two-character
// prefix of the community's hex would otherwise match.
var hexDump = regexp.MustCompile(`[0-9a-f]{6,}`)

// redactHex removes every prefix of the community's lowercase hex from each
// packet dump in s, for the reasons redactError gives.
func redactHex(s, community string) string {
	// An empty community, which is what v3 carries, yields no prefixes, so
	// nothing is replaced rather than an empty needle between every character.
	if community == "" {
		return s
	}
	return hexDump.ReplaceAllStringFunc(s, func(dump string) string {
		// Longest prefix first. Shortest first would replace the leading byte
		// everywhere, leaving the rest of the community with nothing left to
		// match it.
		for n := len(community); n > 0; n-- {
			dump = strings.ReplaceAll(dump, hex.EncodeToString([]byte(community[:n])), redactedCommunity)
		}
		return dump
	})
}

// Host is a struct that represents an SNMP host
type Host struct {
	address        string
	port           uint16
	retries        int
	timeout        time.Duration
	authentication *config.Authentication
	logger         *slog.Logger
	ClientFactory  ClientFactory
}

// NewHost creates a new Host. logger names the target: Walk's lines and its
// clients' add no host of their own.
func NewHost(host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger, ClientFactory ClientFactory) *Host {
	return &Host{
		address:        host,
		port:           port,
		retries:        retries,
		timeout:        timeout,
		authentication: authentication,
		logger:         logger,
		ClientFactory:  ClientFactory,
	}
}

// Walk walks the SNMP host
func (s *Host) Walk(ctx context.Context, objectIDs map[string]int) (mapping.ObjectIDValueMap, error) {
	s.logger.Info("scanning")

	snmpClient, err := s.ClientFactory(s.address, s.port, s.retries, s.timeout, s.authentication, s.logger)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := snmpClient.Close(); err != nil {
			s.logger.Warn("error closing SNMP connection", "error", err)
		}
	}()

	err = snmpClient.Connect()
	if err != nil {
		s.logger.Warn("could not connect to host", "error", err)
		return nil, err
	}

	// Each table is walked on its own so that a table ended short by one of
	// the walk's bounds can be kept and reported. A table the walk cannot
	// finish fails the target: what reaches here is a transport or decode
	// failure, the device going silent or answering with something other
	// than SNMP, and a device missing the tables it lost is not a
	// discovered device.
	output := make(mapping.ObjectIDValueMap)
	for objectID, identifierSize := range objectIDs {
		if err := ctx.Err(); err != nil {
			// The policy stopped waiting: no further table is started.
			return nil, err
		}
		pdu, err := snmpClient.Walk(ctx, objectID, identifierSize)
		switch {
		case err == nil:
		case ctx.Err() != nil:
			// The policy's timeout ended the walk: nothing more is owed to
			// this target, and the runner has stopped waiting for it.
			return nil, err
		case errors.Is(err, ErrWalkTruncated):
			s.logger.Warn("table walk truncated at the row cap; keeping what was collected", "object_id", objectID, "rows", len(pdu))
		case errors.Is(err, ErrWalkRepeated):
			s.logger.Warn("table walk ended at a repeated OID; keeping what was collected", "object_id", objectID, "rows", len(pdu))
		default:
			s.logger.Warn("error walking object ID", "object_id", objectID, "error", err)
			return nil, err
		}
		for k, value := range pdu {
			s.logger.Debug("mapping PDU", "object_id", k, "value", value, "value_type", reflect.TypeOf(value.Value))
			value, err := MapPDU(value)
			if err != nil {
				s.logger.Warn("error mapping PDU", "object_id", k, "error", err)
				continue
			}
			output[k] = value
			s.logger.Debug("mapped PDU", "object_id", k, "value", value)
		}
	}
	return output, nil
}

// MapPDU maps a PDU to a mapping.Value
func MapPDU(pdu PDU) (mapping.Value, error) {
	var value string
	switch pdu.Type {
	case gosnmp.OctetString:
		if str, ok := pdu.Value.(string); ok {
			value = str
		} else if bytes, ok := pdu.Value.([]byte); ok {
			value = string(bytes)
		}
	case gosnmp.Integer:
		if intVal, ok := pdu.Value.(int); ok {
			value = fmt.Sprintf("%d", intVal)
		}
	case gosnmp.IPAddress:
		if ip, ok := pdu.Value.(string); ok {
			value = ip
		}
	case gosnmp.ObjectIdentifier:
		if oid, ok := pdu.Value.(string); ok {
			value = oid
		}
	case gosnmp.TimeTicks:
		if ticks, ok := pdu.Value.(uint32); ok {
			value = fmt.Sprintf("%d", ticks)
		}
	case gosnmp.Counter32, gosnmp.Gauge32, gosnmp.Counter64:
		if val, ok := pdu.Value.(uint); ok {
			value = fmt.Sprintf("%d", val)
		}
	default:
		// Not logged here: the caller logs it, naming the target.
		return mapping.Value{}, fmt.Errorf("unhandled SNMP type: %s", pdu.Type)
	}
	return mapping.Value{
		Type:           mapping.Asn1BER(pdu.Type),
		Value:          value,
		IdentifierSize: pdu.IdentifierSize,
	}, nil
}

// Client wraps gosnmp.GoSNMP to implement the Walker interface
type Client struct {
	*gosnmp.GoSNMP
}

// Close implements the Walker interface by closing the SNMP connection
func (c *Client) Close() error {
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

// EngineDiscovered reports whether the peer answered the SNMPv3 engine
// discovery exchange.
//
// That exchange carries no credentials (RFC 3414 section 4, and gosnmp builds
// it with empty security parameters), so it is the one signal available to a
// probe that deliberately does not authenticate. A learned authoritative
// engine ID means an agent replied; nothing else populates it.
//
// False for v1 and v2c, which have no USM parameters and whose probe admission
// stays the walk result.
func (c *Client) EngineDiscovered() bool {
	usm, ok := c.SecurityParameters.(*gosnmp.UsmSecurityParameters)
	return ok && usm.AuthoritativeEngineID != ""
}

// Walk implements the Walker interface by walking the SNMP tree
func (c *Client) Walk(ctx context.Context, objectIDs string, identifierSize int) (map[string]PDU, error) {
	// gosnmp bounds every request in flight by the deadline of this context,
	// so a target that goes silent after the policy's deadline does not hold
	// the walker through the SNMP timeout and its retries.
	c.Context = ctx
	// gosnmp puts only that deadline on the socket and looks at a
	// cancellation between requests, so a read in flight when the context is
	// cancelled with no deadline, as a shutdown does, would wait out the SNMP
	// timeout. Moving the socket deadline to now returns that read at once,
	// and gosnmp then reads the cancellation.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			if c.Conn != nil {
				_ = c.Conn.SetDeadline(time.Now())
			}
		case <-stop:
		}
	}()
	rows, err := collectWalk(ctx, func(fn gosnmp.WalkFunc) error { return c.GoSNMP.Walk(objectIDs, fn) }, identifierSize)
	return rows, c.redactError(err)
}

// redactError removes the community from an error before it leaves the client.
//
// gosnmp reports a malformed reply by quoting the bytes it could not parse,
// and the community is an octet string near the front of every v1 and v2c
// message, so such an error carries the credential, whole or, from a reply cut
// short inside it, a prefix. The runner logs walk errors at warn and error
// level, so the log adapter's redaction, at debug, does not reach them.
// gosnmp formats packet bytes with %x and nothing else, so lowercase hex is
// the one encoding to remove, and every prefix of it goes, since a prefix of a
// credential is still one. Only packet dumps are matched (see hexDump), so the
// address and port the error names are left alone.
//
// This package's walk errors and a context's carry no packet bytes, and
// callers tell them apart with errors.Is, so they are returned as they are.
// Any other redacted error is a new one rather than a wrapper: an Unwrap
// would hand the original, community and all, to anything that reached for
// it.
func (c *Client) redactError(err error) error {
	if err == nil || errors.Is(err, ErrWalkRepeated) || errors.Is(err, ErrWalkTruncated) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	message := err.Error()
	redacted := redactHex(message, c.Community)
	if redacted == message {
		return err
	}
	return errors.New(redacted)
}

// ErrWalkRepeated is returned with the rows collected when a walk delivered
// an OID it had already delivered, the one way a walk without the ordering
// check can loop: the table is kept as collected and the repeat is
// reported, since the rows after it were never read.
var ErrWalkRepeated = errors.New("walk repeated an OID")

// ErrWalkTruncated is returned with the rows collected when a table hit
// maxWalkRows: the table is kept as collected and the truncation is
// reported, since a walk without the ordering check has no other end
// against an agent that answers every request with a new, non-increasing
// OID.
var ErrWalkTruncated = errors.New("walk truncated at the row cap")

// maxWalkRows bounds one table. Far past any real table, the largest
// forwarding tables included, and small enough that a runaway agent costs
// tens of megabytes rather than the process.
const maxWalkRows = 500_000

// collectWalk gathers the rows a walk delivers, keyed by OID, and ends the
// walk once ctx ends, so the policy's timeout bounds the walk in time as the
// row cap bounds it in size. The ordering
// check gosnmp applies by default is off on every client, since an agent that
// returns a table out of index order is a quirk no operator can correct and
// the check cost the whole target; without it, the one way a walk can loop is
// an agent delivering an OID it already delivered, and that ends the table
// with the rows collected before it. Any other error the walk reports fails
// the table.
func collectWalk(ctx context.Context, walk func(fn gosnmp.WalkFunc) error, identifierSize int) (map[string]PDU, error) {
	output := make(map[string]PDU)
	err := walk(func(pdu gosnmp.SnmpPDU) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, seen := output[pdu.Name]; seen {
			return ErrWalkRepeated
		}
		if len(output) >= maxWalkRows {
			return ErrWalkTruncated
		}
		output[pdu.Name] = PDU{
			Name:           pdu.Name,
			Type:           pdu.Type,
			Value:          pdu.Value,
			IdentifierSize: identifierSize,
		}
		return nil
	})
	if ctxErr := ctx.Err(); ctxErr != nil {
		// A walk that delivered no rows never reached the callback above.
		return nil, ctxErr
	}
	switch {
	case err == nil:
		return output, nil
	case errors.Is(err, ErrWalkRepeated), errors.Is(err, ErrWalkTruncated):
		return output, err
	}
	return nil, err
}

// tolerantWalks is the gosnmp option that turns its OID ordering check off;
// collectWalk guards the loop the check existed to prevent.
func tolerantWalks() map[string]any {
	return map[string]any{"c": true}
}

// PDU is a struct that represents an SNMP PDU
type PDU struct {
	Name           string
	Type           gosnmp.Asn1BER
	Value          any
	IdentifierSize int
}

const (
	// ProtocolVersion1 is the SNMPv1 protocol version
	ProtocolVersion1 = "SNMPv1"
	// ProtocolVersion2c is the SNMPv2c protocol version
	ProtocolVersion2c = "SNMPv2c"
	// ProtocolVersion3 is the SNMPv3 protocol version
	ProtocolVersion3 = "SNMPv3"
)

// ClientFactory is a function that creates a new SNMPClient
type ClientFactory func(host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger) (Walker, error)

// NewClient creates a new SNMPClient for the given target host
func NewClient(host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger) (Walker, error) {
	// Check if debug logging is enabled
	var gosnmpLogger gosnmp.Logger
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		gosnmpLogger = gosnmp.NewLogger(&SlogAdapter{logger: logger, community: authentication.Community})
	}

	switch authentication.ProtocolVersion {
	case ProtocolVersion1:
		return &Client{
			&gosnmp.GoSNMP{
				Target:    host,
				Port:      port,
				Community: authentication.Community,
				Version:   gosnmp.Version1,
				Timeout:   timeout,
				Retries:   retries,
				Logger:    gosnmpLogger,
				AppOpts:   tolerantWalks(),
			},
		}, nil
	case ProtocolVersion2c:
		return &Client{
			&gosnmp.GoSNMP{
				Target:    host,
				Port:      port,
				Community: authentication.Community,
				Version:   gosnmp.Version2c,
				Timeout:   timeout,
				Retries:   retries,
				Logger:    gosnmpLogger,
				AppOpts:   tolerantWalks(),
			},
		}, nil
	case ProtocolVersion3:
		authProtocol, err := getAuthProtocol(authentication.AuthProtocol)
		if err != nil {
			return nil, err
		}
		privProtocol, err := getPrivProtocol(authentication.PrivProtocol)
		if err != nil {
			return nil, err
		}
		msgFlags := gosnmp.NoAuthNoPriv
		switch authentication.SecurityLevel {
		case "noAuthNoPriv":
			msgFlags = gosnmp.NoAuthNoPriv
		case "authNoPriv":
			msgFlags = gosnmp.AuthNoPriv
		case "authPriv":
			msgFlags = gosnmp.AuthPriv
		}
		return &Client{
			&gosnmp.GoSNMP{
				Target:        host,
				Port:          port,
				Version:       gosnmp.Version3,
				Timeout:       timeout,
				Retries:       retries,
				MsgFlags:      msgFlags,
				SecurityModel: gosnmp.UserSecurityModel,
				ContextName:   authentication.ContextName,
				Logger:        gosnmpLogger,
				AppOpts:       tolerantWalks(),
				SecurityParameters: &gosnmp.UsmSecurityParameters{
					UserName:                 authentication.Username,
					AuthenticationProtocol:   authProtocol,
					AuthenticationPassphrase: authentication.AuthPassphrase,
					PrivacyProtocol:          privProtocol,
					PrivacyPassphrase:        authentication.PrivPassphrase,
				},
			},
		}, nil
	}
	return nil, fmt.Errorf("unsupported protocol version: %s", authentication.ProtocolVersion)
}

func getAuthProtocol(authProtocol string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch authProtocol {
	case "NoAuth":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	}
	return gosnmp.NoAuth, fmt.Errorf("unsupported authentication protocol: %s", authProtocol)
}

func getPrivProtocol(privProtocol string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch privProtocol {
	case "NoPriv":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	}
	return gosnmp.NoPriv, fmt.Errorf("unsupported privacy protocol: %s", privProtocol)
}

// Walker interface defines methods for walking SNMP trees
// It allows for connecting to SNMP devices, traversing ObjectID trees,
// and properly closing connections when finished
type Walker interface {
	Walk(ctx context.Context, objectID string, identifierSize int) (map[string]PDU, error)
	Connect() error
	Close() error
}
