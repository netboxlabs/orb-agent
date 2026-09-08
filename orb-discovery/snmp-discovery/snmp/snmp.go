package snmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/mapping"
)

// SlogAdapter adapts slog.Logger to implement gosnmp.LoggerInterface
type SlogAdapter struct {
	logger *slog.Logger
}

// Print implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Print(v ...any) {
	s.logger.Debug(fmt.Sprint(v...))
}

// Printf implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Printf(format string, v ...any) {
	s.logger.Debug(fmt.Sprintf(format, v...))
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

// NewHost creates a new Host
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
	s.logger.Info("scanning", "host", s.address)

	snmpClient, err := s.ClientFactory(s.address, s.port, s.retries, s.timeout, s.authentication, s.logger)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := snmpClient.Close(); err != nil {
			s.logger.Warn("error closing SNMP connection", "host", s.address, "error", err)
		}
	}()

	err = snmpClient.Connect()
	if err != nil {
		s.logger.Warn("could not connect to host", "host", s.address, "error", err)
		return nil, err
	}

	// Each table is walked on its own: one the agent fails is logged and
	// skipped, and the target keeps everything the other tables returned.
	// Returning on the first failure cost the whole target, device,
	// interfaces and addresses included, for one table the agent could not
	// serve. A timeout is not such a failure but the device going silent,
	// and fails the target at once. Only a target that failed every table
	// is failed otherwise.
	output := make(mapping.ObjectIDValueMap)
	var walked, failed int
	var lastErr error
	for objectID, identifierSize := range objectIDs {
		if err := ctx.Err(); err != nil {
			// The policy stopped waiting: no further table is started.
			return nil, err
		}
		walked++
		pdu, err := snmpClient.Walk(ctx, objectID, identifierSize)
		switch {
		case err == nil:
		case ctx.Err() != nil:
			// The policy's timeout ended the walk: nothing more is owed to
			// this target, and the runner has stopped waiting for it.
			return nil, err
		case errors.Is(err, ErrWalkTruncated):
			s.logger.Warn("table walk truncated at the row cap; keeping what was collected", "object_id", objectID, "rows", len(pdu))
		case isTimeout(err):
			// The device stopped answering: every remaining table would
			// spend its own timeout the same way, and one is the target's
			// whole verdict.
			s.logger.Warn("error walking object ID", "object_id", objectID, "error", err)
			return nil, err
		default:
			s.logger.Warn("error walking object ID; continuing with the other tables", "object_id", objectID, "error", err)
			failed++
			lastErr = err
			continue
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
	if walked > 0 && failed == walked {
		return nil, lastErr
	}
	if failed > 0 {
		s.logger.Warn("some tables could not be walked", "host", s.address, "failed", failed, "walked", walked)
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
		slog.Warn("unhandled SNMP type", "name", pdu.Name, "type", pdu.Type)
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
	return collectWalk(ctx, func(fn gosnmp.WalkFunc) error { return c.GoSNMP.Walk(objectIDs, fn) }, identifierSize)
}

// errWalkRepeated ends a walk that delivered an OID it had already delivered.
var errWalkRepeated = errors.New("walk repeated an OID")

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
			return errWalkRepeated
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
	case err == nil, errors.Is(err, errWalkRepeated):
		return output, nil
	case errors.Is(err, ErrWalkTruncated):
		return output, ErrWalkTruncated
	}
	return nil, err
}

// isTimeout reports whether a walk failed because the device stopped
// answering. gosnmp reports that as a plain "request timeout" error, and a
// transport deadline reads the same way; neither is a table the agent could
// not serve, so neither is skipped.
func isTimeout(err error) bool {
	return err != nil && strings.Contains(err.Error(), "timeout")
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
		gosnmpLogger = gosnmp.NewLogger(&SlogAdapter{logger})
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
