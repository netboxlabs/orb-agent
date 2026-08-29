package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
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

// maxRepetitions is the batch size of a GETBULK request.
//
// The tradeoff is response size. gosnmp falls back to 50 and its own
// documentation warns some agents cannot answer that many; such an agent
// replies TooBig, which ends the walk early and collects less than a GETNEXT
// walk would have. 25 halves the reply, matches the default Prometheus
// snmp_exporter ships, and still fetches a thousand-row table in tens of round
// trips rather than thousands.
const maxRepetitions uint32 = 25

// Client wraps gosnmp.GoSNMP to implement the Walker interface
type Client struct {
	*gosnmp.GoSNMP
	// bulkWalk arms GETBULK for subsequent walks. It starts off: the first
	// walks of a collection read sysObjectID and sysDescr, which is how the
	// profile that decides this is chosen.
	bulkWalk bool
}

// SetBulkWalk implements the Walker interface by arming or disarming GETBULK.
//
// SNMPv1 has no GETBULK and gosnmp fails such a request outright rather than
// falling back, so a v1 client stays on GETNEXT whatever the profile asks for.
func (c *Client) SetBulkWalk(enabled bool) {
	c.bulkWalk = enabled && c.Version != gosnmp.Version1
}

// Close implements the Walker interface by closing the SNMP connection
func (c *Client) Close() error {
	if c.Conn != nil {
		return c.Conn.Close()
	}
	return nil
}

// Walk implements the Walker interface by walking the SNMP tree.
//
// A bulk walk fetches maxRepetitions values per request where a GETNEXT walk
// costs one request per value, which is the difference between tens and
// thousands of round trips on the multi-column tables the profiles carry.
func (c *Client) Walk(objectID string, _ int) (map[string]PDU, error) {
	walkAll := c.WalkAll
	if c.bulkWalk {
		walkAll = c.BulkWalkAll
	}
	pdu, err := walkAll(objectID)
	if err != nil {
		return nil, err
	}
	output := make(map[string]PDU)
	for _, pdu := range pdu {
		output[pdu.Name] = PDU{
			Name:  pdu.Name,
			Type:  pdu.Type,
			Value: pdu.Value,
		}
	}
	return output, nil
}

// PDU is a struct that represents an SNMP PDU
type PDU struct {
	Name  string
	Type  gosnmp.Asn1BER
	Value any
}

const (
	// ProtocolVersion1 is the SNMPv1 protocol version
	ProtocolVersion1 = "SNMPv1"
	// ProtocolVersion2c is the SNMPv2c protocol version
	ProtocolVersion2c = "SNMPv2c"
	// ProtocolVersion3 is the SNMPv3 protocol version
	ProtocolVersion3 = "SNMPv3"
)

// ClientFactory is a function that creates a new Walker. ctx is the collection
// the client is being built for.
type ClientFactory func(ctx context.Context, host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger) (Walker, error)

// NewClient creates a new Walker for the given target host.
//
// ctx bounds the whole conversation with the device, not one request. gosnmp
// consults it when it dials and again before each request attempt, and clamps a
// request's read deadline to the context deadline, so a cancelled collection
// ends the retry sequence instead of outliving it.
func NewClient(ctx context.Context, host string, port uint16, retries int, timeout time.Duration, authentication *config.Authentication, logger *slog.Logger) (Walker, error) {
	var gosnmpLogger gosnmp.Logger
	if logger.Enabled(ctx, slog.LevelDebug) {
		gosnmpLogger = gosnmp.NewLogger(&SlogAdapter{logger})
	}

	switch authentication.ProtocolVersion {
	case ProtocolVersion1:
		return &Client{
			GoSNMP: &gosnmp.GoSNMP{
				Target:    host,
				Port:      port,
				Context:   ctx,
				Community: authentication.Community,
				Version:   gosnmp.Version1,
				Timeout:   timeout,
				Retries:   retries,
				Logger:    gosnmpLogger,
			},
		}, nil
	case ProtocolVersion2c:
		return &Client{
			GoSNMP: &gosnmp.GoSNMP{
				Target:         host,
				Port:           port,
				Context:        ctx,
				Community:      authentication.Community,
				Version:        gosnmp.Version2c,
				Timeout:        timeout,
				Retries:        retries,
				MaxRepetitions: maxRepetitions,
				Logger:         gosnmpLogger,
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
			GoSNMP: &gosnmp.GoSNMP{
				Target:         host,
				Port:           port,
				Context:        ctx,
				Version:        gosnmp.Version3,
				Timeout:        timeout,
				Retries:        retries,
				MaxRepetitions: maxRepetitions,
				MsgFlags:       msgFlags,
				SecurityModel:  gosnmp.UserSecurityModel,
				ContextName:    authentication.ContextName,
				Logger:         gosnmpLogger,
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

// ValidateAuthProtocol reports whether name is an authentication protocol the
// client can resolve. It goes through the table NewClient uses rather than a
// list of its own, so a caller checking a policy up front cannot drift from
// what collection accepts. An empty name is valid and selects the default.
func ValidateAuthProtocol(name string) error {
	_, err := getAuthProtocol(name)
	return err
}

// ValidatePrivProtocol is the privacy protocol counterpart of
// ValidateAuthProtocol.
func ValidatePrivProtocol(name string) error {
	_, err := getPrivProtocol(name)
	return err
}

func getAuthProtocol(authProtocol string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch authProtocol {
	case "", "NoAuth":
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
	case "", "NoPriv":
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
type Walker interface {
	Walk(objectID string, identifierSize int) (map[string]PDU, error)
	// SetBulkWalk selects the request type subsequent walks issue. It is a
	// method rather than a dial option because the profile that decides it is
	// only known once sysObjectID has been read from the device.
	SetBulkWalk(enabled bool)
	Connect() error
	Close() error
}
