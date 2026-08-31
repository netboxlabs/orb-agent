package snmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// redactedCommunity stands in for the community in every line gosnmp logs.
const redactedCommunity = "[REDACTED]"

// SlogAdapter adapts slog.Logger to implement gosnmp.LoggerInterface.
//
// gosnmp logs whole packets at debug level, and the community is the
// credential of a v1 or v2c session: its packet format prints the community
// verbatim, and it prints again the one it parses out of every reply. The
// adapter removes the value from every line it forwards, matching on the
// community itself rather than on the library's format string, so a gosnmp
// release that renames or moves the field cannot reopen the disclosure.
type SlogAdapter struct {
	logger *slog.Logger
	// community is the value to redact. Empty for v3, which carries none.
	community string
}

// redact removes the community from a line gosnmp is about to log.
func (s *SlogAdapter) redact(line string) string {
	if s.community == "" {
		return line
	}
	return strings.ReplaceAll(line, s.community, redactedCommunity)
}

// Print implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Print(v ...any) {
	s.logger.Debug(s.redact(fmt.Sprint(v...)))
}

// Printf implements gosnmp.LoggerInterface by logging at Debug level
func (s *SlogAdapter) Printf(format string, v ...any) {
	s.logger.Debug(s.redact(fmt.Sprintf(format, v...)))
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

// redactError removes the community from an error before it leaves the client.
//
// gosnmp reports a malformed reply by quoting the bytes it could not parse,
// and the community is an octet string near the front of every v1 and v2c
// message, so such an error carries the credential. A reply whose community
// length octet is corrupt yields "not enough data for OctetString (29495 vs
// 64): 0482<community><rest of packet>", and one cut short inside the
// community yields a prefix of it. Redacting in the log adapter does not reach
// these: the error is returned, and the collector logs it at warn level and
// the policy status endpoint serves it, so it discloses the community whatever
// the log level.
//
// Lowercase hex is the only encoding to remove. gosnmp formats packet bytes
// with %x and with nothing else, so the value never reaches an error as text.
// Leaving the words of the message unmatched is also what keeps a short
// community from mangling the diagnostic: a one-character community is two hex
// characters, which no word can hold.
//
// Every prefix is removed, not only the whole value, because a dump ending
// inside the community carries a prefix and a prefix of a credential is still
// one. A byte of an unrelated dump that happens to equal the community's first
// byte goes with them. That costs two characters of the dump and leaves the
// parse stage, the byte counts and the remaining bytes, which is the safe
// direction.
//
// The redacted error is a new one rather than a wrapper: an Unwrap would hand
// the original, community and all, to anything that reached for it.
func (c *Client) redactError(err error) error {
	if err == nil {
		return err
	}
	message := err.Error()
	redacted := message
	// Longest prefix first. Shortest first would replace the leading byte
	// everywhere, leaving the rest of the community with nothing left to match
	// it. An empty community, which is what v3 carries, yields no prefixes at
	// all, so the loop is skipped rather than an empty needle being replaced
	// between every character.
	for n := len(c.Community); n > 0; n-- {
		redacted = strings.ReplaceAll(redacted, hex.EncodeToString([]byte(c.Community[:n])), redactedCommunity)
	}
	if redacted == message {
		return err
	}
	return errors.New(redacted)
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
		return nil, c.redactError(err)
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
		gosnmpLogger = gosnmp.NewLogger(&SlogAdapter{logger: logger, community: authentication.Community})
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
		msgFlags := v3MsgFlags(authentication.SecurityLevel)
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

// SecurityLevelNoAuthNoPriv authenticates nothing and encrypts nothing.
const SecurityLevelNoAuthNoPriv = "noAuthNoPriv"

// SecurityLevelAuthNoPriv authenticates the message and does not encrypt it.
const SecurityLevelAuthNoPriv = "authNoPriv"

// SecurityLevelAuthPriv authenticates and encrypts the message.
const SecurityLevelAuthPriv = "authPriv"

// v3MsgFlags maps a policy security level to the gosnmp message flags a v3
// client dials with. An unrecognised level yields the weakest flags, which is
// what NewClient has always done; the level name is checked before a policy
// reaches here.
func v3MsgFlags(securityLevel string) gosnmp.SnmpV3MsgFlags {
	switch securityLevel {
	case SecurityLevelAuthNoPriv:
		return gosnmp.AuthNoPriv
	case SecurityLevelAuthPriv:
		return gosnmp.AuthPriv
	default:
		return gosnmp.NoAuthNoPriv
	}
}

// ValidateV3SecurityParameters reports whether the v3 protocol names, security
// level and passphrases in auth are ones the client can dial with. The caller
// has already established that auth is an SNMPv3 block.
//
// Both names go through the tables NewClient uses and the level goes through
// the same mapping NewClient dials with, so a caller checking a policy up front
// cannot drift from what collection accepts. An empty name is valid and selects
// the default, which is the sentinel: it therefore resolves everywhere and is
// accepted only where the sentinel is.
//
// gosnmp's counterpart is UsmSecurityParameters.validate, which is unexported
// and reachable only by dialing, so the comparisons below are stated here in
// its terms, against its constants and its bit tests, and pinned by a test that
// drives every combination through Connect. The first two come from its
// security level switch and the last two from the passphrase checks that follow
// it: a protocol above the sentinel needs its passphrase whatever the level
// asks for, and a passphrase beside a sentinel protocol is never read. gosnmp
// skips those two when a pre-derived key is set instead, which NewClient never
// does.
func ValidateV3SecurityParameters(auth *config.Authentication) error {
	authProtocol, err := getAuthProtocol(auth.AuthProtocol)
	if err != nil {
		return err
	}
	privProtocol, err := getPrivProtocol(auth.PrivProtocol)
	if err != nil {
		return err
	}

	flags := v3MsgFlags(auth.SecurityLevel)
	if flags&gosnmp.AuthNoPriv > 0 && authProtocol <= gosnmp.NoAuth {
		return fmt.Errorf("security level %s needs an authentication protocol, got %q",
			auth.SecurityLevel, auth.AuthProtocol)
	}
	if flags&gosnmp.AuthPriv > gosnmp.AuthNoPriv && privProtocol <= gosnmp.NoPriv {
		return fmt.Errorf("security level %s needs a privacy protocol, got %q",
			auth.SecurityLevel, auth.PrivProtocol)
	}
	if authProtocol > gosnmp.NoAuth && auth.AuthPassphrase == "" {
		return fmt.Errorf("authentication protocol %s needs an auth passphrase", auth.AuthProtocol)
	}
	if privProtocol > gosnmp.NoPriv && auth.PrivPassphrase == "" {
		return fmt.Errorf("privacy protocol %s needs a priv passphrase", auth.PrivProtocol)
	}
	return nil
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
