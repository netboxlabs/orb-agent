package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-discovery/snmp-discovery/config"
)

// The community is the credential of an SNMPv1 or v2c session. These tests pin
// that it stays out of everything the client logs or returns (MON-777): gosnmp
// logs every packet at debug level, and the agent relays this process's log
// into its own.

// debugLogger returns a debug-level logger and the buffer it writes to. Debug
// is the level that installs gosnmp's packet logger.
func debugLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// communityForms are the ways a line can carry the community: as text, as the
// decimal numbers of a byte slice printed with %v, and as lowercase hex.
func communityForms(community string) []string {
	return []string{
		community,
		decimalBytes(community),
		hex.EncodeToString([]byte(community)),
	}
}

// A debug walk against a device must leave the community out of the log: the
// packets gosnmp sends, the community it parses from each reply and its dump of
// each reply's bytes.
func TestClient_CommunityNeverReachesTheDebugLog(t *testing.T) {
	const (
		root      = "1.3.6.1.2.1.2.2.1"
		community = "n0t-in-the-log"
	)
	agent := newRedactAgent(t, root, nil)
	logger, buf := debugLogger()

	w, err := NewClient("127.0.0.1", agent.port, 1, 3*time.Second,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: community}, logger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })

	rows, err := w.Walk(t.Context(), root, 0)
	require.NoError(t, err)
	require.NotEmpty(t, rows, "the walk has to reach the agent for the log to hold packets")

	logged := buf.String()
	require.Contains(t, logged, "SENDING PACKET", "the packet logger has to be installed for this to pin anything")
	require.Contains(t, logged, "Parsed community", "the reply path has to have parsed a community")
	require.Contains(t, logged, "GET RESPONSE OK", "the reply has to have been dumped")
	for _, form := range communityForms(community) {
		assert.NotContains(t, logged, form, "the community reached the debug log")
	}
	assert.Contains(t, logged, "Community:"+redactedCommunity, "the packet line keeps its community field, redacted")
	assert.Contains(t, logged, root, "redaction left the rest of the packet line intact")
}

// gosnmp's packet format prints the community verbatim. Pinning the adapter
// against that real output means a gosnmp bump that changes it fails here.
func TestSlogAdapter_RedactsTheCommunityFromARealPacketLine(t *testing.T) {
	const community = "n0t-in-the-log"
	packet := &gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: community,
		PDUType:   gosnmp.GetNextRequest,
		RequestID: 42,
		Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}},
	}
	line := packet.SafeString()
	require.Contains(t, line, "Community:"+community,
		"gosnmp no longer prints the community here; revisit what the adapter redacts")

	logger, buf := debugLogger()
	(&SlogAdapter{logger: logger, community: community}).Printf("SENDING PACKET: %s", line)

	logged := buf.String()
	assert.NotContains(t, logged, community)
	assert.Contains(t, logged, "Community:"+redactedCommunity)
	assert.Contains(t, logged, "RequestID:42", "the rest of the line survived the redaction")
}

// gosnmp dumps every reply it reads as a byte slice, which prints the
// community as decimal numbers.
func TestSlogAdapter_RedactsTheCommunityFromAReplyDump(t *testing.T) {
	const community = "n0t-in-the-log"
	reply, err := (&gosnmp.SnmpPacket{
		Version:   gosnmp.Version2c,
		Community: community,
		PDUType:   gosnmp.GetResponse,
		RequestID: 42,
		Variables: []gosnmp.SnmpPDU{{Name: "1.3.6.1.2.1.1.1.0", Type: gosnmp.Null}},
	}).MarshalMsg()
	require.NoError(t, err)
	logger, buf := debugLogger()

	(&SlogAdapter{logger: logger, community: community}).Printf("GET RESPONSE OK: %+v", reply)

	logged := buf.String()
	for _, form := range communityForms(community) {
		assert.NotContains(t, logged, form, "the community survived the adapter")
	}
	assert.Contains(t, logged, "GET RESPONSE OK: ")
	assert.Contains(t, logged, redactedCommunity, "the elided span is marked")
}

// Print carries the same lines as Printf, so it redacts the same way.
func TestSlogAdapter_PrintRedactsTheCommunity(t *testing.T) {
	const community = "n0t-in-the-log"
	logger, buf := debugLogger()

	(&SlogAdapter{logger: logger, community: community}).Print("Parsed community ", community)

	assert.NotContains(t, buf.String(), community)
	assert.Contains(t, buf.String(), "Parsed community "+redactedCommunity)
}

// A v3 client carries no community, so its lines print as gosnmp formats them
// rather than an empty needle being matched between every character.
func TestSlogAdapter_EmptyCommunityLeavesTheLineAlone(t *testing.T) {
	logger, buf := debugLogger()
	adapter := &SlogAdapter{logger: logger}

	adapter.Printf("SECURITY PARAMETERS:%s", "UserName:admin")
	adapter.Printf("GET RESPONSE OK: %+v", []byte{48, 49})

	assert.Contains(t, buf.String(), "SECURITY PARAMETERS:UserName:admin")
	assert.Contains(t, buf.String(), "GET RESPONSE OK: [48 49]")
	assert.NotContains(t, buf.String(), redactedCommunity)
}

// A v2c reply carries the community as an octet string near its front:
// 30 <len> 02 01 01 04 <communityLength> <community> ...
const communityLengthOctet = 6

// A reply whose community length octet is corrupt makes gosnmp quote the rest
// of the packet, community included, into the error it returns, and the runner
// logs that error at warn and error level whatever the log level. A reply cut
// short inside the community leaves a prefix of it, which is still a
// credential.
func TestClient_WalkErrorDoesNotCarryTheCommunity(t *testing.T) {
	const (
		root      = "1.3.6.1.2.1.2.2.1"
		community = "s3cr3tc0mmun1ty"
	)
	for name, corrupt := range map[string]func([]byte) []byte{
		"length overstated": func(pkt []byte) []byte {
			out := append([]byte(nil), pkt...)
			// The BER long form, so the parser reads a length running past the
			// buffer and reports the whole remaining packet.
			out[communityLengthOctet] = 0x82
			return out
		},
		"cut inside": func(pkt []byte) []byte {
			// Seven bytes of the community, with the outer length rewritten so
			// the reply passes gosnmp's sanity check.
			out := append([]byte(nil), pkt[:communityLengthOctet+1+7]...)
			out[1] = byte(len(out) - 2)
			return out
		},
	} {
		t.Run(name, func(t *testing.T) {
			agent := newRedactAgent(t, root, corrupt)
			w, err := NewClient("127.0.0.1", agent.port, 0, 300*time.Millisecond,
				&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: community},
				slog.New(slog.DiscardHandler))
			require.NoError(t, err)
			require.NoError(t, w.Connect())
			t.Cleanup(func() { _ = w.Close() })

			_, err = w.Walk(t.Context(), root, 0)
			require.Error(t, err, "the corrupt reply has to have failed the walk")
			msg := err.Error()
			require.Contains(t, msg, "not enough data for OctetString", "the parse failure survived")
			assert.Contains(t, msg, redactedCommunity, "the elided span is marked")
			assert.NotContains(t, msg, community)
			for n := len(community); n > 0; n-- {
				assert.NotContains(t, msg, hex.EncodeToString([]byte(community[:n])),
					"%d bytes of the community appeared in hex", n)
			}
		})
	}
}

// The walk's own errors and a context's are told apart with errors.Is, so a
// community whose hex happens to occur in their text must not turn them into
// new errors. 0xce occurs in "exceeded", 0xea in "repeated" and "deadline",
// 0xca in "truncated" and "canceled".
func TestClient_RedactErrorKeepsTheWalkAndContextErrors(t *testing.T) {
	for _, community := range []string{"\xce", "\xea", "\xca"} {
		c := &Client{&gosnmp.GoSNMP{Community: community}}
		for _, target := range []error{ErrWalkRepeated, ErrWalkTruncated, context.Canceled, context.DeadlineExceeded} {
			assert.ErrorIs(t, c.redactError(target), target, "community %x", community)
		}
	}
}

// An error carrying nothing to redact is returned as it was.
func TestClient_ErrorWithoutTheCommunityIsReturnedUnchanged(t *testing.T) {
	c := &Client{&gosnmp.GoSNMP{Community: "s3cr3tc0mmun1ty"}}
	original := errors.New("request timeout (after 0 retries)")
	assert.Same(t, original, c.redactError(original))
	assert.NoError(t, c.redactError(nil))
}

// redactAgent answers a GETNEXT walk of one value under root, then a value
// past it, so the walk leaves the subtree. corrupt, when set, rewrites each
// encoded reply before it goes on the wire.
type redactAgent struct {
	conn net.PacketConn
	port uint16
}

func newRedactAgent(t *testing.T, root string, corrupt func([]byte) []byte) *redactAgent {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	require.True(t, ok)
	require.LessOrEqual(t, udp.Port, math.MaxUint16)

	vars := []gosnmp.SnmpPDU{
		{Name: root + ".1.1", Type: gosnmp.OctetString, Value: []byte("c1r1")},
		{Name: "1.3.6.1.2.1.99", Type: gosnmp.Integer, Value: 1},
	}
	go func() {
		codec := &gosnmp.GoSNMP{Version: gosnmp.Version2c, MaxOids: gosnmp.MaxOids}
		buf := make([]byte, 4096)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			req, err := codec.SnmpDecodePacket(buf[:n])
			if err != nil || len(req.Variables) == 0 {
				continue
			}
			answer := []gosnmp.SnmpPDU{{Name: req.Variables[0].Name, Type: gosnmp.EndOfMibView}}
			for _, v := range vars {
				if oidAfter(v.Name, req.Variables[0].Name) {
					answer = []gosnmp.SnmpPDU{v}
					break
				}
			}
			codec.Version = req.Version
			codec.Community = req.Community
			// The encoder stamps the next value of its own counter, so seeding
			// it one below the request's ID makes the reply carry that ID.
			codec.SetRequestID(req.RequestID - 1)
			out, err := codec.SnmpEncodePacket(gosnmp.GetResponse, answer, 0, 0)
			if err != nil {
				continue
			}
			if corrupt != nil {
				out = corrupt(out)
			}
			_, _ = conn.WriteTo(out, addr)
		}
	}()
	return &redactAgent{conn: conn, port: uint16(udp.Port)}
}

// oidAfter reports whether OID a sorts after OID b.
func oidAfter(a, b string) bool {
	as := strings.Split(strings.TrimPrefix(a, "."), ".")
	bs := strings.Split(strings.TrimPrefix(b, "."), ".")
	for i := 0; i < len(as) && i < len(bs); i++ {
		ai, _ := strconv.Atoi(as[i])
		bi, _ := strconv.Atoi(bs[i])
		if ai != bi {
			return ai > bi
		}
	}
	return len(as) > len(bs)
}

// decimalBytes is the community's bytes as a byte slice prints them with %v,
// without the brackets.
func decimalBytes(community string) string {
	numbers := make([]string, 0, len(community))
	for _, b := range []byte(community) {
		numbers = append(numbers, strconv.Itoa(int(b)))
	}
	return strings.Join(numbers, " ")
}
