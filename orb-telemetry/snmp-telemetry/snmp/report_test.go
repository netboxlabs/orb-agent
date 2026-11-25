package snmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// What net-snmp 5.9.4 sent, read off the wire, to a client with a credential
// it refused. Each is the whole datagram. The users were privuser (SHA, AES),
// authuser (SHA, no privacy) and desuser (SHA, DES), and every request asked
// for authPriv.
const (
	// privuser with a wrong auth passphrase: usmStatsWrongDigests.
	netsnmpWrongDigest = "" +
		"3077020103301102040b93906d020300ffe3040100020103042a3028041180001f88807d8f78103a0e066b0000000002" +
		"01010202018304087072697675736572040004003033041180001f88807d8f78103a0e066b000000000400a81c020100" +
		"0201000201003011300f060a2b060106030f01010500410116"
	// A user the device does not have: usmStatsUnknownUserNames.
	netsnmpUnknownUser = "" +
		"3075020103301102041074fa97020300ffe304010002010304283026041180001f88807d8f78103a0e066b0000000002" +
		"01010202018304066e6f626f6479040004003033041180001f88807d8f78103a0e066b000000000400a81c0201000201" +
		"000201003011300f060a2b060106030f01010300410111"
	// authuser, who has no privacy: usmStatsUnsupportedSecLevels.
	netsnmpUnsupportedLevel = "" +
		"30770201033011020408c4f9f6020300ffe3040100020103042a3028041180001f88807d8f78103a0e066b0000000002" +
		"01010202018304086175746875736572040004003033041180001f88807d8f78103a0e066b000000000400a81c020100" +
		"0201000201003011300f060a2b060106030f01010100410108"
	// desuser asked with AES: usmStatsDecryptionErrors.
	netsnmpDecryption = "" +
		"3076020103301102042dfccb0f020300ffe304010002010304293027041180001f88807d8f78103a0e066b0000000002" +
		"01010202018a040764657375736572040004003033041180001f88807d8f78103a0e066b000000000400a81c02010002" +
		"01000201003011300f060a2b060106030f01010600410109"
	// The answer to engine discovery: usmStatsUnknownEngineIDs.
	netsnmpDiscovery = "" +
		"3072020103301102040b93906b020300ffe304010002010304223020041180001f88807d8f78103a0e066b0000000002" +
		"0101020201830400040004003036041180001f88807d8f78103a0e066b000000000400a81f02040b93906b0201000201" +
		"003011300f060a2b060106030f01010400410134"
	// A response to privuser with the right credential, authenticated and
	// encrypted.
	netsnmpResponse = "" +
		"3081970201033011020418ae84d4020300ffe3040103020103043e303c041180001f88807d8f78103a0e066b00000000" +
		"0201010202018304087072697675736572040ca6a4703d1071e9baca5ed224040872433183f40c970c043f5a16e5be3a" +
		"a36a0f0fa1f993ec7fc7373b9e33a4b3cea0d73971a157b9a875f7d720fe5ce4317acc03d036dd904a3a0e7d20b8b379" +
		"c5364d2e74418445317c"
)

func wire(t *testing.T, hexDump string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexDump)
	require.NoError(t, err)
	return b
}

// The reports a device sends are read as what they report, and nothing else
// is: the discovery report is not a refusal, and a response is not a report.
func TestUSMReport_ReadsWhatNetSNMPSends(t *testing.T) {
	for name, tc := range map[string]struct {
		datagram string
		counter  byte
		ok       bool
	}{
		"wrong digest":       {netsnmpWrongDigest, usmStatsWrongDigests, true},
		"unknown user":       {netsnmpUnknownUser, usmStatsUnknownUserNames, true},
		"unsupported level":  {netsnmpUnsupportedLevel, usmStatsUnsupportedSecLevels, true},
		"decryption error":   {netsnmpDecryption, usmStatsDecryptionErrors, true},
		"engine discovery":   {netsnmpDiscovery, 4, true},
		"encrypted response": {netsnmpResponse, 0, false},
		"nothing":            {"", 0, false},
		"a v2c response":     {"303102010104067075626c6963a224020212350201000201003018301606082b06010201010200060a2b06010401bf0803020a", 0, false},
		"not BER":            {"ffffffffffffffffffffffffffffffff", 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			counter, ok := usmReport(wire(t, tc.datagram))
			assert.Equal(t, tc.ok, ok)
			assert.Equal(t, tc.counter, counter)
		})
	}
}

// A report is unauthenticated bytes from the network, so a datagram cut short
// anywhere, or with any one byte changed, is either read as a report of the
// same shape or not at all, and never panics.
func TestUSMReport_SurvivesADamagedDatagram(t *testing.T) {
	whole := wire(t, netsnmpWrongDigest)
	for n := range whole {
		_, ok := usmReport(whole[:n])
		assert.False(t, ok, "cut to %d bytes", n)
	}
	for i := range whole {
		for _, v := range []byte{0x00, 0x7f, 0x80, 0x84, 0xff} {
			damaged := bytes.Clone(whole)
			damaged[i] = v
			assert.NotPanics(t, func() { usmReport(damaged) }, "byte %d set to %#x", i, v)
		}
	}
}

// testEngineID is the engine ID of the device in these tests.
var testEngineID = []byte{0x80, 0x00, 0x1f, 0x88, 0x80, 0x01, 0x02, 0x03, 0x04}

// message is an SNMPv3 message of the user security model, for a test to
// change one field of.
type message struct {
	version, flags, model byte
	msgID, requestID      []byte
	user                  string
	pdu                   byte
	bindings              [][]byte
	// longForm writes every length in the long form, as some devices do.
	longForm bool
}

// reportOf is the report of a usmStats counter as a device sends it.
func reportOf(counter byte) message {
	return message{
		version: 3, model: 3, msgID: []byte{1}, requestID: []byte{0}, user: "admin",
		pdu: berReport, bindings: [][]byte{counterBinding(counter)},
	}
}

// counterBinding is the variable binding of a usmStats counter's instance.
func counterBinding(counter byte) []byte {
	const counter32 = 0x41
	return tlv(berSequence, tlv(berOID, usmStats, []byte{counter, 0}), tlv(counter32, []byte{1}))
}

func (m message) encode() []byte {
	enc := tlv
	if m.longForm {
		enc = tlvLong
	}
	one := []byte{1}
	security := enc(berSequence,
		enc(berOctetString, testEngineID), enc(berInteger, one), enc(berInteger, one), // engine ID, boots, time
		enc(berOctetString, []byte(m.user)), enc(berOctetString), enc(berOctetString)) // user, auth and privacy parameters
	return enc(berSequence,
		enc(berInteger, []byte{m.version}),
		enc(berSequence, enc(berInteger, m.msgID), enc(berInteger, []byte{0x00, 0xff, 0xe3}),
			enc(berOctetString, []byte{m.flags}), enc(berInteger, []byte{m.model})),
		enc(berOctetString, security),
		enc(berSequence, enc(berOctetString, testEngineID), enc(berOctetString),
			enc(m.pdu, enc(berInteger, m.requestID), enc(berInteger, []byte{0}), enc(berInteger, []byte{0}),
				enc(berSequence, m.bindings...))))
}

// tlv encodes one BER element with the short form of its length.
func tlv(tag byte, contents ...[]byte) []byte {
	body := bytes.Join(contents, nil)
	if len(body) >= 0x80 {
		return tlvLong(tag, body)
	}
	return append([]byte{tag, byte(len(body))}, body...)
}

// tlvLong encodes one with the two-octet long form.
func tlvLong(tag byte, contents ...[]byte) []byte {
	body := bytes.Join(contents, nil)
	return append([]byte{tag, 0x82, byte(len(body) >> 8), byte(len(body))}, body...)
}

// Only an unauthenticated report of the user security model with one usmStats
// counter is read: each of these differs from one in a single field.
func TestUSMReport_ReadsOnlyAnUnauthenticatedReportOfOneCounter(t *testing.T) {
	counter, ok := usmReport(reportOf(usmStatsWrongDigests).encode())
	require.True(t, ok, "the report these cases change is itself read")
	require.Equal(t, byte(usmStatsWrongDigests), counter)

	for name, change := range map[string]func(*message){
		"SNMPv2c's version":        func(m *message) { m.version = 1 },
		"another security model":   func(m *message) { m.model = 1 },
		"the auth flag set":        func(m *message) { m.flags = 0x01 },
		"the privacy flag set":     func(m *message) { m.flags = 0x03 },
		"a response, not a report": func(m *message) { m.pdu = 0xa2 },
		"no variable":              func(m *message) { m.bindings = nil },
		"two variables": func(m *message) {
			m.bindings = append(m.bindings, counterBinding(usmStatsUnknownUserNames))
		},
		"a variable outside usmStats": func(m *message) {
			m.bindings = [][]byte{tlv(berSequence, tlv(berOID, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03, 0x00}), tlv(0x43, []byte{1}))}
		},
		"a usmStats column, not an instance": func(m *message) {
			m.bindings = [][]byte{tlv(berSequence, tlv(berOID, usmStats, []byte{usmStatsWrongDigests}), tlv(0x41, []byte{1}))}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m := reportOf(usmStatsWrongDigests)
			change(&m)
			_, ok := usmReport(m.encode())
			assert.False(t, ok)
		})
	}
}

// Some devices write a length in the long form where the short one would do.
// gosnmp reads those replies, so the report is read from them too.
func TestUSMReport_ReadsLongFormLengths(t *testing.T) {
	m := reportOf(usmStatsUnknownUserNames)
	m.longForm = true
	counter, ok := usmReport(m.encode())
	require.True(t, ok)
	assert.Equal(t, byte(usmStatsUnknownUserNames), counter)
}

// scriptedConn returns one scripted datagram per read, and a timeout for a
// nil one and once they are spent.
type scriptedConn struct {
	net.Conn
	reads [][]byte
}

func (s *scriptedConn) Read(b []byte) (int, error) {
	if len(s.reads) == 0 || s.reads[0] == nil {
		s.reads = s.reads[min(1, len(s.reads)):]
		return 0, os.ErrDeadlineExceeded
	}
	n := copy(b, s.reads[0])
	s.reads = s.reads[1:]
	return n, nil
}

// The recorder keeps the last reply, so a response after a report clears the
// report: a later failure of the same walk is not the device refusing it. A
// reply too large to be a report is not kept, a read that times out keeps the
// reply before it, and nothing is kept across walks.
func TestReplyRecorder_KeepsTheLastReply(t *testing.T) {
	report := reportOf(usmStatsWrongDigests).encode()
	timeout := walkFailure()
	buf := make([]byte, 4096)

	r := &replyRecorder{Conn: &scriptedConn{reads: [][]byte{report, nil}}}
	_, _ = r.Read(buf)
	_, err := r.Read(buf)
	require.Error(t, err)
	assert.Equal(t, gosnmp.ErrWrongDigest, r.refusal(timeout, false), "the retry timed out; the report before it stands")
	r.forget()
	assert.Equal(t, timeout, r.refusal(timeout, false), "the next walk starts with nothing")

	response := wire(t, netsnmpResponse)
	r = &replyRecorder{Conn: &scriptedConn{reads: [][]byte{report, response}}}
	_, _ = r.Read(buf)
	_, _ = r.Read(buf)
	assert.Equal(t, timeout, r.refusal(timeout, false), "a response followed the report")

	r = &replyRecorder{Conn: &scriptedConn{reads: [][]byte{report, make([]byte, maxReportSize+1)}}}
	_, _ = r.Read(buf)
	n, _ := r.Read(buf)
	require.Equal(t, maxReportSize+1, n, "the caller still gets the whole reply")
	assert.Empty(t, r.last, "a reply too large to be a report is not kept")
	assert.Equal(t, timeout, r.refusal(timeout, false))

	var none *replyRecorder
	none.forget()
	assert.Equal(t, timeout, none.refusal(timeout, false), "a client without a recorder returns its error")
}

// The counters that refuse a credential become gosnmp's errors for them. The
// two that belong to engine discovery and time synchronisation do not.
func TestReplyRecorder_RefusalMapsTheCounters(t *testing.T) {
	failed := walkFailure()
	for counter, want := range map[byte]error{
		usmStatsUnsupportedSecLevels: gosnmp.ErrUnknownSecurityLevel,
		2:                            failed, // usmStatsNotInTimeWindows
		usmStatsUnknownUserNames:     gosnmp.ErrUnknownUsername,
		usmStatsUnknownEngineIDs:     failed,
		usmStatsWrongDigests:         gosnmp.ErrWrongDigest,
		usmStatsDecryptionErrors:     gosnmp.ErrDecryption,
		7:                            failed,
	} {
		r := &replyRecorder{last: reportOf(counter).encode()}
		assert.Equal(t, want, r.refusal(failed, false), "counter %d", counter)
	}
}

// The answer to engine discovery as the last reply of a failed walk means the
// device did not answer the request. On a session that encrypts, that is what
// a wrong privacy passphrase looks like, so the error says so and still reads
// as the timeout. It says nothing on a session without privacy, or for a
// collection that was cancelled before the device could answer.
func TestReplyRecorder_NoAnswerAfterDiscovery(t *testing.T) {
	failed := walkFailure()
	discovery := reportOf(usmStatsUnknownEngineIDs).encode()

	err := (&replyRecorder{priv: true, last: discovery}).refusal(failed, false)
	var silent *NoAnswerAfterDiscoveryError
	require.ErrorAs(t, err, &silent)
	assert.Equal(t, failed.Error(), err.Error(), "it reads as the timeout")
	assert.ErrorIs(t, err, failed)

	assert.Equal(t, failed, (&replyRecorder{priv: false, last: discovery}).refusal(failed, false), "no privacy to get wrong")
	assert.Equal(t, failed, (&replyRecorder{priv: true, last: discovery}).refusal(failed, true), "cancelled, not unanswered")
	assert.Equal(t, failed, (&replyRecorder{priv: true}).refusal(failed, false), "the device answered nothing at all")
}

// walkFailure is the error of a walk that failed for a reason of its own.
func walkFailure() error { return os.ErrDeadlineExceeded }

// v3Device is an SNMPv3 device on a UDP port. It answers engine discovery as
// a device does, with its engine ID in a usmStatsUnknownEngineIDs report, and
// every later request with what reply returns for it: nothing for silence.
type v3Device struct {
	conn net.PacketConn
	port uint16
	// reply gets the count of requests since discovery, from 1, and the
	// request: its IDs and, for a plaintext GETNEXT, the OID it asks from.
	reply func(n int, msgID, requestID, oid []byte) []byte
	// mute makes it answer nothing, engine discovery included. Set before
	// the first request.
	mute atomic.Bool

	mu       sync.Mutex
	requests int
}

func newV3Device(t *testing.T, reply func(n int, msgID, requestID, oid []byte) []byte) *v3Device {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	d := &v3Device{conn: conn, port: udpPort(t, conn.LocalAddr()), reply: reply}
	go d.serve()
	t.Cleanup(func() { _ = conn.Close() })
	return d
}

func (d *v3Device) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.requests
}

func (d *v3Device) serve() {
	buf := make([]byte, 4096)
	for {
		n, addr, err := d.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		msgID, requestID, oid, discovery := readRequest(buf[:n])
		var out []byte
		if d.mute.Load() {
			continue
		}
		if discovery {
			m := reportOf(4) // usmStatsUnknownEngineIDs
			m.msgID, m.requestID, m.user = msgID, requestID, ""
			out = m.encode()
		} else {
			d.mu.Lock()
			d.requests++
			count := d.requests
			d.mu.Unlock()
			out = d.reply(count, msgID, requestID, oid)
		}
		if out != nil {
			_, _ = d.conn.WriteTo(out, addr)
		}
	}
}

// readRequest reads what the device needs of a client's message: its message
// ID and, when its PDU is plaintext, the request ID and the first OID asked
// for. discovery is true for the plaintext GetRequest with no variables that
// starts a session.
func readRequest(b []byte) (msgID, requestID, oid []byte, discovery bool) {
	const getRequest = 0xa0
	whole := ber{b: b}
	msg := ber{b: whole.next(berSequence)}
	msg.next(berInteger) // version
	header := ber{b: msg.next(berSequence)}
	msgID = header.next(berInteger)
	msg.next(berOctetString) // security parameters
	scoped := ber{b: msg.next(berSequence)}
	scoped.next(berOctetString) // contextEngineID
	scoped.next(berOctetString) // contextName
	if scoped.bad || len(scoped.b) == 0 {
		return msgID, nil, nil, false // encrypted
	}
	kind := scoped.b[0]
	pdu := ber{b: scoped.next(kind)}
	requestID = pdu.next(berInteger)
	pdu.next(berInteger)
	pdu.next(berInteger)
	bindings := ber{b: pdu.next(berSequence)}
	binding := ber{b: bindings.next(berSequence)}
	oid = binding.next(berOID)
	return msgID, requestID, oid, kind == getRequest && oid == nil
}

// v3Client dials device at the security level, with the credential the level
// needs.
func v3Client(t *testing.T, device *v3Device, retries int, level string) Walker {
	t.Helper()
	w, err := NewClient(t.Context(), "127.0.0.1", device.port, retries, 300*time.Millisecond, v3Auth(level), clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })
	return w
}

func v3Auth(level string) *config.Authentication {
	auth := &config.Authentication{ProtocolVersion: ProtocolVersion3, SecurityLevel: level, Username: "admin"}
	if level != SecurityLevelNoAuthNoPriv {
		auth.AuthProtocol, auth.AuthPassphrase = "SHA", "TESTONLY-auth-passphrase"
	}
	if level == SecurityLevelAuthPriv {
		auth.PrivProtocol, auth.PrivPassphrase = "AES", "TESTONLY-priv-passphrase"
	}
	return auth
}

const sysObjectIDRoot = "1.3.6.1.2.1.1.2"

// A device that refuses the credential of an authenticated session answers
// with a report it cannot authenticate, which gosnmp discards. The walk's
// error is the reason the device gave all the same, for each report net-snmp
// sends, so the policy can say which setting to check.
func TestClient_WalkReportsWhyTheDeviceRefusedTheCredential(t *testing.T) {
	for name, tc := range map[string]struct {
		report string
		want   error
	}{
		"wrong auth protocol or passphrase": {netsnmpWrongDigest, gosnmp.ErrWrongDigest},
		"unknown user":                      {netsnmpUnknownUser, gosnmp.ErrUnknownUsername},
		"a level the user does not have":    {netsnmpUnsupportedLevel, gosnmp.ErrUnknownSecurityLevel},
		"a request it cannot decrypt":       {netsnmpDecryption, gosnmp.ErrDecryption},
	} {
		t.Run(name, func(t *testing.T) {
			report := wire(t, tc.report)
			device := newV3Device(t, func(int, []byte, []byte, []byte) []byte { return report })

			_, err := v3Client(t, device, 0, SecurityLevelAuthPriv).Walk(sysObjectIDRoot)

			require.ErrorIs(t, err, tc.want)
			assert.NotContains(t, err.Error(), "not authentic", "gosnmp's error for the discarded report is replaced")
			assert.Equal(t, 1, device.count(), "one request, refused")
		})
	}
}

// A device may answer only the first of the attempts it refuses. The reason
// it gave stands when the retry times out.
func TestClient_WalkKeepsTheRefusalWhenTheRetryIsNotAnswered(t *testing.T) {
	report := wire(t, netsnmpWrongDigest)
	device := newV3Device(t, func(n int, _, _, _ []byte) []byte {
		if n == 1 {
			return report
		}
		return nil
	})

	_, err := v3Client(t, device, 1, SecurityLevelAuthPriv).Walk(sysObjectIDRoot)

	require.ErrorIs(t, err, gosnmp.ErrWrongDigest)
	assert.Equal(t, 2, device.count(), "the attempt and its retry")
}

// A walk's error comes from a reply to that walk. After a walk the device
// refused, a second one it does not answer reads as a timeout, not as the
// refusal of the first.
func TestClient_WalkDoesNotReportTheRefusalOfAnEarlierWalk(t *testing.T) {
	report := wire(t, netsnmpWrongDigest)
	device := newV3Device(t, func(n int, _, _, _ []byte) []byte {
		if n == 1 {
			return report
		}
		return nil
	})
	w := v3Client(t, device, 0, SecurityLevelAuthPriv)
	_, err := w.Walk(sysObjectIDRoot)
	require.ErrorIs(t, err, gosnmp.ErrWrongDigest)

	_, err = w.Walk(sysObjectIDRoot)

	require.Error(t, err)
	assert.NotErrorIs(t, err, gosnmp.ErrWrongDigest)
	assert.Contains(t, err.Error(), "request timeout")
}

// A device that answers engine discovery and then not the request, as net-snmp
// does for a wrong privacy passphrase, times out: its answer to discovery is a
// report too, and is not a refusal. On an authPriv session the error says the
// device was there, which is what tells this from a device that is not.
func TestClient_WalkSaysWhenTheDeviceAnswersDiscoveryAndNotTheRequest(t *testing.T) {
	device := newV3Device(t, func(int, []byte, []byte, []byte) []byte { return nil })

	_, err := v3Client(t, device, 0, SecurityLevelAuthPriv).Walk(sysObjectIDRoot)

	var silent *NoAnswerAfterDiscoveryError
	require.ErrorAs(t, err, &silent)
	assert.Contains(t, err.Error(), "request timeout", "it still reads as the timeout")
	for _, refusal := range []error{gosnmp.ErrWrongDigest, gosnmp.ErrUnknownUsername, gosnmp.ErrUnknownSecurityLevel, gosnmp.ErrDecryption} {
		assert.NotErrorIs(t, err, refusal)
	}
	assert.Equal(t, 1, device.count())
}

// The same silence says nothing of privacy on a session that does not encrypt,
// and a device that answers nothing at all is only a timeout.
func TestClient_WalkOnlyTimesOutWithoutPrivacyOrWithoutADevice(t *testing.T) {
	var silent *NoAnswerAfterDiscoveryError

	device := newV3Device(t, func(int, []byte, []byte, []byte) []byte { return nil })
	_, err := v3Client(t, device, 0, SecurityLevelAuthNoPriv).Walk(sysObjectIDRoot)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request timeout")
	assert.NotErrorAs(t, err, &silent, "authNoPriv has no privacy to get wrong")

	absent := newV3Device(t, nil)
	absent.mute.Store(true)
	_, err = v3Client(t, absent, 0, SecurityLevelAuthPriv).Walk(sysObjectIDRoot)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request timeout")
	assert.NotErrorAs(t, err, &silent, "the device answered nothing, discovery included")
}

// A collection cancelled while its request waits has no answer yet. That is
// the cancellation, not a device that dropped the request.
func TestClient_WalkCancelledAfterDiscoveryIsNotAHint(t *testing.T) {
	asked := make(chan struct{}, 1)
	device := newV3Device(t, func(int, []byte, []byte, []byte) []byte {
		asked <- struct{}{}
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	w, err := NewClient(ctx, "127.0.0.1", device.port, 0, 10*time.Second, v3Auth(SecurityLevelAuthPriv), clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })
	go func() {
		<-asked
		cancel()
	}()

	_, err = w.Walk(sysObjectIDRoot)

	require.Error(t, err)
	var silent *NoAnswerAfterDiscoveryError
	assert.NotErrorAs(t, err, &silent)
}

// The recorder stands between gosnmp and the socket of every SNMPv3 session,
// so a walk that succeeds has to read its replies through it unchanged.
func TestClient_V3WalkReadsItsRepliesThroughTheRecorder(t *testing.T) {
	sysObjectID := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02, 0x00}
	enterprise := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xbf, 0x08, 0x03, 0x02, 0x0a}
	device := newV3Device(t, func(n int, msgID, requestID, oid []byte) []byte {
		const getResponse, endOfMibView = 0xa2, 0x82
		m := message{version: 3, model: 3, msgID: msgID, requestID: requestID, user: "admin", pdu: getResponse}
		if n == 1 {
			m.bindings = [][]byte{tlv(berSequence, tlv(berOID, sysObjectID), tlv(berOID, enterprise))}
		} else {
			m.bindings = [][]byte{tlv(berSequence, tlv(berOID, oid), tlv(endOfMibView))}
		}
		return m.encode()
	})
	w := v3Client(t, device, 0, SecurityLevelNoAuthNoPriv)
	c, ok := w.(*Client)
	require.True(t, ok)
	require.NotNil(t, c.replies, "an SNMPv3 session over UDP has the recorder")

	got, err := w.Walk(sysObjectIDRoot)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, ".1.3.6.1.4.1.8072.3.2.10", got["."+sysObjectIDRoot+".0"].Value)
}

// SNMPv1 and v2c have no reports, so their sessions keep the socket gosnmp
// dialled.
func TestClient_V2cHasNoRecorder(t *testing.T) {
	agent := newFakeAgent(t, nil)
	w, err := NewClient(t.Context(), "127.0.0.1", agent.port, 0, 300*time.Millisecond,
		&config.Authentication{ProtocolVersion: ProtocolVersion2c, Community: "public"}, clientTestLogger)
	require.NoError(t, err)
	require.NoError(t, w.Connect())
	t.Cleanup(func() { _ = w.Close() })
	c, ok := w.(*Client)
	require.True(t, ok)
	assert.Nil(t, c.replies)
	_, isUDP := c.Conn.(*net.UDPConn)
	assert.True(t, isUDP)
}
