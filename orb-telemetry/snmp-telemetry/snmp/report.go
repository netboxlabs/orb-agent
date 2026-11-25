package snmp

import (
	"bytes"
	"net"

	"github.com/gosnmp/gosnmp"
)

// A device that refuses the credential of an SNMPv3 request says why in a
// Report PDU: it does not know the user, the digest is wrong, the user does
// not have the security level, or it cannot decrypt the request. It sends that
// report without authentication. RFC 3412 (7.1, step 3) gives a report the
// level noAuthNoPriv unless the security model names one, and RFC 3414 (3.2)
// names one only for a message outside the time window. gosnmp checks every
// reply of an authenticated session against the session's key before it reads
// the PDU, so it discards exactly these reports ("incoming packet is not
// authentic, discarding") and never returns the errors it defines for them.
// The client therefore keeps the last reply of a walk and, when the walk
// fails, reads the device's reason from it.
//
// Such a report is not authenticated, so whoever can send from the device's
// address can forge one. It is used for one thing, the error of a walk that
// has already failed: it never makes a request succeed, and nothing else in it
// is read or kept.
//
// One refusal has no report. A device decrypts a request sent with a wrong
// privacy passphrase into something it cannot parse and drops it (RFC 3412,
// 7.2), so the request times out. The kept reply still tells that apart from
// a device that is not there: it is the device's answer to engine discovery
// (see NoAnswerAfterDiscoveryError).

// maxReportSize bounds what the client keeps of a reply. A report carries the
// header, the security parameters and one counter, about 120 bytes with a
// short user name; a larger reply is a response with data.
const maxReportSize = 512

// replyRecorder is the connection of an SNMPv3 client over UDP. It keeps the
// last datagram read that is small enough to be a report. gosnmp reads and the
// client looks from the one goroutine that runs a walk, so nothing is locked.
type replyRecorder struct {
	net.Conn
	// priv is whether the session encrypts its requests (authPriv).
	priv bool
	last []byte
}

// Read keeps the datagram it returns. A read that returns nothing, such as a
// timeout, keeps the one before: a device that reported why it refused the
// first attempt may not answer the retry.
func (r *replyRecorder) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.last = r.last[:0]
		if n <= maxReportSize {
			r.last = append(r.last, b[:n]...)
		}
	}
	return n, err
}

// forget drops the kept reply, before a walk: only a reply to that walk says
// why it failed.
func (r *replyRecorder) forget() {
	if r != nil {
		r.last = r.last[:0]
	}
}

// refusal returns the error of a walk that failed with err: gosnmp's error for
// the reason the device reported, when the last reply is a report refusing the
// credential; a NoAnswerAfterDiscoveryError, when an authPriv session got the
// answer to engine discovery and nothing after it; and err otherwise.
// cancelled is whether the collection was cancelled, which is why such a
// request has no answer yet, and is not a hint at anything.
func (r *replyRecorder) refusal(err error, cancelled bool) error {
	if r == nil {
		return err
	}
	counter, ok := usmReport(r.last)
	if !ok {
		return err
	}
	switch counter {
	case usmStatsUnsupportedSecLevels:
		return gosnmp.ErrUnknownSecurityLevel
	case usmStatsUnknownUserNames:
		return gosnmp.ErrUnknownUsername
	case usmStatsWrongDigests:
		return gosnmp.ErrWrongDigest
	case usmStatsDecryptionErrors:
		return gosnmp.ErrDecryption
	case usmStatsUnknownEngineIDs:
		// The answer to engine discovery, which starts a session, is still
		// the last reply: the device did not answer the request itself.
		if r.priv && !cancelled {
			return &NoAnswerAfterDiscoveryError{Err: err}
		}
	}
	// usmStatsNotInTimeWindows is part of time synchronisation, which gosnmp
	// handles.
	return err
}

// NoAnswerAfterDiscoveryError is the error of a walk on an authPriv session
// whose device answered engine discovery and then did not answer the request.
// The device is there and speaks SNMPv3, and a user, digest or security level
// it refuses gets a report, so what is left is a request it dropped: as it
// does with one it decrypts into something it cannot parse, with a wrong
// privacy passphrase or protocol. A slow device or a lost reply reads the
// same, so this says what to check and proves nothing. It reads as Err, the
// timeout.
type NoAnswerAfterDiscoveryError struct{ Err error }

func (e *NoAnswerAfterDiscoveryError) Error() string { return e.Err.Error() }

// Unwrap returns the timeout.
func (e *NoAnswerAfterDiscoveryError) Unwrap() error { return e.Err }

// The counters of usmStats (1.3.6.1.6.3.15.1.1) the client reads: the four
// that refuse a credential, and the one that answers engine discovery.
const (
	usmStatsUnsupportedSecLevels = 1
	usmStatsUnknownUserNames     = 3
	usmStatsUnknownEngineIDs     = 4
	usmStatsWrongDigests         = 5
	usmStatsDecryptionErrors     = 6
)

// usmStats is the BER encoding of 1.3.6.1.6.3.15.1.1. A counter's instance
// adds the counter and a zero.
var usmStats = []byte{0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01}

// BER tags of the elements of an SNMPv3 report.
const (
	berInteger     = 0x02
	berOctetString = 0x04
	berOID         = 0x06
	berSequence    = 0x30
	berReport      = 0xa8
)

// usmReport returns the usmStats counter a datagram reports, when the datagram
// is an SNMPv3 message of the user security model, sent without authentication
// or privacy, whose PDU is a report with that counter as its only variable.
//
// It reads the datagram itself rather than through gosnmp's decoder, whose
// panics on malformed input the trap receiver already guards against: the
// bytes are a stranger's until proven otherwise, and this needs five fields.
func usmReport(datagram []byte) (counter byte, ok bool) {
	whole := ber{b: datagram}
	msg := ber{b: whole.next(berSequence)}
	version := msg.next(berInteger)
	header := ber{b: msg.next(berSequence)}
	header.next(berInteger) // msgID
	header.next(berInteger) // msgMaxSize
	flags := header.next(berOctetString)
	model := header.next(berInteger)
	msg.next(berOctetString) // msgSecurityParameters
	// An encrypted PDU is an octet string, and fails here.
	scoped := ber{b: msg.next(berSequence)}
	scoped.next(berOctetString) // contextEngineID
	scoped.next(berOctetString) // contextName
	pdu := ber{b: scoped.next(berReport)}
	pdu.next(berInteger) // request-id
	pdu.next(berInteger) // error-status
	pdu.next(berInteger) // error-index
	bindings := ber{b: pdu.next(berSequence)}
	binding := ber{b: bindings.next(berSequence)}
	oid := binding.next(berOID)

	// A failed read returns nothing, so every read after it fails too: the
	// last one answers for the chain from the message to the variable. The
	// header's fields are checked by their values.
	const authOrPriv = 0x03
	switch {
	case binding.bad, len(bindings.b) != 0:
		return 0, false
	case !bytes.Equal(version, []byte{3}), !bytes.Equal(model, []byte{3}):
		return 0, false
	case len(flags) != 1 || flags[0]&authOrPriv != 0:
		return 0, false
	case len(oid) != len(usmStats)+2 || !bytes.HasPrefix(oid, usmStats) || oid[len(oid)-1] != 0:
		return 0, false
	}
	return oid[len(usmStats)], true
}

// ber reads BER elements off the front of b. A read that fails sets bad and
// returns nothing.
type ber struct {
	b   []byte
	bad bool
}

// next returns the contents of the element at the front, which must have tag,
// and moves past it. It accepts the long form of a length, which some devices
// use where the short form would do.
func (r *ber) next(tag byte) []byte {
	if r.bad || len(r.b) < 2 || r.b[0] != tag {
		r.bad = true
		return nil
	}
	length, rest := uint64(r.b[1]), r.b[2:]
	if length >= 0x80 {
		octets := int(length & 0x7f)
		if octets == 0 || octets > 4 || len(rest) < octets {
			r.bad = true
			return nil
		}
		length = 0
		for _, o := range rest[:octets] {
			length = length<<8 | uint64(o)
		}
		rest = rest[octets:]
	}
	if length > uint64(len(rest)) {
		r.bad = true
		return nil
	}
	r.b = rest[length:]
	return rest[:length]
}
