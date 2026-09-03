package traps

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// maxDatagram is the largest trap the receiver reads. It matches gosnmp's own
// default buffer; a longer datagram is truncated by the kernel and would fail
// the parser's length check, so it is counted as oversized instead.
const maxDatagram = 4096

// ackTimeout bounds the write of an inform acknowledgement, which runs
// inside the intake section a close waits for.
const ackTimeout = 100 * time.Millisecond

// stopTimeout bounds how long Stop waits for the read goroutine. gosnmp's
// listener waits three seconds, which spent out of the agent's five second
// stop grace would starve the final export.
const stopTimeout = 250 * time.Millisecond

// Receiver owns the UDP socket and the one goroutine that reads it.
//
// It does not use gosnmp.TrapListener. That wrapper parses every datagram
// before the handler sees it, so no source check can run ahead of the cost of
// parsing (F5); it acknowledges every inform after the handler returns
// regardless of what the handler decided (F4); and it hides the connection,
// so the read buffer cannot be sized or its loss observed. What it provides
// beyond that is a hundred lines of bind and loop, which live here instead.
// gosnmp still does every byte of the decoding through UnmarshalTrap.
type Receiver struct {
	conn   *net.UDPConn
	reg    *Registry
	tally  *Tally
	names  map[string]string
	logger *slog.Logger

	params   *gosnmp.GoSNMP
	usersGen uint64
	// tables caches one credential table per distinct set of users, keyed
	// by their contents, and sourceKeys caches each source's key, so a
	// source's user set is resolved once per registry generation rather
	// than per datagram; both reset when the registry changes. Only the
	// loop goroutine touches them. builds and resolutions are test counters.
	tables     map[string]*gosnmp.SnmpV3SecurityParametersTable
	sourceKeys map[netip.Addr]string
	// statsMu guards the test counters and the cache sizes, which a test
	// reads from its own goroutine.
	statsMu     sync.Mutex
	builds      int
	resolutions int
	clocks      *timeliness

	stopOnce sync.Once
	done     chan struct{}
	// intakeMu guards every call into the tally against close: close takes
	// it for writing and sets stopped, so once close has returned no count
	// or drop can land, even from a read whose parse outlasted the stop
	// bound. Shutdown relies on that to run the final export after Close.
	intakeMu sync.RWMutex
	stopped  bool

	// beforeCount, when set, runs after a datagram is parsed and before the
	// policies it is counted under are resolved. Tests use it to change the
	// registry in that window, from their own goroutine, hence the atomic;
	// it is nil otherwise.
	beforeCount atomic.Pointer[func()]
	// duringCount, when set, runs inside the claims visit, with the registry
	// read-locked, before the first count. Tests use it to race a release
	// against the count from another goroutine; it is nil otherwise.
	duringCount atomic.Pointer[func()]
}

// setBeforeCount is a test seam. A nil f clears it.
func (r *Receiver) setBeforeCount(f func()) {
	if f == nil {
		r.beforeCount.Store(nil)
		return
	}
	r.beforeCount.Store(&f)
}

// setDuringCount is a test seam.
func (r *Receiver) setDuringCount(f func()) { r.duringCount.Store(&f) }

// Listen binds addr and starts reading. The bind is synchronous so a failure
// is reported to the caller rather than logged from a goroutine.
func Listen(addr string, reg *Registry, tally *Tally, names map[string]string, logger *slog.Logger) (*Receiver, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("trap listen address %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("binding trap socket %s: %w", addr, err)
	}
	if err := conn.SetReadBuffer(4 << 20); err != nil {
		logger.Warn("Could not size the trap socket read buffer", "error", err)
	}
	r := &Receiver{
		conn:   conn,
		reg:    reg,
		tally:  tally,
		names:  names,
		logger: logger,
		done:   make(chan struct{}),
		clocks: newTimeliness(time.Now),
	}
	r.params = &gosnmp.GoSNMP{
		// Version3 with the user security model is what lets UnmarshalTrap
		// take a v3 packet at all; v1 and v2c parse regardless (F2). Which
		// versions are then accepted is decided by Decode, not here.
		Version:       gosnmp.Version3,
		SecurityModel: gosnmp.UserSecurityModel,
		// No logger: gosnmp's would format every message before any level
		// filter, at a pace strangers set, and a trap has no per-device
		// community to redact.
		Logger: gosnmp.NewLogger(nil),
	}
	go r.loop()
	return r, nil
}

// Addr is the bound address, useful when the port was chosen by the kernel.
func (r *Receiver) Addr() netip.AddrPort {
	return r.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// Stop closes the socket and waits briefly for the loop to exit.
func (r *Receiver) Stop() {
	r.close()
	r.wait()
}

// close closes the socket, which is what ends the read loop, and does nothing
// on a second call. It is separate from the wait so a caller holding its own
// lock can close under it: while this socket is open, another bind of the
// same address fails, and the wait below is far too long to hold a lock for.
func (r *Receiver) close() {
	r.stopOnce.Do(func() {
		r.intakeMu.Lock()
		r.stopped = true
		r.intakeMu.Unlock()
		_ = r.conn.Close()
	})
}

// intake runs fn, which touches the tally, unless the receiver has been
// closed, and reports whether it ran.
func (r *Receiver) intake(fn func()) bool {
	r.intakeMu.RLock()
	defer r.intakeMu.RUnlock()
	if r.stopped {
		return false
	}
	fn()
	return true
}

// wait waits for the read goroutine to exit, up to its bound.
func (r *Receiver) wait() {
	expired := make(chan struct{})
	timer := time.AfterFunc(stopTimeout, func() { close(expired) })
	defer timer.Stop()
	r.waitUntil(expired)
}

// waitUntil waits for the read goroutine to exit or expired to close,
// whichever is first, so a pool can wait for every receiver under one
// deadline: a closed channel is observed by every waiter, where a timer's
// channel would be drained by the first.
func (r *Receiver) waitUntil(expired <-chan struct{}) {
	select {
	case <-r.done:
	case <-expired:
		r.logger.Warn("Trap receiver did not stop within its bound", "timeout", stopTimeout)
	}
}

// tableFor returns gosnmp's credential table for a datagram from src: the v3
// users the claiming policies poll that device with, and no others. gosnmp
// keys its table by username and tries every entry under a name in turn,
// localising keys for each, so a wider table would both let another
// device's credential vouch for this source and cost the receive goroutine
// one localisation per candidate. Tables are cached per distinct user set
// and rebuilt whole when the registry changes, since gosnmp's table has Add
// but no Remove. Only the loop goroutine touches r.params and the cache, so
// this needs no lock.
func (r *Receiver) tableFor(src netip.Addr) *gosnmp.SnmpV3SecurityParametersTable {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	if gen := r.reg.Generation(); r.tables == nil || gen != r.usersGen {
		r.tables = make(map[string]*gosnmp.SnmpV3SecurityParametersTable)
		r.sourceKeys = make(map[netip.Addr]string)
		r.usersGen = gen
	}
	key, known := r.sourceKeys[src]
	var users []V3User
	if !known {
		users = r.reg.UsersAt(src)
		key = userSetKey(users)
		r.sourceKeys[src] = key
		r.resolutions++
	}
	if table, ok := r.tables[key]; ok {
		return table
	}
	if known {
		users = r.reg.UsersAt(src)
	}
	r.builds++
	table := gosnmp.NewSnmpV3SecurityParametersTable(r.params.Logger)
	for _, u := range users {
		authProto, err := snmp.AuthProtocol(u.AuthProtocol)
		if err != nil {
			r.logger.Warn("Skipping a trap v3 user with an unsupported auth protocol", "username", u.Username, "error", err)
			continue
		}
		privProto, err := snmp.PrivProtocol(u.PrivProtocol)
		if err != nil {
			r.logger.Warn("Skipping a trap v3 user with an unsupported priv protocol", "username", u.Username, "error", err)
			continue
		}
		sp := &gosnmp.UsmSecurityParameters{
			UserName:                 u.Username,
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: u.AuthPassphrase,
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        u.PrivPassphrase,
			Logger:                   r.params.Logger,
		}
		if err := table.Add(u.Username, sp); err != nil {
			r.logger.Warn("Could not add a trap v3 user", "username", u.Username, "error", err)
		}
	}
	r.tables[key] = table
	return table
}

// Test accessors, read under statsMu.
func (r *Receiver) tableCacheSize() int {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return len(r.tables)
}

func (r *Receiver) tableBuilds() int {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.builds
}

func (r *Receiver) userSetResolutions() int {
	r.statsMu.Lock()
	defer r.statsMu.Unlock()
	return r.resolutions
}

// wireVersion reads the SNMP version integer off the first bytes of a
// datagram: the outer SEQUENCE header, then an INTEGER of one byte. It is
// what decides whether a credential table is needed at all, since only a v3
// datagram is authenticated, and it costs nothing a parse would not.
func wireVersion(b []byte) (int, bool) {
	if len(b) < 2 || b[0] != 0x30 {
		return 0, false
	}
	i := 2
	if b[1]&0x80 != 0 {
		i += int(b[1] & 0x7f)
	}
	if len(b) < i+3 || b[i] != 0x02 || b[i+1] != 0x01 {
		return 0, false
	}
	return int(b[i+2]), true
}

// loop is the receive path, in the order the spec's section 6.2 gives: read,
// canonicalise, look the source up before the datagram is judged on anything
// else, size check, parse, filter, decode, count, and acknowledge an inform.
// The source is first because every later drop reason names a fault an
// operator reads as their own devices', and because every sender that
// reaches those later steps is one a policy has already claimed.
func (r *Receiver) loop() {
	defer close(r.done)
	buf := make([]byte, maxDatagram+1)
	for {
		n, from, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			r.logger.Debug("Trap socket read failed", "error", err)
			continue
		}
		src := canonical(from.Addr())

		policies := r.reg.Lookup(src)
		if len(policies) == 0 {
			r.drop(DropUnknownSource, src, "")
			continue
		}

		if n > maxDatagram {
			r.drop(DropOversized, src, "")
			continue
		}

		// Only a v3 datagram is authenticated, so only a v3 datagram gets
		// the source's credential table; a v1 or v2c one pays nothing for
		// the credentials its source carries. A datagram whose version
		// cannot be read gets the table and lets the parser judge it.
		r.params.TrapSecurityParametersTable = nil
		if v, ok := wireVersion(buf[:n]); !ok || v == int(gosnmp.Version3) {
			r.params.TrapSecurityParametersTable = r.tableFor(src)
		}
		pkt, err := r.parse(buf[:n])
		if err != nil {
			r.drop(DropMalformed, src, parseErrorCategory(err))
			continue
		}

		tr, reason := Decode(pkt)
		if reason != "" {
			r.drop(reason, src, "")
			continue
		}
		// Decode has established that a v3 trap carries USM parameters and a
		// verified digest, so the boots and time in them are the engine's
		// own word; what remains is whether that word is current. The clock
		// is kept per sender, per credential and per engine ID: a device
		// writing another device's engine ID with higher boots, authenticated
		// with its own credential, poisons only the clock that credential is
		// judged by, and two credentials at one address are two principals.
		if tr.Version == V3 {
			sp := pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters)
			if !r.clocks.check(clockKey(src, sp, pkt.MsgFlags), sp.AuthoritativeEngineBoots, sp.AuthoritativeEngineTime) {
				r.drop(DropV3NotInTimeWindow, src, "")
				continue
			}
		}

		if hook := r.beforeCount.Load(); hook != nil {
			(*hook)()
		}

		// The policies a trap is counted under are resolved now, not from
		// the lookup that admitted the datagram: a policy released while
		// the datagram was being parsed must not be counted, and one that
		// replaced it under the same name gets the count only if it claims
		// the device. For a v3 trap only the policies holding the credential
		// that verified it qualify; every user at the address was handed to
		// the parser together, and the parser reports which one matched.
		var holding func(V3User) bool
		if tr.Version == V3 {
			holding = credentialMatcher(pkt.SecurityParameters.(*gosnmp.UsmSecurityParameters), pkt.MsgFlags)
		}

		// The agent-addr override is a claim about provenance, and only a
		// registered sender has one to make; every sender past this point
		// is one. The claim is honoured only when the named address has a
		// policy of its own.
		deviceIP := src
		if tr.AgentAddr.IsValid() && tr.AgentAddr != src && len(r.reg.PoliciesAt(tr.AgentAddr, holding)) > 0 {
			deviceIP = canonical(tr.AgentAddr)
			// Which address a count was attributed to is the one thing an
			// operator cannot reconstruct from the exported series, since
			// the series names only the winner.
			r.logger.Debug("Attributed a trap to its agent-addr rather than its source", "source", src.String(), "agent_addr", deviceIP.String())
		}

		// Each policy names the trap from its own profile set, so two
		// policies on one socket can count one OID under two names; a policy
		// that registered no names uses the socket's. The visit counts under
		// the registry's read lock, so the claims a count is attributed
		// under are the claims at the moment it lands.
		// One intake section decides the datagram's whole outcome: the
		// datagram counter, the counts, and the drop when there is one, so
		// a close arriving meanwhile waits for all of it and the final
		// export never holds a datagram without an outcome. series_limit is
		// a datagram outcome: one drop, and only when no claiming policy
		// could count the trap.
		first := true
		claimed, counted := 0, 0
		var dropped DropReason
		ran := r.intake(func() {
			r.tally.Account(func(a *Account) {
				a.Datagram()
				claimed = r.reg.VisitClaims(deviceIP, holding, func(policy string, names map[string]string) {
					if first {
						first = false
						if hook := r.duringCount.Load(); hook != nil {
							(*hook)()
						}
					}
					if names == nil {
						names = r.names
					}
					if a.Received(deviceIP.String(), policy, NameFor(names, tr.OID), tr.Version) {
						counted++
					}
				})
				switch {
				case claimed == 0:
					dropped = DropUnknownSource
				case counted == 0:
					dropped = DropSeriesLimit
				}
				if dropped != "" {
					a.Dropped(dropped)
				}
			})
			// An inform that parsed and was attributed is acknowledged
			// whether or not a series could be allocated for it: the limit
			// is the tally's, not the device's, and an unacknowledged inform
			// is sent again. It is acknowledged inside the intake section
			// that counted it, so a close cannot land between the two and
			// have the device retransmit an inform already counted.
			if tr.Inform && dropped != DropUnknownSource {
				r.acknowledge(pkt, from)
			}
		})
		if !ran {
			continue
		}
		if dropped != "" {
			r.logDrop(dropped, src, "")
		}
	}
}

// parse hands the datagram to gosnmp and turns a panic in it into an error.
//
// The spec says the receive goroutine recovers nothing, and that stays true of
// this package's own code: a panic there is a bug, and a process that carries
// on with a dead receiver hides it. A panic inside a vendored ASN.1 parser fed
// bytes a stranger chose is a different thing, and the two do not share a
// policy. F16: gosnmp blanks the authentication parameters in place with an
// unchecked copy(packet[cursor+2:cursor+len(mac)], ...) (v3_usm.go:1059) as
// soon as the auth bit is set and the named user has a real auth protocol, so
// a datagram that ends before the digest is wide enough panics. Without this
// the socket is a remote kill switch. The recover is this narrow on purpose:
// it wraps the third-party call and nothing else, so nothing here is caught.
func (r *Receiver) parse(b []byte) (pkt *gosnmp.SnmpPacket, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			pkt, err = nil, fmt.Errorf("panic in the SNMP parser: %v", rec)
		}
	}()
	return r.params.UnmarshalTrap(b, false)
}

// privacyVerified reports whether a message at these flags proved a privacy
// key: only an authPriv message did. An authNoPriv message carries and
// verifies nothing about privacy, so two credentials differing only in
// privacy settings are the same principal to it.
func privacyVerified(flags gosnmp.SnmpV3MsgFlags) bool {
	return flags&gosnmp.AuthPriv == gosnmp.AuthPriv
}

// clockKey names the clock a v3 message is judged by: the sender's address,
// the credential that verified it, and the engine ID it carries. The
// credential is identified by the fields the message's security level
// verified: username, auth protocol and passphrase always, the privacy
// fields only for an authPriv message.
func clockKey(src netip.Addr, sp *gosnmp.UsmSecurityParameters, flags gosnmp.SnmpV3MsgFlags) clockID {
	id := clockID{
		src:       src,
		user:      sp.UserName,
		authPass:  sp.AuthenticationPassphrase,
		authProto: sp.AuthenticationProtocol,
		engineID:  sp.AuthoritativeEngineID,
	}
	if privacyVerified(flags) {
		id.privPass, id.privProto = sp.PrivacyPassphrase, sp.PrivacyProtocol
	}
	return id
}

// userSetKey identifies a set of users for the credential-table cache. Every
// field is length-prefixed, so no operator-chosen value can act as a field
// boundary and make two user sets one table.
func userSetKey(users []V3User) string {
	var key strings.Builder
	for _, u := range users {
		for _, field := range []string{u.Username, u.AuthProtocol, u.AuthPassphrase, u.PrivProtocol, u.PrivPassphrase} {
			key.WriteString(strconv.Itoa(len(field)))
			key.WriteByte(':')
			key.WriteString(field)
		}
		key.WriteByte(';')
	}
	return key.String()
}

// credentialMatcher reports whether a registered user is a credential the
// parser verified a packet with. gosnmp returns the table entry it matched
// as the packet's security parameters, passphrases and protocols included,
// so the comparison is on the fields the packet's security level actually
// verified: username, auth protocol and auth passphrase always, and the
// privacy protocol and passphrase only for an authPriv packet. An authNoPriv
// packet proves nothing about privacy, and gosnmp returns whichever
// same-auth entry it tried first, so two users differing only in privacy
// settings both verified it and both count.
func credentialMatcher(sp *gosnmp.UsmSecurityParameters, flags gosnmp.SnmpV3MsgFlags) func(V3User) bool {
	return func(u V3User) bool {
		if u.Username != sp.UserName || u.AuthPassphrase != sp.AuthenticationPassphrase {
			return false
		}
		authProto, err := snmp.AuthProtocol(u.AuthProtocol)
		if err != nil || authProto != sp.AuthenticationProtocol {
			return false
		}
		if !privacyVerified(flags) {
			return true
		}
		privProto, err := snmp.PrivProtocol(u.PrivProtocol)
		return err == nil && privProto == sp.PrivacyProtocol && u.PrivPassphrase == sp.PrivacyPassphrase
	}
}

// parseErrorCategory keeps the part of a parse error that names the fault and
// drops the part that quotes the packet. gosnmp reports a malformed message
// by appending the bytes it could not parse, and in a v1 or v2c message those
// begin at or just after the community, which is the polling credential more
// often than not. The poller redacts the community it knows from such errors;
// the receiver knows no community, so it keeps the category alone, which is
// everything before the first colon or parenthesis: the stage that failed
// and what it expected.
func parseErrorCategory(err error) string {
	s := err.Error()
	if i := strings.IndexAny(s, ":("); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// drop records a datagram and its drop reason together, so the datagram
// counter never runs ahead of the outcomes.
func (r *Receiver) drop(reason DropReason, src netip.Addr, detail string) {
	if !r.intake(func() { r.tally.Account(func(a *Account) { a.Datagram(); a.Dropped(reason) }) }) {
		return
	}
	r.logDrop(reason, src, detail)
}

func (r *Receiver) logDrop(reason DropReason, src netip.Addr, detail string) {
	r.logger.Debug("Dropped a trap datagram", "reason", string(reason), "source", src.String(), "registered_addresses", r.reg.Size(), "detail", detail)
}

// acknowledge answers an inform the way an agent expects, so a registered
// sender does not retransmit. The packet is reused with its PDU type and
// error fields changed, which is what gosnmp's own listener does.
//
// The write runs inside the intake section, which close waits for, so it
// carries a deadline: a UDP send blocks only when the local send buffer is
// full, but a shutdown must not wait behind it.
func (r *Receiver) acknowledge(pkt *gosnmp.SnmpPacket, to netip.AddrPort) {
	pkt.PDUType = gosnmp.GetResponse
	pkt.Error = gosnmp.NoError
	pkt.ErrorIndex = 0
	out, err := pkt.MarshalMsg()
	if err != nil {
		r.logger.Debug("Could not build an inform acknowledgement", "error", err)
		return
	}
	if err := r.conn.SetWriteDeadline(time.Now().Add(ackTimeout)); err != nil {
		r.logger.Debug("Could not bound an inform acknowledgement", "error", err)
		return
	}
	if _, err := r.conn.WriteToUDPAddrPort(out, to); err != nil {
		r.logger.Debug("Could not send an inform acknowledgement", "error", err)
	}
}
