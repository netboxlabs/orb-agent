package traps

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/snmp"
)

// maxDatagram is the largest trap the receiver reads. It matches gosnmp's own
// default buffer; a longer datagram is truncated by the kernel and would fail
// the parser's length check, so it is counted as oversized instead.
const maxDatagram = 4096

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

	stopOnce sync.Once
	done     chan struct{}
}

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
	r.rebuildUsersIfChanged()
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
		_ = r.conn.Close()
	})
}

// wait waits for the read goroutine to exit, up to its bound.
func (r *Receiver) wait() {
	select {
	case <-r.done:
	case <-time.After(stopTimeout):
		r.logger.Warn("Trap receiver did not stop within its bound", "timeout", stopTimeout)
	}
}

// rebuildUsersIfChanged refreshes gosnmp's credential table when the registry
// has changed. gosnmp's table has Add but no Remove, so it is rebuilt whole.
// Only the loop goroutine touches r.params, so this needs no lock.
func (r *Receiver) rebuildUsersIfChanged() {
	gen := r.reg.Generation()
	if r.params.TrapSecurityParametersTable != nil && gen == r.usersGen {
		return
	}
	table := gosnmp.NewSnmpV3SecurityParametersTable(r.params.Logger)
	for _, u := range r.reg.Users() {
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
	r.params.TrapSecurityParametersTable = table
	r.usersGen = gen
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
		r.tally.Datagram()
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

		r.rebuildUsersIfChanged()
		pkt, err := r.parse(buf[:n])
		if err != nil {
			r.drop(DropMalformed, src, err.Error())
			continue
		}

		tr, reason := Decode(pkt)
		if reason != "" {
			r.drop(reason, src, "")
			continue
		}

		// The agent-addr override is a claim about provenance, and only a
		// registered sender has one to make; every sender past this point
		// is one. The claim is honoured only when the named address has a
		// policy of its own.
		deviceIP := src
		if tr.AgentAddr.IsValid() && tr.AgentAddr != src {
			if agentPolicies := r.reg.Lookup(tr.AgentAddr); len(agentPolicies) > 0 {
				deviceIP = canonical(tr.AgentAddr)
				policies = agentPolicies
				// Which address a count was attributed to is the one thing an
				// operator cannot reconstruct from the exported series, since
				// the series names only the winner.
				r.logger.Debug("Attributed a trap to its agent-addr rather than its source", "source", src.String(), "agent_addr", deviceIP.String())
			}
		}

		name := NameFor(r.names, tr.OID)
		for _, policy := range policies {
			r.tally.Received(deviceIP.String(), policy, name, tr.Version)
		}

		if tr.Inform {
			r.acknowledge(pkt, from)
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

func (r *Receiver) drop(reason DropReason, src netip.Addr, detail string) {
	r.tally.Dropped(reason)
	r.logger.Debug("Dropped a trap datagram", "reason", string(reason), "source", src.String(), "registered_addresses", r.reg.Size(), "detail", detail)
}

// acknowledge answers an inform the way an agent expects, so a registered
// sender does not retransmit. The packet is reused with its PDU type and
// error fields changed, which is what gosnmp's own listener does.
func (r *Receiver) acknowledge(pkt *gosnmp.SnmpPacket, to netip.AddrPort) {
	pkt.PDUType = gosnmp.GetResponse
	pkt.Error = gosnmp.NoError
	pkt.ErrorIndex = 0
	out, err := pkt.MarshalMsg()
	if err != nil {
		r.logger.Debug("Could not build an inform acknowledgement", "error", err)
		return
	}
	if _, err := r.conn.WriteToUDPAddrPort(out, to); err != nil {
		r.logger.Debug("Could not send an inform acknowledgement", "error", err)
	}
}
