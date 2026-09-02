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
	conn          *net.UDPConn
	reg           *Registry
	tally         *Tally
	names         map[string]string
	acceptUnknown bool
	logger        *slog.Logger

	params   *gosnmp.GoSNMP
	usersGen uint64

	stopOnce sync.Once
	done     chan struct{}
}

// Listen binds addr and starts reading. The bind is synchronous so a failure
// is reported to the caller rather than logged from a goroutine.
func Listen(addr string, reg *Registry, tally *Tally, names map[string]string, acceptUnknown bool, logger *slog.Logger) (*Receiver, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("trap listen address %q: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("binding trap listener on %s: %w", addr, err)
	}
	if err := conn.SetReadBuffer(4 << 20); err != nil {
		logger.Warn("Could not size the trap socket read buffer", "error", err)
	}
	r := &Receiver{
		conn:          conn,
		reg:           reg,
		tally:         tally,
		names:         names,
		acceptUnknown: acceptUnknown,
		logger:        logger,
		done:          make(chan struct{}),
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
	r.stopOnce.Do(func() {
		_ = r.conn.Close()
		select {
		case <-r.done:
		case <-time.After(stopTimeout):
			r.logger.Warn("Trap receiver did not stop within its bound", "timeout", stopTimeout)
		}
	})
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
// else, size check, parse, filter, decode, count, and acknowledge an inform
// only for a registered source. The source is first because every later drop
// reason names a fault an operator reads as their own devices'.
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
		registered := len(policies) > 0
		if !registered {
			if !r.acceptUnknown {
				r.drop(DropUnknownSource, src, "")
				continue
			}
			policies = []string{""}
		}

		if n > maxDatagram {
			r.drop(DropOversized, src, "")
			continue
		}

		r.rebuildUsersIfChanged()
		pkt, err := r.params.UnmarshalTrap(buf[:n], false)
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
		// registered sender has one to make. An unregistered sender reaching
		// here is one accept-unknown let through, and its packet must not
		// re-attribute to a device that does have a policy.
		deviceIP := src
		if registered && tr.AgentAddr.IsValid() && tr.AgentAddr != src {
			if agentPolicies := r.reg.Lookup(tr.AgentAddr); len(agentPolicies) > 0 {
				deviceIP = canonical(tr.AgentAddr)
				policies = agentPolicies
			}
		}

		name := NameFor(r.names, tr.OID)
		for _, policy := range policies {
			r.tally.Received(deviceIP.String(), policy, name, tr.Version)
		}

		if tr.Inform && registered {
			r.acknowledge(pkt, from)
		}
	}
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
