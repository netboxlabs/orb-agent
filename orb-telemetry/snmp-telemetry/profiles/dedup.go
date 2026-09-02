package profiles

import (
	"log/slog"

	"github.com/netboxlabs/orb-agent/orb-telemetry/snmp-telemetry/config"
)

// symbolRef locates one symbol inside a resolved profile's metric entries.
type symbolRef struct {
	entry int
	// index is -1 for the entry's own `symbol:`, and otherwise a position in
	// its `symbols:` list.
	index int
}

// get returns the symbol the ref points at.
func (r symbolRef) get(p *Profile) *Symbol {
	e := &p.Metrics[r.entry]
	if r.index < 0 {
		return e.Symbol
	}
	return &e.Symbols[r.index]
}

// symbolRefs returns every symbol a resolved profile declares, in declaration
// order: each entry's `symbol:` first, then the members of its `symbols:`.
func symbolRefs(p *Profile) []symbolRef {
	var out []symbolRef
	for i := range p.Metrics {
		if p.Metrics[i].Symbol != nil {
			out = append(out, symbolRef{entry: i, index: -1})
		}
		for j := range p.Metrics[i].Symbols {
			out = append(out, symbolRef{entry: i, index: j})
		}
	}
	return out
}

// Precedence is one declaration's standing when two of them claim a single
// metric name: whether the profile inherited the entry the symbol sits in, and
// the OID the symbol names.
//
// The name contest reads it to decide which declaration keeps the name. The
// collector reads it as well, to decide which declaration's observation a row
// keeps when two declarations retained by `allow_duplicate: true` both answer
// for that row. One type serves both so the two cannot come to disagree about
// which of two declarations is the more specific.
type Precedence struct {
	fromExtended bool
	oid          string
}

// SymbolPrecedence returns the standing of one symbol declared in entry.
func SymbolPrecedence(entry *MetricEntry, sym *Symbol) Precedence {
	return Precedence{fromExtended: entry.FromExtended, oid: sym.OID}
}

// Beats reports whether p outranks other.
//
// The rule is upstream's. A symbol the profile declares itself beats one it
// inherited through `extends:`, on the reading that a profile naming a device
// knows better than the base profile it extends. Where that does not separate
// them the longer OID wins, which is how a fully qualified instance beats the
// column it sits in and how a more specific table beats a general one.
//
// Two declarations neither rule separates report false, leaving the caller to
// break the tie by declaration order. Deciding it here on anything else would
// have to read the map the caller holds them in, and map order differs from one
// process to the next.
func (p Precedence) Beats(other Precedence) bool {
	switch {
	case other.fromExtended && !p.fromExtended:
		return true
	case p.fromExtended && !other.fromExtended:
		return false
	default:
		return len(p.oid) > len(other.oid)
	}
}

// duplicateLosers returns the symbols that lose a contest for their metric
// name, and the symbol that beat each of them.
//
// Precedence.Beats holds the rule, and the first declared symbol keeps the name
// where it does not separate two of them. A symbol declaring
// `allow_duplicate: true` is never a loser, though it still takes part in the
// contest and can still beat another symbol.
//
// A symbol whose ExportName is empty is never a loser. It names no metric, so
// there is no series for a second symbol to take from it, and one bundled
// profile declares such a symbol beside a real one.
//
// The contest is held on Symbol.MetricName, which is what the collector exports
// under, rather than on the name as written. Two symbols spelling one name in
// two cases are one series, so they contest it.
func duplicateLosers(p *Profile, refs []symbolRef) map[symbolRef]symbolRef {
	holder := make(map[string]int, len(refs))
	for i, r := range refs {
		sym := r.get(p)
		name := sym.MetricName()
		held, seen := holder[name]
		if !seen {
			holder[name] = i
			continue
		}
		heldRef := refs[held]
		this := SymbolPrecedence(&p.Metrics[r.entry], sym)
		if this.Beats(SymbolPrecedence(&p.Metrics[heldRef.entry], heldRef.get(p))) {
			holder[name] = i
		}
	}

	winners := make(map[int]bool, len(holder))
	for _, i := range holder {
		winners[i] = true
	}
	losers := make(map[symbolRef]symbolRef)
	for i, r := range refs {
		sym := r.get(p)
		if winners[i] || sym.AllowDup || sym.ExportName() == "" {
			continue
		}
		losers[r] = refs[holder[sym.MetricName()]]
	}
	return losers
}

// pruneDuplicates returns p with the symbols that lose a metric name contest
// removed, or p itself when no two symbols claim one name.
//
// Two symbols resolving to one metric name and one attribute set are one
// exported series carrying whichever value was written last, so one of them is
// dropped rather than left to overwrite the other.
//
// Two details differ from upstream, and neither changes the outcome for any
// bundled profile:
//
//   - Upstream holds device metrics and interface metrics in separate maps and
//     contests each on its own. This collector writes both into one metric
//     namespace, where a name shared across that boundary is still one series,
//     so it holds a single contest. No bundled collision straddles the
//     boundary.
//   - Upstream contests the name as written. This collector lowercases it to
//     build the metric name, so the contest reads the lowercased name and two
//     spellings of one name meet. No bundled profile writes one name twice.
//   - Upstream keys its symbols by OID, so two symbols that neither rule
//     separates are decided by map iteration order and the loser differs from
//     one process to the next. The first declared wins here instead, so a
//     device exports the same series across restarts.
//
// An entry whose every symbol lost is dropped whole. What remains of it names
// tag columns for a metric nothing collects, and walking those columns would
// cost a request per poll and produce no point.
func pruneDuplicates(p *Profile, logger *slog.Logger) *Profile {
	refs := symbolRefs(p)
	losers := duplicateLosers(p, refs)
	if len(losers) == 0 {
		return p
	}
	// Reported in declaration order rather than by ranging the map, so two runs
	// over one profile log the same lines in the same order.
	for _, ref := range refs {
		winner, lost := losers[ref]
		if !lost {
			continue
		}
		dropped, kept := ref.get(p), winner.get(p)
		logger.Debug("SNMP profile declares one metric name twice, dropping the losing symbol",
			"metric_name", config.SanitizeLogValue(dropped.MetricName()),
			"dropped_symbol", config.SanitizeLogValue(dropped.Name),
			"dropped_oid", config.SanitizeLogValue(dropped.OID),
			"kept_symbol", config.SanitizeLogValue(kept.Name),
			"kept_oid", config.SanitizeLogValue(kept.OID),
			"file", config.SanitizeLogValue(p.RelPath))
	}

	out := *p
	out.Metrics = make([]MetricEntry, 0, len(p.Metrics))
	for i := range p.Metrics {
		e := p.Metrics[i]
		declared := e.Symbol != nil || len(e.Symbols) > 0
		if _, lost := losers[symbolRef{entry: i, index: -1}]; lost {
			e.Symbol = nil
		}
		if len(e.Symbols) > 0 {
			kept := make([]Symbol, 0, len(e.Symbols))
			for j := range e.Symbols {
				if _, lost := losers[symbolRef{entry: i, index: j}]; lost {
					continue
				}
				kept = append(kept, e.Symbols[j])
			}
			e.Symbols = kept
		}
		if declared && e.Symbol == nil && len(e.Symbols) == 0 {
			continue
		}
		out.Metrics = append(out.Metrics, e)
	}
	return &out
}
