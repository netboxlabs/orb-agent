package policy

import (
	"strings"

	"github.com/Ullaakut/nmap/v3"
	"github.com/netboxlabs/diode-sdk-go/diode"

	"github.com/netboxlabs/orb-agent/orb-discovery/network-discovery/config"
)

// maxDNSNameLength is the length of NetBox's dns_name field.
const maxDNSNameLength = 255

// dnsName returns the form of a reverse-lookup name that NetBox accepts as
// an IP address's dns_name, and false when the name has none.
//
// NetBox allows letters, digits, hyphens and underscores in a label. nmap,
// which does the lookup, prints an asterisk in place of any character it
// will not pass, a space in a DNS label for one, and lets a few others
// through that NetBox does not, so every such character becomes a hyphen.
// nmap's asterisk never means a wildcard, so it is not kept as one. The name
// is lowercased, as it always was. A name with an empty label, longer than
// the field with its trailing dot, or left with no letter or digit is
// refused rather than guessed at.
// nmap passes only ASCII, so an internationalised label never arrives.
func dnsName(name string) (string, bool) {
	name = strings.ToLower(name)
	trailingDot := strings.HasSuffix(name, ".") && len(name) > 1
	if trailingDot {
		name = strings.TrimSuffix(name, ".")
	}
	if name == "" {
		return "", false
	}
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if label == "" {
			return "", false
		}
		labels[i] = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, label)
	}
	out := strings.Join(labels, ".")
	if trailingDot {
		out += "."
	}
	if len(out) > maxDNSNameLength || !strings.ContainsFunc(out, func(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }) {
		return "", false
	}
	return out, true
}

// hostnameOutcome says what became of a host's reverse-lookup name.
type hostnameOutcome int

const (
	hostnameNone      hostnameOutcome = iota // the host had no name
	hostnameUnchanged                        // the name went out as nmap gave it, lowercased
	hostnameReplaced                         // characters NetBox rejects became hyphens
	hostnameRefused                          // the name had no acceptable form and was left off
)

// applyHostname sets the IP's dns_name from the host's reverse lookup,
// preferring a PTR record and otherwise the last name nmap listed. When the
// name used had to change or could not be used, and the comments are the
// backend's to write, it returns that name as nmap gave it for the IP's
// comments, so the original is not lost; a name that needed no change
// returns nothing, and the comments of every IP already in NetBox stay as
// they are.
func (r *Runner) applyHostname(ip *diode.IPAddress, hostnames []nmap.Hostname, addr, policyName string, canRecord bool) (hostnameOutcome, []config.Hostname) {
	var chosen nmap.Hostname
	for _, hostname := range hostnames {
		chosen = hostname
		if hostname.Type == "PTR" {
			break
		}
	}
	if chosen.Name == "" {
		return hostnameNone, nil
	}
	name, ok := dnsName(chosen.Name)
	outcome := hostnameRefused
	if ok {
		ip.DnsName = diode.String(name)
		if name == strings.ToLower(chosen.Name) {
			return hostnameUnchanged, nil
		}
		outcome = hostnameReplaced
	}
	switch {
	case !ok:
		r.logger.Warn("reverse hostname has no form NetBox accepts as dns_name; left off", "hostname", chosen.Name, "ip_address", addr, "policy", policyName)
	case canRecord:
		r.logger.Debug("reverse hostname carried characters NetBox does not accept as dns_name; replaced, original kept in comments", "hostname", chosen.Name, "dns_name", name, "ip_address", addr, "policy", policyName)
	default:
		r.logger.Warn("reverse hostname carried characters NetBox does not accept as dns_name; replaced, and the policy's comments leave no room for the original", "hostname", chosen.Name, "dns_name", name, "ip_address", addr, "policy", policyName)
	}
	if !canRecord {
		return outcome, nil
	}
	return outcome, []config.Hostname{{Name: chosen.Name, Type: chosen.Type}}
}
