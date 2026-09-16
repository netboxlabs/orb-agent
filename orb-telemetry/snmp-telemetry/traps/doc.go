// Package traps receives SNMP traps on a UDP socket the package owns, identifies
// the sender against the addresses running policies name, and counts what it
// received and what it dropped.
//
// Invariant: this package never imports policy or collector, and nothing a
// trap says may trigger a poll. A trap is one-way UDP with a source address
// anyone on the path can choose. The obvious later enhancement, a linkDown
// trap prompting an immediate re-poll, would turn a spoofable packet into a
// credentialed outbound SNMP request, which the README promises the backend
// never sends to an address a policy did not name.
package traps
