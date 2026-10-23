// Package octets renders an SNMP OCTET STRING as attribute text.
//
// An OCTET STRING is bytes. Most carry text, but many carry binary: a MAC in
// ifPhysAddress, an LLDP chassis ID or an ARP entry read without a hwaddr
// conversion. OTLP strings must be valid UTF-8, and one value that is not fails
// the marshalling of the whole export, which carries every policy of the
// process. Text renders every value as valid UTF-8.
package octets

import (
	"bytes"
	"net"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Text renders raw as attribute text:
//
//   - A value of only NUL bytes, or none, is empty. Devices answer an unset
//     string that way, such as an unconfigured ifAlias on Dell Networking OS.
//   - A value that is UTF-8 text, once NUL padding at its end is dropped, is
//     kept, trimmed of surrounding space. Text holds no control characters but
//     tab and line breaks.
//   - Anything else is binary, and reads as the colon-separated hex of every
//     byte: Hex(raw), what a hwaddr conversion renders for a MAC. Two binary
//     values therefore never read alike.
//
// A value is text or binary as a whole, decided on its bytes before any
// trimming, so trimming never makes two binary values alike. Text that is not
// UTF-8, such as Latin-1, reads as hex: a test over the LibreNMS recordings
// found one Latin-1 text among about 6,600 binary values whose bytes are all
// printable Latin-1, a sixth of the MACs, which decoding would render as
// letters.
//
// A binary value whose bytes all happen to be printable ASCII reads as that
// text. Nothing in the bytes tells it apart, so a column that holds MACs needs
// a hwaddr conversion in its profile to always read as a MAC.
func Text(raw []byte) string {
	trimmed := bytes.TrimRight(raw, "\x00")
	if len(trimmed) == 0 {
		return ""
	}
	if utf8.Valid(trimmed) && !bytes.ContainsFunc(trimmed, isControl) {
		return strings.TrimSpace(string(trimmed))
	}
	return Hex(raw)
}

// Hex renders every byte of raw as two hex digits, separated by colons, the
// way net.HardwareAddr renders a MAC. It is one-to-one: two different values
// never render alike.
func Hex(raw []byte) string {
	return net.HardwareAddr(raw).String()
}

// isControl reports a control character other than the tab and line breaks
// text can carry. U+0080 to U+009F are C1 controls and count too.
func isControl(r rune) bool {
	return unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r'
}
