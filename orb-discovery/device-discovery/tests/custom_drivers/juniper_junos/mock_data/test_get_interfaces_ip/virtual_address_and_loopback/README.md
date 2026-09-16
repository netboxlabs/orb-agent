# Junos interface IP scenario: virtual address beside a loopback

`get-interface-information.xml` is a terse reply carrying two shapes that matter
together: an interface with a maskless virtual address next to a real address
that has a mask, and a loopback whose address is also maskless. Upstream NAPALM
turns both maskless values into a host length, which is what makes the
distinction between them load-bearing.

`get-vrrp-information.xml` follows the element names and hierarchy that two
independent public sources agree on: `vrrp-information` / `vrrp-interface` with
`interface`, `group`, `local-interface-address` and `virtual-ip-address`. One is
an open-source NETCONF integration log, the other is the `junos_exporter`
project, which unmarshals exactly those fields. Juniper's own `show vrrp`
reference defines the two address roles the names correspond to: the local
interface address and the configured virtual address.

**This is public corroboration of the shape, not a capture from a device.** The
full published reply comes from a NETCONF mock environment, so it establishes
that these element names are a recognised Junos integration shape without
proving that every platform and release emits exactly this XML. The parser
therefore still fails closed on anything it does not recognise: an address with
no role and no matching name is left alone rather than suppressed.

Addresses use the documentation ranges from RFC 5737. Recording the model and
Junos version here is worth doing if a genuine device capture ever replaces
this file.
