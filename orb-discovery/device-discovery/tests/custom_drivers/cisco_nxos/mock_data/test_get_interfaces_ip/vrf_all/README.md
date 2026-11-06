# NX-OS scenario: addresses in every VRF (NX-API)

`show_ip_interface_vrf_all.json` and `show_ipv6_interface_vrf_all.json` follow the shape of the
NX-API replies to `show ip interface vrf all` and `show ipv6 interface vrf all` from a Nexus
3064PQ (N3K-C3064PQ) running NX-OS 9.3(9): one `TABLE_intf` object whose `ROW_intf` lists the
interfaces of every VRF, and no `TABLE_vrf`. Rows carry the keys napalm reads plus a few of the
switch's own; interfaces sit in the default VRF, in two other VRFs and in `management`. Names
are invented, and addresses are from the documentation ranges (RFC 5737, RFC 3849).

It pins that `get_interfaces_ip()` returns the addresses of every VRF. napalm sends
`show ip interface` without a VRF, which NX-OS answers for the default VRF only, so with
napalm's command alone this scenario would return nothing.
