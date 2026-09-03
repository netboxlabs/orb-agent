# FortiOS 7.4.12, device capture

`get system interface` from the FortiGate-100F in netboxlabs/orb-agent#537, supplied by
the reporter after the fix shipped. All 25 rows, with the field order and the trailing
whitespace the device printed.

Sanitised:

- The reporter redacted eight addresses to `x.x.x.x`, which is not parseable. Replaced
  with private and RFC 5737 documentation addresses, keeping the four-octet shape and
  the netmask beside it. `dmz` and `mgmt` were given the addresses the physical capture
  in the sibling scenario shows for the same interfaces.
- Two `switch:` values were site-specific names. Replaced with `Lab Backup` and
  `Lab Old Backup`, preserving the space inside the value, which is the part that matters:
  a value containing a space sits directly before `wccp: disable`, so this row is what
  proves the field splitter does not swallow the following key.

This row set answers the question the reconstructed `7412` scenario next to it could not.
`switch:` and `aggregate:` appear with real values and real positions rather than invented
ones, and `mtu-override:` is last on every row that has it, which is where 7.4.12 puts it
and not where the eleven vendored ntc-templates captures put it.

Types covered: physical, tunnel, switch, aggregate, vlan, vxlan.
