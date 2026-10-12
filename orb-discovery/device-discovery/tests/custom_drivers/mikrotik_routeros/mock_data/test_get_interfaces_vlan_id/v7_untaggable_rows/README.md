Constructed RouterOS 7 output covering every row the getter reports but
refuses to link (mapped to `null`):

- `Kantoor` is tagged inside `Huis`, itself a VLAN interface (stacked tags).
- `svc100` is an 802.1ad S-tag (`use-service-tag=yes`). Its comment contains
  `vlan-id=99` to pin that comment text is never read as an attribute.
- VLAN ID 20 sits on both `ether2` and `ether3`, so neither row is linked.

`vlan40` is disabled and its name disagrees with its VLAN ID; the device's
`vlan-id=30` is what is reported. `to isp` pins quoted values with spaces.
