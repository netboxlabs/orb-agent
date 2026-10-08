`get-vlan-information-extensive.xml` is the `show vlans extensive | display xml`
reply from an EX4550 (non-ELS, Junos 15.1R7) as a user sent it, sanitized at
source and reduced here to five of its 39 VLANs. Every element kept is as the
device reported it, namespaces included.

It pins:

- `vlan-l3-interface` carries a state suffix (`vlan.20 (UP)`), which is
  stripped.
- `vlan-index` (5 for `MGMT`) is not the VLAN ID; `vlan-tag` (20) is.
- `VL100` has no L3 interface and contributes nothing.
- The `default` VLAN carries tag 0, which is not a VLAN ID, and contributes
  nothing.
