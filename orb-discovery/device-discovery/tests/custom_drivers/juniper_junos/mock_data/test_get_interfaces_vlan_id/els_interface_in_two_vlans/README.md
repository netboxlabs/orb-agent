Hand-authored ELS reply, in the shape of a QFX5100 running Junos 21.4.

- `irb.20` routes for VLAN 200: the IRB unit number is the operator's choice
  and is never read as the VLAN ID.
- `irb.300` is named by VLANs in two routing instances with different tags
  (300 and 301). The reply contradicts itself, so it maps to `null` and is
  not linked.
- The `default` VLAN has no L3 interface and contributes nothing.
