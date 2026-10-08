`get-vlan-information-extensive.xml` is the `show vlans extensive | display xml`
reply from a QFX5100 (ELS, Junos 21.4), as a user sent it, sanitized at source:
VLAN names, tags, internal indexes, L3 interfaces and members are as the device
reported them.

Each `irb.N` is bound to its VLAN by `l2ng-l2rtb-vlan-l3-interface`. The
`default` VLAN (tag 1) has no L3 interface and contributes nothing.
