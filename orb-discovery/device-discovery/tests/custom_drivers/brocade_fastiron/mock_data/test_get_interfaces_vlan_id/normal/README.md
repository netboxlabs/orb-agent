The same `show running-config vlan` as `test_get_vlans/normal` (hand-authored).
Only `router-interface ve <N>` binds a VE to its VLAN; the `untagged ve 10`
member line under VLAN 30 is an L2 membership and is not reported.
