Mock data is hand-authored to exercise a stack whose uplinks sit on a removable
network module, not captured from a device.

The chassis is a plain Catalyst 9300, which is the family that accepts a
`C9300-NM-*`. The C9300L does not — its uplinks are fixed and it reports no FRU
row at all, which is `fixed_uplink_9300l_no_fru_row`.
