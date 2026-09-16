Mock data is hand-authored to exercise the omitted-FRU-row case, not captured
from a device.

The chassis is a plain Catalyst 9300, whose uplink module IS removable, so a
missing `Switch 2 FRU Uplink Module 1` row means the vendor omitted a row that
should exist — `Te2/1/1` has a parent and must not be promoted. Contrast
`fixed_uplink_9300l_no_fru_row`: byte-identical in ifname shape and equally
lacking a FRU row, but on a C9300L there is genuinely no module to report.
