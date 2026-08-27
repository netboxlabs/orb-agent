Mock data is hand-authored to exercise the every-optic-declined case, not
captured from a device.

A plain Catalyst 9300 whose uplink module row the vendor omitted. `Te1/1/1` is
on module 1, not the baseboard, and the chassis is not on the fixed-uplink
allowlist, so the optic is correctly declined. With no bay left to emit the
payload is `None`, which is the exact silence that turned #514 and #556 into
support tickets. The fixture pins that the driver says why.
