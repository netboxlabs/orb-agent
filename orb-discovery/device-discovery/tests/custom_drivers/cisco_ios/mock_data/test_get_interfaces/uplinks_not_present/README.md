Mock data is hand-authored, not captured from a device.

A Catalyst whose network-module slot carries 25G uplinks. `show interfaces`
still lists the 1G and 10G uplinks the slot could carry, and marks them
`Hardware is not present`. Those two are left out of `expected_result.json`.
The second 25G port is down with no transceiver; it is present, so it stays.
