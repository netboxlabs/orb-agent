# FortiOS 7.4.12, reconstructed

Not a device capture. Built from the one real fragment in netboxlabs/orb-agent#537:
a redacted `get system interface` line carrying `trunk: disable`, one of the fields
that no variant of the upstream template admits.

`switch:` appears in that issue only as prose, with no value and no line position, so
its position here is invented; `aggregate:` is left out entirely and covered in the
scanner unit tests instead, where an invented position is harmless.

port2 and its address are invented, so that this scenario is not vacuous: with only
the unnumbered port1 the expected result is `{}`, and the fixture could be truncated
to zero bytes and still pass. port1 stays unnumbered because that is what keeps the
signal-3 silence test meaningful.

Replace this with a sanitised capture if the reporter supplies one.
