Hand-authored from the inventory reported in issue #556, not captured from a
device. A WS-C2960S reports its installed SFP with the literal PID
`Unspecified`, which is a placeholder rather than a model.

`Unspecified` is truthy, so the row survives the `pid and sn` filter and never
reaches the blank-PID warning. It is instead rejected by the transceiver type
gate. The point of the fixture is that rejection is announced, not silent.
