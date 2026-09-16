Hand-authored from the inventory reported in issue #556, not captured from a
device. A WS-C2960S reports its installed SFP with the literal PID
`Unspecified`, which is a placeholder rather than a model.

`Unspecified` is truthy, so the row survives the `pid and sn` filter but is
not a real model. The row is still serial-bearing and has a usable
description, so it is now recorded as an unidentified transceiver rather than
dropped: the fixture demonstrates that a device-reported placeholder still
produces a module, using the description (`1000BaseSX SFP`) as the model and
`identified: false` to say the device did not name it.
