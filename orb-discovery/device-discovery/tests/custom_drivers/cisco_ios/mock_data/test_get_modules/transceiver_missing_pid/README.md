Mock data is hand-authored from the values reported in issue #514, not
captured from a device. `Te1/0/7` reports a serial and a usable description
but no PID -- a real optic the switch could not name, the same shape as the
C9200L's DAC cables in issue #556. It is now recorded as an unidentified
transceiver (model taken from its description, `identified: false`) rather
than dropped, alongside `Te1/0/1`, which is identified and unaffected.
