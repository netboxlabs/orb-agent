# FortiOS 7.4.12, reconstructed

Not a device capture. The physical fixture is the same reconstruction as
`test_get_interfaces/7412/`; see that README for what is real.

This scenario exists because it is the only test that pins `get_facts`'s rewiring:
with it absent, `get_facts` can be left calling the aborting ntc-template and the
entire suite still passes.

`get_system_status.txt` and `get_system_performance_status.txt` are copies of the
`normal` scenario's. They are required, not decorative: the harness returns an empty
string for any command with no fixture file, which would silently make `hostname` and
`serial_number` `"Unknown"` and let this scenario pass while proving nothing.
