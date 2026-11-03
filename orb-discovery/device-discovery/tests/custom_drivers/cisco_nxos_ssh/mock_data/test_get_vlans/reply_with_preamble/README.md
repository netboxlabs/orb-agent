# NX-OS scenario: `| json` reply that opens with a device message (VLANs)

The first line of `show_vlan_brief_json.txt` is verbatim from a Nexus 3064PQ
(N3K-C3064PQ) running NX-OS 9.3(9), queried over the discovery SSH session:
NX-OS prints it ahead of every `| json` reply. The JSON after it is
hand-authored in the shape of the same switch's reply — one line of compact JSON,
member ports as one comma-separated string (`vlanshowplist-ifidx`); VLAN names and
ports are invented.

It pins that `get_vlans()` skips the device's line and parses the JSON:
`expected_result.json` is the result for the same JSON without that line. The
getter itself is napalm's; the line is skipped in this driver's
`_get_command_table()`.
