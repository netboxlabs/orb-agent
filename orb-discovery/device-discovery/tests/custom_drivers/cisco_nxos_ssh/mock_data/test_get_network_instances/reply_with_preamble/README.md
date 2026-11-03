# NX-OS scenario: `| json` replies that open with a device message (VRFs)

The first line of `show_vrf_detail_json.txt` and `show_vrf_interface_json.txt` is
verbatim from a Nexus 3064PQ (N3K-C3064PQ) running NX-OS 9.3(9), queried over the
discovery SSH session: NX-OS prints it ahead of every `| json` reply.
The JSON after it is hand-authored in the shape of the same switch's replies — one
line of compact JSON, `rd` `0:0` on VRF-lite, string `vrf_id`s; VRF and interface
names are invented.

It pins that `get_network_instances()` skips the device's line and parses the JSON:
`expected_result.json` is the result for the same JSON without that line.
