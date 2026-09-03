# FortiOS 7.4.12, device capture

`get system interface physical` from the FortiGate-100F in netboxlabs/orb-agent#537,
supplied by the reporter after the fix shipped. All 29 blocks, in the order and with
the indentation the device printed.

Sanitised: nothing. The capture carried only 10.10.10.1, 192.168.1.99 and 0.0.0.0,
so no address needed replacing.

`medium:` appears on port17 through port20 only, and sits **below** `status:`, between
`speed:` and `FEC:`. That is the real position, and it is why the reconstructed
`7412` scenario next to this one is kept rather than replaced: there `medium:` sits
deliberately above `status:`, where a regression that treats an unknown field line as
unreadable discards the block and fails the test. In the position the device actually
uses, the same regression would still pass. The two scenarios test different things.

No `fnsysctl_ifconfig.txt`: the reporter did not supply one, and the mock device returns
an empty string for a missing file, so MAC addresses come out empty rather than invented.
