# FortiOS 7.4.12, reconstructed

Not a device capture. Built from the one real fragment in netboxlabs/orb-agent#537:
the physical-block line `medium: n/a`, which is the line that aborted the upstream
template and made the FortiGate report no interfaces at all.

`medium: n/a` sits deliberately **above** `status:`. As the last line of a block it
would prove nothing: deleting it leaves this scenario green, so the scenario would
not catch a regression that treats an unknown field line as unreadable — the direct
analogue of the `^. -> Error` this change removes. Above `status:`, such a regression
discards the block and this scenario fails.

The issue's own field order is not evidence either way: its quoted flat line puts
`mtu-override:` last, where all eleven vendored captures put it before `wccp:`.

The reporter has since supplied a capture; it is the `7412_capture` scenario beside
this one. This scenario is kept rather than replaced, because the device puts `medium:`
below `status:`, where a regression that discards a block on an unknown field line would
still pass. The deliberate ordering here is what catches it.
