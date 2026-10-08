Hand-authored non-ELS reply, in the shape of an EX4550 running Junos 15.1.

- `vlan.400 (DOWN)`: the state suffix is stripped, and the unit number (400)
  is not the VLAN ID; the tag (40) is.
- `LAB` has an empty L3 interface and contributes nothing.
- `STORAGE` names `vlan.70` but has no usable tag, so `vlan.70` is reported
  as `null` (not linked).
- `vlan.80` is named by `VOICE` (tag 80) and by `VOICE-OLD` (tag 0). One of
  its rows has no usable tag, so it is `null` rather than linked to 80.
