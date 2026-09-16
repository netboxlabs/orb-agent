# SNMP profile provenance

The contents of `snmp-profiles/` are copied verbatim from
[kentik/snmp-profiles](https://github.com/kentik/snmp-profiles), path `profiles/kentik_snmp/`.

| | |
|---|---|
| Upstream | https://github.com/kentik/snmp-profiles |
| Branch | `main` |
| Commit | `9ac6a341175fdf28a5bfefd2dc8ce86ef5202b6a` |
| Synced | `2026-08-28` |
| Files | `205` |
| Licence | Apache 2.0 (`snmp-profiles/LICENSE`) |

**The files are unmodified.** Apache 2.0 §4(b) requires a prominent notice on any
file that is changed, so local edits are avoided entirely. A device that needs
different behaviour should use the `--snmp-profiles-dir` override, which overlays
the bundled set at runtime.

Upstream has no `NOTICE` file, so Apache 2.0 §4(d) does not apply.

To refresh, clone upstream, `rsync -a --delete <clone>/profiles/kentik_snmp/ snmp-profiles/`,
copy `LICENSE` across, and update the commit, date and count above.
