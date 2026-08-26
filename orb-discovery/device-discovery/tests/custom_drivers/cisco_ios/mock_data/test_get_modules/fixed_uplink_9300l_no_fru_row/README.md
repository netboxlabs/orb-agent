Hand-authored from a publicly published `show inventory` for a C9300L-24T-4X
running IOS-XE 17.09.05, sanitized: serials and identifiers are replaced, the
hardware structure is not. A second, independently published `show inventory`
from a C9300L-48P-4X shows the same structure.

Like the C9200L in `fixed_uplink_chassis_no_fru_row`, this family has FIXED SFP
uplinks numbered `Te1/1/x` (module 1) and no `FRU Uplink Module` row, because
there is no removable module. The C9300 and C9300X, which do take a removable
`C9300-NM-*`, report that module as its own FRU row — see
`cat9300_stack_with_nm_uplinks`.

The `StackAdapter1/x` rows are present because real captures carry them; they
are not interface-shaped and must not be read as optics.
