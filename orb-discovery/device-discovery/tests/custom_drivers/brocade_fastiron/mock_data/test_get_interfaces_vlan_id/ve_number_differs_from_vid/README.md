Hand-authored. VE numbers are operator-chosen and do not match the VLAN IDs
they route for, which is why the VE name alone is never parsed for a VLAN.
`ve 20` is bound by two VLANs; contradictory data maps it to `null`.
