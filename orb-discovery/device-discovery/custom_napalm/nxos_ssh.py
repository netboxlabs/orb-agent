# Copyright 2026 NetBox Labs Inc
"""
Cisco NX-OS-SSH NAPALM driver subclass adding ``get_interfaces_vlans()``.

Fetches ``show interface switchport`` over SSH (Netmiko), parses via
ntc-templates ``cisco_nxos`` platform, and reuses the shared NX-OS
field mapper so output is byte-identical with the NX-API path.
"""

import logging

from napalm.nxos_ssh.nxos_ssh import NXOSSSHDriver as NapalmNXOSSSHDriver
from ntc_templates.parse import parse_output

from custom_napalm._nxos_common import nxos_row_to_switchport_info
from custom_napalm._vlan import classify_switchport

logger = logging.getLogger(__name__)


class NXOSSSHDriver(NapalmNXOSSSHDriver):
    """Cisco NX-OS-SSH NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config (CLI scrape via ntc-templates)."""
        output = self._send_command("show interface switchport")
        if not output:
            return {}
        try:
            rows = parse_output(
                platform="cisco_nxos",
                command="show interface switchport",
                data=output,
            )
        except Exception:
            logger.debug("ntc-templates failed to parse NX-OS switchport", exc_info=True)
            return {}

        result: dict[str, dict] = {}
        for row in rows or []:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = nxos_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result
