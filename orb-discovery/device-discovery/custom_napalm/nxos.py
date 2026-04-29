# Copyright 2026 NetBox Labs Inc
"""
Cisco NX-OS NAPALM driver subclass adding ``get_interfaces_vlans()``.

Fetches structured switchport data via NX-API (JSON) and maps each row
through the shared NX-OS field-normalizer + generic classifier.
"""

import logging

from napalm.nxos.nxos import NXOSDriver as NapalmNXOSDriver

from custom_napalm._nxos_common import nxos_row_to_switchport_info
from custom_napalm._vlan import classify_switchport

logger = logging.getLogger(__name__)


def _flatten_nxos_rows(payload: dict) -> list[dict]:
    """
    Flatten NX-API ``show interface switchport`` JSON into a list of row dicts.

    NX-API wraps rows in ``TABLE_interface > ROW_interface``; ``ROW_interface``
    is a dict for a single port and a list for multiple. Normalize to list.
    """
    table = (payload or {}).get("TABLE_interface") or {}
    row = table.get("ROW_interface")
    if row is None:
        return []
    if isinstance(row, list):
        return row
    return [row]


class NXOSDriver(NapalmNXOSDriver):
    """Cisco NX-OS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """Return per-interface VLAN config (NX-API JSON path)."""
        try:
            payload = self.device.show("show interface switchport", raw_text=False)
        except Exception:
            logger.debug("NX-OS show interface switchport failed", exc_info=True)
            return {}

        rows = _flatten_nxos_rows(payload)
        result: dict[str, dict] = {}
        for row in rows:
            ifname = row.get("interface")
            if not ifname:
                continue
            info = nxos_row_to_switchport_info(row)
            result[ifname] = classify_switchport(info)
        return result
