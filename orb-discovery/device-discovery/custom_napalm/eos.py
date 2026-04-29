# Copyright 2026 NetBox Labs Inc
"""
Arista EOS NAPALM driver subclass adding ``get_interfaces_vlans()``.

Fetches structured switchport data via pyeapi (eAPI JSON-RPC) and maps
each port into a :class:`custom_napalm._vlan.SwitchportInfo` for the
generic classifier.
"""

import logging

from napalm.eos.eos import EOSDriver as NapalmEOSDriver

from custom_napalm._vlan import SwitchportInfo, classify_switchport, parse_vlan_range_string

logger = logging.getLogger(__name__)


def _maybe_int(v: object) -> int | None:
    """Coerce to int, returning None for bools and non-numeric values."""
    if isinstance(v, bool):
        return None
    try:
        return int(v)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _eos_port_to_switchport_info(port_data: dict) -> SwitchportInfo:
    """
    Build a SwitchportInfo from one entry of eAPI ``show interfaces switchport`` output.

    Arista eAPI per-port shape::

        {
            "enabled": true,
            "switchportInfo": {
                "mode": "access" | "trunk",
                "accessVlanId": 100,
                "trunkingNativeVlanId": 1,
                "trunkAllowedVlans": "1-4094" | "10,20" | "ALL" | "NONE",
                ...
            }
        }
    """
    if not port_data.get("enabled", True):
        return SwitchportInfo(
            enabled=False,
            admin_mode=None,
            oper_mode=None,
            access_vlan=None,
            native_vlan=None,
            allowed_vlans=None,
        )

    sw = port_data.get("switchportInfo") or {}
    mode_raw = (sw.get("mode") or "").lower()
    if "access" in mode_raw:
        admin: str | None = "access"
    elif "trunk" in mode_raw:
        admin = "trunk"
    else:
        # Includes "routed", empty, and any unknown mode — the generic
        # classifier maps admin_mode=None to a routed entry.
        admin = None

    trunk_spec = sw.get("trunkAllowedVlans") or ""
    if trunk_spec:
        vids, is_wildcard = parse_vlan_range_string(trunk_spec)
        allowed: list[int] | str | None = "all" if is_wildcard else vids
    else:
        allowed = None

    return SwitchportInfo(
        enabled=True,
        admin_mode=admin,  # type: ignore[arg-type]
        oper_mode=None,  # EOS does not expose DTP-style oper mode
        access_vlan=_maybe_int(sw.get("accessVlanId")),
        native_vlan=_maybe_int(sw.get("trunkingNativeVlanId")),
        allowed_vlans=allowed,
    )


class EOSDriver(NapalmEOSDriver):
    """Arista EOS NAPALM driver with VLAN-interface association support."""

    def get_interfaces_vlans(self) -> dict[str, dict]:
        """
        Return per-interface VLAN config.

        Output shape per interface::

            {"mode": "access"|"trunk"|"trunk-all"|"routed",
             "tagged": list[int], "untagged": int | None}

        Uses ``self._run_commands`` (the upstream EOSDriver wrapper) — NOT
        ``self.device.run_commands``. The wrapper bridges both eAPI
        (pyeapi ``Node.run_commands``) and SSH (Netmiko ``send_command`` +
        ``| json`` pipe). Calling pyeapi directly via ``self.device``
        breaks deployments that configure ``transport=ssh``.
        """
        try:
            response = self._run_commands(
                ["show interfaces switchport"], encoding="json"
            )
        except Exception:
            logger.debug("EOS show interfaces switchport failed", exc_info=True)
            return {}

        if not response:
            return {}
        switchports = (response[0] or {}).get("switchports") or {}

        result: dict[str, dict] = {}
        for ifname, port_data in switchports.items():
            info = _eos_port_to_switchport_info(port_data or {})
            result[ifname] = classify_switchport(info)
        return result
