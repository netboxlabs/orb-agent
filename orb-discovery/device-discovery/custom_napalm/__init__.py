"""Custom NAPALM drivers shipped with device-discovery."""

from custom_napalm.aoscx import AOSCXDriver
from custom_napalm.aoscx_ssh import AOSCXSSHDriver
from custom_napalm.asa import ASADriver
from custom_napalm.asa_ssh import ASASSHDriver
from custom_napalm.ftd_ssh import FTDSSHDriver
from custom_napalm.hp_comware import ComwareDriver
from custom_napalm.hp_procurve import ProCurveDriver
from custom_napalm.huawei_vrp import VRPDriver
from custom_napalm.panos import PANOSDriver
from custom_napalm.panos_ssh import PANOSSHDriver
from custom_napalm.viptela_ssh import ViptelaSSHDriver
from custom_napalm.wlc import WLCDriver

__all__ = [
    "AOSCXDriver",
    "AOSCXSSHDriver",
    "ASADriver",
    "ASASSHDriver",
    "FTDSSHDriver",
    "ComwareDriver",
    "ProCurveDriver",
    "VRPDriver",
    "PANOSDriver",
    "PANOSSHDriver",
    "ViptelaSSHDriver",
    "WLCDriver",
]
