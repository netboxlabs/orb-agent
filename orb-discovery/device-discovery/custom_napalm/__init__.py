"""Custom NAPALM drivers shipped with device-discovery."""

from custom_napalm.aoscx import AOSCXDriver
from custom_napalm.aoscx_ssh import AOSCXSSHDriver
from custom_napalm.asa import ASADriver
from custom_napalm.asa_ssh import ASASSHDriver
from custom_napalm.comware import ComwareDriver
from custom_napalm.ers import ERSDriver
from custom_napalm.exos import ExosDriver
from custom_napalm.fastiron import FastIronDriver
from custom_napalm.ftd_ssh import FTDSSHDriver
from custom_napalm.ftos import FTOSDriver
from custom_napalm.gaia import GaiaDriver
from custom_napalm.huawei_vrp import VRPDriver
from custom_napalm.netiron import NetIronDriver
from custom_napalm.panos import PANOSDriver
from custom_napalm.panos_ssh import PANOSSHDriver
from custom_napalm.procurve import ProcurveDriver
from custom_napalm.ros import ROSDriver
from custom_napalm.saos import SAOSDriver
from custom_napalm.sros import SROSDriver
from custom_napalm.sros_ssh import SROSSSHDriver
from custom_napalm.viptela_ssh import ViptelaSSHDriver
from custom_napalm.vsp import VSPDriver
from custom_napalm.wlc import WLCDriver

__all__ = [
    "AOSCXDriver",
    "AOSCXSSHDriver",
    "ASADriver",
    "ASASSHDriver",
    "ComwareDriver",
    "ERSDriver",
    "ExosDriver",
    "FastIronDriver",
    "FTDSSHDriver",
    "FTOSDriver",
    "GaiaDriver",
    "NetIronDriver",
    "ROSDriver",
    "SAOSDriver",
    "SROSDriver",
    "SROSSSHDriver",
    "VRPDriver",
    "PANOSDriver",
    "PANOSSHDriver",
    "ProcurveDriver",
    "ViptelaSSHDriver",
    "VSPDriver",
    "WLCDriver",
]
