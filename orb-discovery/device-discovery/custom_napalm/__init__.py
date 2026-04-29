"""Custom NAPALM drivers shipped with device-discovery."""

from custom_napalm.alcatel_aos import AlcatelAOSDriver
from custom_napalm.aruba_aoscx import AOSCXDriver
from custom_napalm.aruba_aoscx_ssh import AOSCXSSHDriver
from custom_napalm.aruba_os import ArubaOSDriver
from custom_napalm.aruba_osswitch import ArubaOSSDriver
from custom_napalm.avaya_ers import ERSDriver
from custom_napalm.brocade_fastiron import FastIronDriver
from custom_napalm.brocade_netiron import NetIronDriver
from custom_napalm.checkpoint_gaia import GaiaDriver
from custom_napalm.ciena_saos import SAOSDriver
from custom_napalm.cisco_apic import APICDriver
from custom_napalm.cisco_asa import ASADriver
from custom_napalm.cisco_asa_ssh import ASASSHDriver
from custom_napalm.cisco_ftd_ssh import FTDSSHDriver
from custom_napalm.cisco_fxos import FXOSDriver
from custom_napalm.cisco_s300 import S300Driver
from custom_napalm.cisco_viptela_ssh import ViptelaSSHDriver
from custom_napalm.cisco_wlc import WLCDriver
from custom_napalm.cumulus_linux import CumulusDriver
from custom_napalm.dell_ftos import FTOSDriver
from custom_napalm.dell_powerconnect import PowerConnectDriver
from custom_napalm.dell_sonic import SONiCDriver
from custom_napalm.ericsson_ipos import IPOSDriver
from custom_napalm.extreme_exos import ExosDriver
from custom_napalm.extreme_slx import SLXOSDriver
from custom_napalm.extreme_vsp import VSPDriver
from custom_napalm.fortinet_fortios_ssh import FortiOSSSHDriver
from custom_napalm.hp_comware import ComwareDriver
from custom_napalm.hp_procurve import ProcurveDriver
from custom_napalm.huawei_smartax import SmartDriver
from custom_napalm.huawei_vrp import VRPDriver
from custom_napalm.ios import IOSDriver
from custom_napalm.mellanox_mlnxos import MLNXOSDriver
from custom_napalm.mikrotik_routeros import ROSDriver
from custom_napalm.nokia_srl import SRLDriver
from custom_napalm.nokia_sros import SROSDriver
from custom_napalm.nokia_sros_ssh import SROSSSHDriver
from custom_napalm.paloalto_panos import PANOSDriver
from custom_napalm.paloalto_panos_ssh import PANOSSHDriver
from custom_napalm.ubiquiti_edgerouter import EdgeRouterDriver
from custom_napalm.ubiquiti_edgeswitch import EdgeSwitchDriver
from custom_napalm.ubiquiti_unifiswitch import UniFiSwitchDriver

__all__ = [
    "AlcatelAOSDriver",
    "AOSCXDriver",
    "AOSCXSSHDriver",
    "APICDriver",
    "ArubaOSDriver",
    "ArubaOSSDriver",
    "ASADriver",
    "ASASSHDriver",
    "ComwareDriver",
    "CumulusDriver",
    "EdgeRouterDriver",
    "EdgeSwitchDriver",
    "ERSDriver",
    "ExosDriver",
    "FastIronDriver",
    "FortiOSSSHDriver",
    "FTDSSHDriver",
    "FTOSDriver",
    "FXOSDriver",
    "GaiaDriver",
    "IOSDriver",
    "IPOSDriver",
    "MLNXOSDriver",
    "NetIronDriver",
    "PANOSDriver",
    "PANOSSHDriver",
    "PowerConnectDriver",
    "ProcurveDriver",
    "ROSDriver",
    "S300Driver",
    "SAOSDriver",
    "SLXOSDriver",
    "SmartDriver",
    "SONiCDriver",
    "SRLDriver",
    "SROSDriver",
    "SROSSSHDriver",
    "UniFiSwitchDriver",
    "ViptelaSSHDriver",
    "VRPDriver",
    "VSPDriver",
    "WLCDriver",
]
