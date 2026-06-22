# orb-discovery

Orb discovery backends collection

- [device-discovery](./device-discovery/README.md) - Device Discovery Backend that uses [NAPALM](https://github.com/napalm-automation/napalm) Drivers.
- [network-discovery](./network-discovery/README.md) - Network Discovery Backend which is a wrapper over [NMAP](https://nmap.org/) scanner.
- [worker](./worker/README.md) - A Worker Backend that allows to run custom implementation as part of Orb Agent.
- [snmp-discovery](./snmp-discovery/README.md) - Device discovery that uses SNMP
- [gnmi-discovery](./gnmi-discovery/README.md) - **(experimental)** Event-driven device discovery that uses [gNMI](https://github.com/openconfig/gnmi) subscriptions over [OpenConfig](https://www.openconfig.net/) models.