# snmp-discovery
Orb snmp discovery backend

### Usage
```bash
usage: snmp-discovery [-h] [-V] [-s HOST] [-p PORT] -t DIODE_TARGET -k DIODE_API_KEY

Orb SNMP Discovery Backend

options:
  -h, --help            show this help message and exit
  -V, --version         Display SNMP Discover version
  -s HOST, --host HOST  Server host
  -p PORT, --port PORT  Server port
  -t DIODE_TARGET, --diode-target DIODE_TARGET
                        Diode target
  -k DIODE_API_KEY, --diode-api-key DIODE_API_KEY
                        Diode API key. Environment variables can be used by wrapping them in ${} (e.g.
                        ${MY_API_KEY})
  -a DIODE_APP_NAME_PREFIX, --diode-app-name-prefix DIODE_APP_NAME_PREFIX
                        Diode producer_app_name prefix
```
