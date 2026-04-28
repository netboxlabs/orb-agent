# SSH Configuration and Jumphost Support for Device Discovery

The device discovery backend supports advanced SSH scenarios through NAPALM's `ssh_config_file` optional argument. This guide covers connecting to network devices through jumphost/bastion servers, custom ProxyCommand configurations, and VRF-aware SSH connections.

## Table of Contents
- [Overview](#overview)
- [How It Works](#how-it-works)
- [File Mounting Considerations](#file-mounting-considerations)
- [Basic Jumphost Pattern (ProxyJump)](#basic-jumphost-pattern-proxyjump)
- [ProxyCommand Pattern](#proxycommand-pattern)
- [VRF-Aware Jumphost Pattern](#vrf-aware-jumphost-pattern)
- [Multi-Environment Pattern](#multi-environment-pattern)
- [Advanced: SSH Control Master](#advanced-ssh-control-master-for-performance)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Complete Examples](#complete-examples)

## Overview

In production network environments, direct SSH access to network devices is often restricted. Common scenarios include:

- **Bastion/Jumphost Architecture**: Devices accessible only through an intermediate jump server
- **VRF-Isolated Devices**: Devices in specific VRF contexts on a jumphost
- **Multi-Hop SSH**: Complex network topologies requiring multiple SSH hops
- **Custom Authentication**: Specialized key-based authentication requirements

NAPALM supports these scenarios through the `ssh_config_file` optional argument, which allows you to specify a standard OpenSSH configuration file. This configuration is passed through to NAPALM's underlying SSH libraries (Netmiko/Paramiko), enabling sophisticated connection routing.

### Prerequisites

- orb-agent Docker image includes `openssh-client`
- NAPALM drivers with `ssh_config_file` support: ios, iosxr, junos, panos, vyos
- SSH key-based authentication to jumphost (recommended)
- OpenSSH 7.3+ for modern ProxyJump support (ProxyCommand works with older versions)

## How It Works

The configuration flow for SSH jumphost connectivity:

```
orb-agent policy config
    ↓ (optional_args)
NAPALM driver
    ↓ (connection parameters)
Netmiko/Paramiko SSH library
    ↓ (ssh_config_file parameter)
OpenSSH configuration
    ↓ (ProxyJump/ProxyCommand directives)
Jumphost → Target Device
```

When you specify `ssh_config_file` in the policy's `optional_args`, NAPALM passes this to its underlying SSH connection library, which reads the configuration file and establishes connections according to the rules defined within.

**Important:** The SSH config file path must be accessible inside the Docker container, not on the host system.

## File Mounting Considerations

Since orb-agent runs in a Docker container, you need to mount both the SSH config file and any private keys into the container filesystem.

### Recommended Directory Structure

**On Host System:**
```
/local/orb/
├── agent.yaml                # Main orb-agent configuration
├── ssh-napalm.conf          # SSH configuration file
└── keys/
    ├── jumphost_rsa         # Private key for jumphost
    └── device_rsa           # Private key for devices (if different)
```

**Docker Mount Mapping:**
```bash
docker run -v /local/orb:/opt/orb netboxlabs/orb-agent:latest
```

**Resulting Container Paths:**
- `/opt/orb/agent.yaml` - Main config
- `/opt/orb/ssh-napalm.conf` - SSH config
- `/opt/orb/keys/jumphost_rsa` - Private keys

### SSH Key Permissions

SSH requires private keys to have restrictive permissions. Set permissions before mounting:

```bash
chmod 600 /local/orb/keys/jumphost_rsa
chmod 600 /local/orb/keys/device_rsa
```

**Windows Consideration:** Windows filesystems don't enforce Unix permissions. When mounting from Windows, you may encounter "permissions are too open" errors. Solutions:

1. **Use WSL2 with Linux filesystem**: Store keys in WSL2 filesystem (e.g., `/home/user/.ssh/`) and mount from there
2. **Two-step mount with ENTRYPOINT**: Mount to temporary location, copy with correct permissions in container startup script
3. **Run on Linux**: Use a Linux VM or remote Docker host for production deployments

## Basic Jumphost Pattern (ProxyJump)

ProxyJump is the modern, recommended approach for jumphost connectivity (OpenSSH 7.3+). It's simpler and more maintainable than ProxyCommand.

### SSH Config

Create `/local/orb/ssh-napalm.conf`:

```sshconfig
# Jumphost/Bastion definition
Host jumphost
  HostName 203.0.113.50
  User admin
  IdentityFile /opt/orb/keys/jumphost_rsa
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# All devices (except jumphost) route through jumphost
Host * !jumphost
  ProxyJump jumphost
  StrictHostKeyChecking no
```

**Configuration Breakdown:**
- `Host jumphost` - Defines the jumphost connection parameters
- `HostName 203.0.113.50` - IP or hostname of the jumphost
- `IdentitiesOnly yes` - Prevents SSH agent from trying unwanted keys
- `StrictHostKeyChecking accept-new` - Accepts new host keys on first connection
- `Host * !jumphost` - Matches all hosts except the jumphost itself
- `ProxyJump jumphost` - Routes connections through the named jumphost

### Policy Configuration

In your orb-agent policy (`/local/orb/agent.yaml`):

```yaml
orb:
  policies:
    device_discovery:
      prod_network:
        config:
          defaults:
            site: Production
            role: switch
        scope:
          - driver: ios
            hostname: 10.0.1.10
            username: cisco
            password: ${CISCO_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-napalm.conf
          - driver: eos
            hostname: 10.0.2.20
            username: arista
            password: ${ARISTA_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-napalm.conf
```

### Pattern Matching

You can use SSH config patterns to apply rules to specific device ranges:

```sshconfig
Host jumphost
  HostName 203.0.113.50
  User admin
  IdentityFile /opt/orb/keys/jumphost_rsa

# Only 10.0.0.0/8 networks use jumphost
Host 10.*
  ProxyJump jumphost
  StrictHostKeyChecking no

# Direct connections for management network
Host 192.168.*
  StrictHostKeyChecking no
```

## ProxyCommand Pattern

ProxyCommand provides more flexibility for special cases, older SSH versions, or when you need custom connection logic.

### When to Use ProxyCommand

- Older OpenSSH versions (< 7.3) without ProxyJump support
- Custom connection logic (e.g., VRF-aware connections)
- Integration with external tools or scripts
- Compatibility with specific network environments

### SSH Config

Create `/local/orb/ssh-napalm.conf`:

```sshconfig
# Bastion host definition
Host bastion
  HostName 203.0.113.100
  User bastion-user
  IdentityFile /opt/orb/keys/bastion_rsa
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  BatchMode yes
  PreferredAuthentications publickey

# Devices in 192.168.0.0/16
Host 192.168.*
  ProxyCommand ssh -F /opt/orb/ssh-napalm.conf -W %h:%p bastion
  StrictHostKeyChecking no
```

**ProxyCommand Variables:**
- `%h` - Target hostname (e.g., 192.168.1.10)
- `%p` - Target port (default: 22)
- `-W %h:%p` - Forwards stdin/stdout to specified host:port
- `-F /opt/orb/ssh-napalm.conf` - References the same config file for bastion connection

### Important: Non-Standard Ports

Due to Paramiko limitations, non-standard SSH ports must be explicitly specified in the SSH config:

```sshconfig
Host bastion
  HostName 203.0.113.100
  Port 2222  # Explicit port specification

Host device01
  HostName 10.0.1.5
  Port 2200  # Explicit port specification
  ProxyCommand ssh -F /opt/orb/ssh-napalm.conf -W %h:%p bastion
```

## VRF-Aware Jumphost Pattern

Some network devices are only accessible within a specific VRF (Virtual Routing and Forwarding) context on the jumphost. This requires using netcat (`nc`) to establish the connection within the VRF.

### Scenario

- Jumphost at 10.50.50.1 with VRF named "MGMT"
- Network devices in 172.16.0.0/16 only accessible within MGMT VRF
- User has sudo privileges for `ip vrf exec` command on jumphost

### SSH Config

Create `/local/orb/ssh-napalm.conf`:

```sshconfig
# VRF-aware jumphost
Host jumphost-vrf
  HostName 10.50.50.1
  User netops
  IdentityFile /opt/orb/keys/jumphost_rsa
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# Devices accessible within MGMT VRF
Host 172.16.*
  ProxyCommand ssh -q -F /opt/orb/ssh-napalm.conf jumphost-vrf 'sudo ip vrf exec MGMT nc %h %p'
  StrictHostKeyChecking no
```

**Command Breakdown:**
- `-q` - Quiet mode, suppresses SSH warning messages
- `'sudo ip vrf exec MGMT nc %h %p'` - Executes netcat within the MGMT VRF context
- `%h` and `%p` - Replaced with target device hostname and port

### Jumphost Prerequisites

On the jumphost, ensure the following prerequisites are met:

**1. Install netcat:**
```bash
# Debian/Ubuntu
sudo apt-get install -y netcat

# RHEL/CentOS
sudo yum install -y nmap-ncat
```

**2. Configure passwordless sudo for VRF command:**

Create `/etc/sudoers.d/netops` (use `visudo -f /etc/sudoers.d/netops`):
```
netops ALL=(ALL) NOPASSWD: /sbin/ip vrf exec *
```

**3. Test manually:**
```bash
# From jumphost, test VRF connectivity
sudo ip vrf exec MGMT nc -v 172.16.1.1 22
```

### Policy Configuration

```yaml
scope:
  - driver: iosxr
    hostname: 172.16.1.1
    username: admin
    password: ${ROUTER_PASS}
    optional_args:
      ssh_config_file: /opt/orb/ssh-napalm.conf
      timeout: 120  # Increase timeout for VRF connections
```

## Multi-Environment Pattern

Organizations often have multiple environments (production, staging, development), each with its own jumphost. Pattern matching allows a single SSH config to handle all environments.

### SSH Config

Create `/local/orb/ssh-napalm.conf`:

```sshconfig
# Production Bastion
Host prod-bastion
  HostName bastion.prod.example.com
  User prod-admin
  IdentityFile /opt/orb/keys/prod_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# Staging Bastion
Host staging-bastion
  HostName bastion.staging.example.com
  User staging-admin
  IdentityFile /opt/orb/keys/staging_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# Production devices (10.10.0.0/16)
Host 10.10.*
  ProxyJump prod-bastion
  StrictHostKeyChecking no

# Staging devices (10.20.0.0/16)
Host 10.20.*
  ProxyJump staging-bastion
  StrictHostKeyChecking no
```

### Policy Configuration

```yaml
scope:
  # Production devices
  - driver: ios
    hostname: 10.10.1.5
    username: cisco
    password: ${PROD_PASS}
    optional_args:
      ssh_config_file: /opt/orb/ssh-napalm.conf
    override_defaults:
      site: Production

  # Staging devices
  - driver: ios
    hostname: 10.20.1.5
    username: cisco
    password: ${STAGING_PASS}
    optional_args:
      ssh_config_file: /opt/orb/ssh-napalm.conf
    override_defaults:
      site: Staging
```

This pattern automatically routes connections based on IP ranges, with each environment using its own jumphost and credentials.

## Advanced: SSH Control Master for Performance

When discovering many devices, SSH connection establishment overhead can be significant. SSH Control Master enables connection multiplexing, reusing existing SSH connections to the jumphost.

### Benefits

- **Faster Connections**: Subsequent connections to the same jumphost are nearly instantaneous
- **Reduced Load**: Fewer authentication handshakes on the jumphost
- **Lower Latency**: Eliminates TCP and SSH handshake overhead
- **Connection Persistence**: Keeps connections alive between device discoveries

### SSH Config

Create `/local/orb/ssh-napalm.conf`:

```sshconfig
# Jumphost with Control Master
Host jumphost
  HostName 203.0.113.50
  User admin
  IdentityFile /opt/orb/keys/jumphost_rsa
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  # Control Master settings
  ControlMaster auto
  ControlPath /tmp/ssh-cm-%r@%h:%p
  ControlPersist 10m

# All devices use jumphost
Host 10.*
  ProxyJump jumphost
  StrictHostKeyChecking no
```

**Configuration Options:**
- `ControlMaster auto` - Automatically creates or reuses master connection
- `ControlPath /tmp/ssh-cm-%r@%h:%p` - Socket file path (unique per user@host:port)
- `ControlPersist 10m` - Keeps connection alive for 10 minutes after last use

### Important: Writable Directory

The `ControlPath` directory must be writable inside the container. Options:

1. **Use /tmp** (default, works out of the box)
2. **Mount a volume**: `-v /local/orb/ssh-sockets:/opt/orb/ssh-sockets`
   ```sshconfig
   ControlPath /opt/orb/ssh-sockets/cm-%r@%h:%p
   ```

### Performance Comparison

**Without Control Master** (10 devices):
- First connection: ~2-3 seconds
- Each subsequent connection: ~2-3 seconds
- Total time: ~20-30 seconds

**With Control Master** (10 devices):
- First connection: ~2-3 seconds
- Each subsequent connection: ~0.5 seconds
- Total time: ~7-8 seconds

## Security Best Practices

### SSH Key Permissions

Private keys must have restrictive permissions:

```bash
chmod 600 /local/orb/keys/private_key  # Owner read/write only
chmod 400 /local/orb/keys/private_key  # Owner read-only (more restrictive)
```

SSH will refuse to use keys with overly permissive settings (e.g., 644, 777).

### StrictHostKeyChecking

Choose the appropriate level for your environment:

- `StrictHostKeyChecking yes` - Production: Reject unknown host keys (most secure)
- `StrictHostKeyChecking accept-new` - Recommended: Accept new keys, reject changed keys
- `StrictHostKeyChecking no` - Lab/Dev: Accept all keys (least secure, use only for testing)

**Recommendation**: Use `accept-new` for jumphosts and `no` for devices in dynamic environments.

### IdentitiesOnly

Always set `IdentitiesOnly yes` to prevent SSH agent from trying all available keys:

```sshconfig
Host jumphost
  IdentityFile /opt/orb/keys/specific_key
  IdentitiesOnly yes
```

Without this, SSH may try multiple keys and trigger account lockouts or rate limits.

### BatchMode

For automated contexts, use `BatchMode yes` to prevent interactive prompts:

```sshconfig
Host bastion
  BatchMode yes
  PreferredAuthentications publickey
```

This ensures the connection fails cleanly rather than hanging on password prompts.

### Environment Variables for Secrets

Never hardcode passwords in configuration files. Always use environment variables:

```yaml
scope:
  - hostname: 10.0.1.5
    username: admin
    password: ${DEVICE_PASSWORD}  # ✓ Correct
    # password: hardcoded123      # ✗ Never do this
```

### Key-Based Authentication for Jumphosts

Always use SSH keys (not passwords) for jumphost authentication:

- More secure than passwords
- Required for non-interactive automation
- Easier to rotate and manage centrally
- Supports key-specific restrictions and logging

## Troubleshooting

### Connection Hangs or Timeouts

**Symptoms:** Connection attempts hang indefinitely or time out

**Possible Causes:**
- Jumphost not reachable from container network
- Firewall blocking SSH from container to jumphost
- Network routing issues

**Solutions:**
1. Test jumphost connectivity from container:
   ```bash
   docker exec <container_id> ping 203.0.113.50
   docker exec <container_id> nc -zv 203.0.113.50 22
   ```

2. Increase NAPALM timeout:
   ```yaml
   optional_args:
     ssh_config_file: /opt/orb/ssh-napalm.conf
     timeout: 120
   ```

3. Check Docker network mode and firewall rules

### Permission Denied (publickey)

**Symptoms:** "Permission denied (publickey)" error

**Possible Causes:**
- Incorrect key file permissions
- Wrong username in SSH config
- Key not authorized on jumphost
- Key file not mounted correctly

**Solutions:**
1. Verify key permissions on host:
   ```bash
   ls -la /local/orb/keys/
   # Should show: -rw------- (600) or -r-------- (400)
   ```

2. Test key authentication manually:
   ```bash
   ssh -i /local/orb/keys/jumphost_rsa admin@203.0.113.50
   ```

3. Verify public key is in jumphost's `~/.ssh/authorized_keys`

4. Check SSH config username matches actual jumphost username

### No Such File or Directory (SSH Config)

**Symptoms:** "Could not open SSH config file" or similar error

**Possible Causes:**
- SSH config file path is incorrect
- Volume not mounted correctly
- Path refers to host filesystem instead of container filesystem

**Solutions:**
1. Verify mount in docker run command:
   ```bash
   docker run -v /local/orb:/opt/orb ...
   ```

2. Check file exists in container:
   ```bash
   docker exec <container_id> ls -la /opt/orb/ssh-napalm.conf
   ```

3. Ensure path in optional_args is absolute and container-relative:
   ```yaml
   ssh_config_file: /opt/orb/ssh-napalm.conf  # ✓ Correct (container path)
   # ssh_config_file: /local/orb/ssh-napalm.conf  # ✗ Wrong (host path)
   ```

### ProxyCommand Not Working

**Symptoms:** "ProxyCommand failed" or connection errors with ProxyCommand

**Possible Causes:**
- openssh-client not installed in container
- Syntax error in ProxyCommand
- Incorrect variable substitution (%h, %p)

**Solutions:**
1. Verify openssh-client is installed (should be in recent orb-agent images):
   ```bash
   docker exec <container_id> which ssh
   docker exec <container_id> ssh -V
   ```

2. Test ProxyCommand manually:
   ```bash
   docker exec <container_id> ssh -F /opt/orb/ssh-napalm.conf 10.0.1.5
   ```

3. Add verbose debugging to ProxyCommand:
   ```sshconfig
   ProxyCommand ssh -vvv -F /opt/orb/ssh-napalm.conf -W %h:%p bastion
   ```

4. Check ProxyCommand syntax carefully (quotes, %h/%p placement)

### VRF Command Fails

**Symptoms:** VRF connections fail or hang

**Possible Causes:**
- Netcat (nc) not installed on jumphost
- No sudo privileges for `ip vrf exec` command
- VRF name incorrect or case-sensitive mismatch

**Solutions:**
1. Test VRF command manually on jumphost:
   ```bash
   sudo ip vrf exec MGMT nc -v 172.16.1.1 22
   ```

2. Verify netcat is installed:
   ```bash
   which nc
   ```

3. Check sudo configuration:
   ```bash
   sudo -l  # Should show: NOPASSWD: /sbin/ip vrf exec *
   ```

4. Verify VRF name (case-sensitive):
   ```bash
   ip vrf show
   ```

### Non-Standard Port Issues

**Symptoms:** Connections to non-standard SSH ports fail

**Cause:** Paramiko doesn't automatically detect ports from hostnames

**Solution:** Explicitly specify ports in SSH config:

```sshconfig
Host bastion
  HostName bastion.example.com
  Port 2222  # Explicit port

Host device01
  HostName device01.example.com
  Port 2200  # Explicit port
  ProxyJump bastion
```

### Windows ProxyCommand Issues

**Symptoms:** ProxyCommand fails on Windows Docker Desktop

**Cause:** Known Paramiko/ProxyCommand compatibility issues on Windows

**Solution:** Use Linux for production orb-agent deployments:
- Linux VM or remote Docker host
- WSL2 with Docker in WSL2 (not Docker Desktop)
- Cloud-based container platforms

## Complete Examples

### Example 1: Basic Jumphost with ProxyJump

**Scenario:** Cisco IOS devices behind a single bastion host, using key-based authentication.

**Directory Structure:**
```
/local/orb/
├── agent.yaml
├── ssh-jumphost.conf
└── keys/
    └── bastion_key
```

**SSH Config** (`/local/orb/ssh-jumphost.conf`):
```sshconfig
Host bastion
  HostName 203.0.113.100
  User admin
  IdentityFile /opt/orb/keys/bastion_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

Host 10.*
  ProxyJump bastion
  StrictHostKeyChecking no
```

**Agent Config** (`/local/orb/agent.yaml`):
```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: bastion-agent
    device_discovery:
  policies:
    device_discovery:
      behind_bastion:
        config:
          schedule: "*/5 * * * *"
          defaults:
            site: Remote Site
            role: switch
        scope:
          - driver: ios
            hostname: 10.0.1.10
            username: cisco
            password: ${CISCO_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-jumphost.conf
          - driver: ios
            hostname: 10.0.1.20
            username: cisco
            password: ${CISCO_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-jumphost.conf
```

**Setup Commands:**
```bash
# Create directory structure
mkdir -p /local/orb/keys

# Generate SSH key for bastion
ssh-keygen -t rsa -b 4096 -f /local/orb/keys/bastion_key -N ""

# Set correct permissions
chmod 600 /local/orb/keys/bastion_key

# Copy public key to bastion host
ssh-copy-id -i /local/orb/keys/bastion_key.pub admin@203.0.113.100

# Create config files (use editor or cat)
# ... create agent.yaml and ssh-jumphost.conf ...
```

**Run Command:**
```bash
docker run -d \
  --name orb-agent \
  -v /local/orb:/opt/orb \
  -e DIODE_CLIENT_ID="${DIODE_CLIENT_ID}" \
  -e DIODE_CLIENT_SECRET="${DIODE_CLIENT_SECRET}" \
  -e CISCO_PASS="${CISCO_PASS}" \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### Example 2: VRF-Aware Jumphost

**Scenario:** Devices accessible only within a VRF on the jumphost.

**Directory Structure:**
```
/local/orb/
├── agent.yaml
├── ssh-vrf.conf
└── keys/
    └── jumphost_key
```

**SSH Config** (`/local/orb/ssh-vrf.conf`):
```sshconfig
Host jumphost-mgmt
  HostName 10.50.50.1
  User netops
  IdentityFile /opt/orb/keys/jumphost_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

Host 172.16.*
  ProxyCommand ssh -q -F /opt/orb/ssh-vrf.conf jumphost-mgmt 'sudo ip vrf exec MGMT nc %h %p'
  StrictHostKeyChecking no
```

**Agent Config** (`/local/orb/agent.yaml`):
```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://192.168.0.100:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: vrf-agent
    device_discovery:
  policies:
    device_discovery:
      vrf_devices:
        config:
          defaults:
            site: VRF Site
            role: router
        scope:
          - driver: iosxr
            hostname: 172.16.1.1
            username: admin
            password: ${ROUTER_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-vrf.conf
              timeout: 120
          - driver: iosxr
            hostname: 172.16.2.1
            username: admin
            password: ${ROUTER_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-vrf.conf
              timeout: 120
```

**Prerequisites on Jumphost:**
```bash
# Install netcat
sudo apt-get install -y netcat

# Configure passwordless sudo
echo "netops ALL=(ALL) NOPASSWD: /sbin/ip vrf exec *" | sudo tee /etc/sudoers.d/netops

# Test VRF connectivity
sudo ip vrf exec MGMT nc -v 172.16.1.1 22
```

**Run Command:**
```bash
docker run -d \
  --name orb-agent-vrf \
  -v /local/orb:/opt/orb \
  -e DIODE_CLIENT_ID="${DIODE_CLIENT_ID}" \
  -e DIODE_CLIENT_SECRET="${DIODE_CLIENT_SECRET}" \
  -e ROUTER_PASS="${ROUTER_PASS}" \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### Example 3: Multiple Jumphosts (Multi-Environment)

**Scenario:** Multiple environments with different jumphosts, routing based on IP ranges.

**Directory Structure:**
```
/local/orb/
├── agent.yaml
├── ssh-multi.conf
└── keys/
    ├── prod_key
    └── staging_key
```

**SSH Config** (`/local/orb/ssh-multi.conf`):
```sshconfig
# Production Bastion
Host prod-bastion
  HostName bastion.prod.example.com
  User prod-admin
  IdentityFile /opt/orb/keys/prod_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# Staging Bastion
Host staging-bastion
  HostName bastion.staging.example.com
  User staging-admin
  IdentityFile /opt/orb/keys/staging_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new

# Production devices (10.10.0.0/16)
Host 10.10.*
  ProxyJump prod-bastion
  StrictHostKeyChecking no

# Staging devices (10.20.0.0/16)
Host 10.20.*
  ProxyJump staging-bastion
  StrictHostKeyChecking no
```

**Agent Config** (`/local/orb/agent.yaml`):
```yaml
orb:
  config_manager:
    active: local
  backends:
    common:
      diode:
        target: grpc://diode.example.com:8080/diode
        client_id: ${DIODE_CLIENT_ID}
        client_secret: ${DIODE_CLIENT_SECRET}
        agent_name: multi-env-agent
    device_discovery:
  policies:
    device_discovery:
      multi_environment:
        config:
          schedule: "0 8 * * *"
        scope:
          # Production devices
          - driver: ios
            hostname: 10.10.1.5
            username: cisco
            password: ${PROD_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-multi.conf
            override_defaults:
              site: Production
          - driver: ios
            hostname: 10.10.2.10
            username: cisco
            password: ${PROD_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-multi.conf
            override_defaults:
              site: Production

          # Staging devices
          - driver: ios
            hostname: 10.20.1.5
            username: cisco
            password: ${STAGING_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-multi.conf
            override_defaults:
              site: Staging
```

**Setup Commands:**
```bash
# Generate keys for both environments
ssh-keygen -t rsa -b 4096 -f /local/orb/keys/prod_key -N ""
ssh-keygen -t rsa -b 4096 -f /local/orb/keys/staging_key -N ""

# Set permissions
chmod 600 /local/orb/keys/prod_key
chmod 600 /local/orb/keys/staging_key

# Copy keys to respective bastions
ssh-copy-id -i /local/orb/keys/prod_key.pub prod-admin@bastion.prod.example.com
ssh-copy-id -i /local/orb/keys/staging_key.pub staging-admin@bastion.staging.example.com
```

**Run Command:**
```bash
docker run -d \
  --name orb-agent-multi \
  -v /local/orb:/opt/orb \
  -e DIODE_CLIENT_ID="${DIODE_CLIENT_ID}" \
  -e DIODE_CLIENT_SECRET="${DIODE_CLIENT_SECRET}" \
  -e PROD_PASS="${PROD_PASS}" \
  -e STAGING_PASS="${STAGING_PASS}" \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```

### Example 4: High-Performance with Control Master

**Scenario:** Discovering many devices efficiently using connection multiplexing.

**SSH Config** (`/local/orb/ssh-performance.conf`):
```sshconfig
# Jumphost with Control Master for connection reuse
Host jumphost
  HostName 203.0.113.50
  User admin
  IdentityFile /opt/orb/keys/jumphost_key
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
  # Connection multiplexing settings
  ControlMaster auto
  ControlPath /tmp/ssh-cm-%r@%h:%p
  ControlPersist 15m

# All devices route through jumphost with multiplexing
Host 10.0.*
  ProxyJump jumphost
  StrictHostKeyChecking no
```

**Agent Config** (`/local/orb/agent.yaml`):
```yaml
orb:
  policies:
    device_discovery:
      high_volume:
        config:
          schedule: "0 */4 * * *"
          defaults:
            site: Data Center
        scope:
          # Multiple devices - connection multiplexing improves performance
          - driver: ios
            hostname: 10.0.1.1-50
            username: admin
            password: ${NET_PASS}
            optional_args:
              ssh_config_file: /opt/orb/ssh-performance.conf
```

**Performance Benefits:**
- First connection: ~2-3 seconds (establishes master)
- Subsequent connections: ~0.5 seconds (reuses master)
- For 50 devices: ~30 seconds total vs ~150 seconds without multiplexing

**Run Command:**
```bash
docker run -d \
  --name orb-agent-perf \
  -v /local/orb:/opt/orb \
  -e DIODE_CLIENT_ID="${DIODE_CLIENT_ID}" \
  -e DIODE_CLIENT_SECRET="${DIODE_CLIENT_SECRET}" \
  -e NET_PASS="${NET_PASS}" \
  netboxlabs/orb-agent:latest run -c /opt/orb/agent.yaml
```
