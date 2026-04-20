# SNMP Discovery - Interface Type Matching

The SNMP discovery backend uses an intelligent **six-tier priority system** to automatically determine interface types. This system provides zero-configuration support for common network equipment while allowing fine-grained customization through user-defined patterns.

## Deferred Type Resolution

SNMP discovery implements **deferred type resolution** to handle the fact that SNMP walks return OIDs in numeric order. Typically, the interface type OID (`.1.3.6.1.2.1.2.2.1.3`) comes before the interface name OID (`.1.3.6.1.2.1.2.2.1.2`) in SNMP walks, which would prevent pattern matching from working correctly.

To solve this, the SNMP mapper:
1. Stores the raw SNMP `ifType` value during field processing
2. Collects all interface fields (name, speed, MAC address, etc.)
3. Resolves the final interface type **after all fields are collected**
4. This ensures the interface name is always available for pattern matching

This approach ensures pattern matching works correctly regardless of SNMP OID ordering.

## Priority Order

Interface types are determined using the following priority order (first match wins):

### 0. Subinterface Detection (Highest Priority - Structural)
- Subinterfaces are identified by name patterns containing `.` or `:` separators
- If a subinterface is detected, it is ALWAYS assigned type `virtual`
- Parent interface tracking is performed in a post-processing phase
- This takes precedence over ALL other matching methods

### 1. User-Defined Patterns (Highest Priority for Non-Subinterfaces)
- Patterns configured in `defaults.interface_patterns` are checked first
- If ANY user pattern matches, the most specific (longest) user match is used
- User patterns ALWAYS take priority over all other methods

### 2. SNMP ifType Mapping
- If no user pattern matches, the SNMP `ifType` value is mapped to NetBox interface types
- Standard IANA interface types are automatically converted (e.g., `ethernetCsmacd(6)` → `1000base-t`)
- See [SNMP ifType Mappings](#snmp-iftype-mappings) below for full mapping table

### 3. Built-In Patterns
- If SNMP ifType is unknown or generic, built-in vendor patterns are checked
- Provides zero-configuration support for common network equipment (Cisco, Juniper, Arista, Nokia, etc.)
- Most specific (longest) built-in match is used

### 4. Speed-Based Detection
- If no patterns match and SNMP ifType is unknown, interface speed (from SNMP `ifSpeed` or `ifHighSpeed`) is used
- Only applies when speed data is present and greater than 0
- Maps speeds from 100 Mbps to 800G to appropriate interface types

### 5. Default Fallback (Lowest Priority)
- If nothing else matches, uses `defaults.if_type`
- Defaults to `other` if not specified

## Subinterface Detection and Parent Tracking

SNMP discovery automatically detects subinterfaces based on naming conventions and tracks parent-child relationships.

### What are Subinterfaces?

Subinterfaces are logical interfaces created on top of physical interfaces, commonly used for:
- VLAN tagging (802.1Q)
- Multiple L3 networks on one physical interface
- Traffic segregation and policy enforcement

### Detection Mechanism

Subinterfaces are identified by the presence of dot (`.`) or colon (`:`) separators in the interface name:
- `GigabitEthernet0/0.100` → parent: `GigabitEthernet0/0`, subinterface: `.100`
- `eth0.50` → parent: `eth0`, subinterface: `.50`
- `ge-0/0/0:0` → parent: `ge-0/0/0`, subinterface: `:0`

The separator must appear between non-empty parent and child parts. Interface names ending with separators (e.g., `eth0.`) or starting with separators (e.g., `.100`) are not considered subinterfaces.

### Supported Vendor Formats

| Vendor | Format | Example | Parent |
|--------|--------|---------|--------|
| Cisco IOS/IOS-XE | `Interface.subint` | `GigabitEthernet0/0.100` | `GigabitEthernet0/0` |
| Cisco IOS-XR | `Interface.subint` | `TenGigE0/0/0/0.200` | `TenGigE0/0/0/0` |
| Juniper | `interface:unit` | `ge-0/0/0:0` | `ge-0/0/0` |
| Arista | `Ethernet.subint` | `Ethernet1.100` | `Ethernet1` |
| Nokia SR OS | `ethernet.subint` | `ethernet-1/1/1.50` | `ethernet-1/1/1` |
| Linux | `interface.vlan` | `eth0.100` | `eth0` |

### Two-Phase Processing

Subinterface resolution uses a two-phase approach to handle SNMP discovery ordering issues:

**Phase 1: Mapping (During SNMP Walk)**
- All interfaces are discovered and mapped
- Subinterfaces are immediately assigned type `virtual` (Tier 0 priority)
- Parent relationships are NOT resolved yet (parent names may not exist in registry)

**Phase 2: Post-Processing (After All Interfaces Discovered)**
- `ResolveSubinterfaceParents()` is called after mapping completes
- Parent interface names are extracted from subinterface names
- Parent interfaces are looked up by name in the entity registry
- If parent is found, a reference is stored in the subinterface entity
- If parent is not found (orphan), the subinterface still retains type `virtual`

This two-phase approach is critical because SNMP walks return interfaces in arbitrary order - subinterfaces are often discovered BEFORE their parent interfaces.

### Parent Interface Tracking

When a parent interface is found, the subinterface entity stores a reference:

```go
subinterface.Parent = &diode.Interface{
    Name: parent.Name,
    Type: parent.Type,
}
```

This reference can be used by downstream systems to understand interface hierarchy and relationships.

### Orphan Handling

If a parent interface is not found (e.g., parent administratively down, filtered, or not discoverable via SNMP):
- The subinterface retains type `virtual`
- No parent reference is set (`Parent` field is `nil`)
- No errors are raised
- The subinterface is still included in discovery results

This graceful handling ensures discovery continues successfully even when parent interfaces are missing.

## User-Defined Interface Patterns

You can define custom interface patterns in the `defaults.interface_patterns` list. Each pattern consists of a regular expression match and a NetBox interface type.

### Configuration

```yaml
defaults:
  interface:
    if_type: other  # Fallback type when nothing matches
  interface_patterns:
    - match: "^(GigabitEthernet|Gi).*"
      type: "1000base-t"
    - match: "^(TenGigE|Te).*"
      type: "10gbase-x-sfpp"
    - match: "^Loopback.*"
      type: "virtual"
```

### Pattern Matching Rules

- Patterns are **case-sensitive** regular expressions
- Within user patterns, the **most specific match wins** (longest match)
- If multiple patterns have equal length matches, the **first pattern wins**
- User patterns **always override SNMP ifType, built-in patterns, and speed detection**

### Example

```yaml
interface_patterns:
  - match: "^Gi.*"              # Matches "Gi" prefix (2 chars)
    type: "10gbase-x-sfpp"
  # SNMP ifType would normally map to "1000base-t"
  # Built-in pattern: "^(GigabitEthernet|Gi)\S+" would match 16 chars

# Result for "GigabitEthernet0/0" with ifType=6 (ethernetCsmacd):
# Uses user pattern "10gbase-x-sfpp"
# User pattern wins over SNMP ifType and built-in patterns
```

## Interface Exclusion Patterns

Use `interface_exclude_patterns` to prevent specific interfaces — and their associated IP addresses — from being ingested into NetBox. This is useful for filtering out virtual or host-only interfaces (TAP, veth, loopback, etc.) that are not relevant to your network inventory.

### Configuration

```yaml
defaults:
  interface_exclude_patterns:
    - "^tap.*"      # exclude TAP interfaces (e.g. tap103i0)
    - "^veth.*"     # exclude veth pairs
    - "^docker.*"   # exclude Docker bridge interfaces
```

### Rules

- Patterns are **case-sensitive** regular expressions matched against the full interface name
- A pattern matches anywhere in the name — use `^` to anchor to the start (e.g. `^tap` matches `tap0` but not `mytap0`)
- When an interface is excluded, **all IP addresses assigned to it are also suppressed**
- The `override_defaults` field on a target replaces the global list wholesale (same behaviour as `interface_patterns`)

### Per-Target Override

```yaml
defaults:
  interface_exclude_patterns:
    - "^tap.*"
scope:
  targets:
    - host: "192.168.1.1"
      override_defaults:
        interface_exclude_patterns:
          - "^tap.*"
          - "^veth.*"   # this target also excludes veth interfaces
```

### Invalid Patterns

Invalid regex patterns are logged as warnings and skipped. Valid patterns in the same list are still applied.

## SNMP ifType Mappings

Standard IANA interface types from SNMP `ifType` (`.1.3.6.1.2.1.2.2.1.3`) are automatically mapped:

| SNMP ifType | Value | NetBox Type | Description |
|-------------|-------|-------------|-------------|
| `ethernetCsmacd` | 6 | `1000base-t` | Standard Ethernet |
| `iso88023Csmacd` | 7 | `1000base-t` | ISO 802.3 CSMA/CD |
| `gigabitEthernet` | 117 | `1000base-t` | Gigabit Ethernet |
| `fastEther` | 62 | `100base-tx` | Fast Ethernet |
| `fastEtherFX` | 69 | `100base-fx` | Fast Ethernet Fiber |
| `ieee8023adLag` | 161 | `lag` | Link Aggregation |
| `l2vlan` | 135 | `virtual` | VLAN Interface |
| `l3ipvlan` | 136 | `virtual` | IP VLAN Interface |
| `tunnel` | 131 | `virtual` | Tunnel Interface |
| `softwareLoopback` | 24 | `virtual` | Loopback Interface |
| `propVirtual` | 53 | `virtual` | Proprietary Virtual |
| `other` | 1 | `other` | Other/Unknown |

**Note:** If SNMP returns an unknown ifType value (e.g., vendor-specific types), the system falls back to built-in pattern matching, then speed-based detection.

## Built-In Patterns

When no user patterns match and SNMP ifType is unknown, the system automatically applies built-in patterns for common network equipment:

### Cisco IOS/IOS-XE
- `HundredGig*`, `Hu*` → `100gbase-x-qsfp28`
- `FortyGig*`, `Fo*` → `40gbase-x-qsfpp`
- `TenGig*`, `Te*` → `10gbase-x-sfpp`
- `GigabitEthernet*`, `Gi*` → `1000base-t`
- `FastEthernet*`, `Fa*` → `100base-tx`
- `Port-channel*` → `lag`

### Juniper
- `ge-*` → `1000base-t` (Gigabit Ethernet)
- `xe-*` → `10gbase-x-sfpp` (10 Gigabit Ethernet)
- `et-*` → `40gbase-x-qsfpp` (40 Gigabit Ethernet)
- `ae*` → `lag` (Link Aggregation)
- `lo*` → `virtual` (Loopback)
- `fxp*` → `1000base-t` (Management)

### Nokia SR OS
- `ethernet-*` → `1000base-t`

### Arista
- `Ethernet*` → `1000base-t`

### Virtual/Logical Interfaces
- `Loopback*`, `Lo*` → `virtual`
- `Vlan*`, `vlan*` → `virtual`
- `Tunnel*`, `Tu*` → `virtual`

### Management Interfaces
- `Management*`, `Mg*`, `mgmt*` → `1000base-t`

### Linux Interfaces
- `eth*`, `ens*`, `enp*`, `swp*` → `1000base-t`

### LAG Interfaces
- `Port-channel*` → `lag` (Cisco)
- `Bundle-Ether*` → `lag` (Cisco IOS-XR)

## Speed-Based Detection

When SNMP ifType is unknown and no patterns match, the system uses interface speed from SNMP `ifHighSpeed` (`.1.3.6.1.2.1.31.1.1.1.15`) or `ifSpeed` (`.1.3.6.1.2.1.2.2.1.5`) to determine the type:

| Speed (Mbps) | Interface Type |
|--------------|----------------|
| ≤ 100 | `100base-tx` |
| ≤ 1000 | `1000base-t` |
| ≤ 2500 | `2.5gbase-t` |
| ≤ 5000 | `5gbase-t` |
| ≤ 10000 | `10gbase-x-sfpp` |
| ≤ 25000 | `25gbase-x-sfp28` |
| ≤ 40000 | `40gbase-x-qsfpp` |
| ≤ 50000 | `50gbase-x-sfp56` |
| ≤ 100000 | `100gbase-x-qsfp28` |
| ≤ 200000 | `200gbase-x-qsfp56` |
| ≤ 400000 | `400gbase-x-qsfp112` |
| > 400000 | `800gbase-x-qsfp-dd` |

**Note:** Speed-based detection is only used when SNMP ifType is unknown AND no patterns match.

## Complete Matching Flow Example

```yaml
defaults:
  if_type: other
  interface_patterns:
    - match: "^Gi.*"
      type: "10gbase-x-sfpp"  # User override for Gigabit interfaces
```

### Interface Matching Results

| Interface Name | SNMP ifType | User Match? | SNMP Mapping | Built-in Match? | Speed | Final Type | Reason |
|----------------|-------------|-------------|--------------|-----------------|-------|------------|--------|
| `GigabitEthernet0/0.100` | 6 | - | - | - | 1000 | `virtual` | Tier 0: Subinterface |
| `eth0.50` | 6 | - | - | - | 1000 | `virtual` | Tier 0: Subinterface |
| `ge-0/0/0:0` | 6 | - | - | - | 10000 | `virtual` | Tier 0: Subinterface |
| `GigabitEthernet0/0` | 6 | `^Gi.*` ✓ | - | - | 1000 | `10gbase-x-sfpp` | Tier 1: User pattern |
| `TenGigabitEthernet1/0/1` | 6 | ✗ | `1000base-t` | - | 10000 | `1000base-t` | Tier 2: SNMP ifType |
| `Port-channel1` | 161 | ✗ | `lag` | - | 10000 | `lag` | Tier 2: SNMP ifType |
| `CustomInt0` | 999 | ✗ | unknown | ✗ | 25000 | `25gbase-x-sfp28` | Tier 4: Speed |
| `UnknownInt0` | 1 | ✗ | `other` | ✗ | 0 | `other` | Tier 2: SNMP ifType |

## Zero-Configuration Support

If no `interface_patterns` are configured, the system automatically provides intelligent defaults for 80-90% of deployments through SNMP ifType mappings and built-in patterns:

```yaml
defaults:
  if_type: other
  # No interface_patterns specified
```

### Automatic Results

**Standard SNMP ifTypes (Most Common):**
- Any interface with `ifType=6` (ethernetCsmacd) → `1000base-t`
- Any interface with `ifType=161` (ieee8023adLag) → `lag`
- Any interface with `ifType=24` (softwareLoopback) → `virtual`
- Any interface with `ifType=135` (l2vlan) → `virtual`

**Vendor-Specific via Built-in Patterns:**
- Cisco `GigabitEthernet0/0` → `1000base-t`
- Juniper `ge-0/0/0` → `1000base-t`
- Arista `Ethernet1` → `1000base-t`
- Cisco `Port-channel1` → `lag`

**Speed-Based Fallback:**
- Generic interfaces with unknown ifType but speed data → Speed-based detection
- Unknown interfaces without speed → `other` (defaults.if_type)