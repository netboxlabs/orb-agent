# Device Discovery - Interface Type Matching

The device discovery backend uses an intelligent **five-tier priority system** to automatically determine interface types. This system provides zero-configuration support for common network equipment while allowing fine-grained customization through user-defined patterns.

## Priority Order

Interface types are determined using the following priority order (first match wins):

**1. Structural Detection (Highest Priority)**
   - Subinterfaces (e.g., `GigabitEthernet0/0.100`, `ethernet-1/1.0`) are always assigned type `virtual`
   - This rule applies regardless of any patterns or speed data

**2. User-Defined Patterns**
   - Patterns configured in `defaults.interface_patterns` are checked first
   - If ANY user pattern matches, the most specific (longest) user match is used
   - User patterns ALWAYS take priority over built-in patterns, even if the built-in pattern would be more specific

**3. Built-In Patterns**
   - If no user pattern matches, built-in vendor patterns are checked
   - Provides zero-configuration support for common network equipment (Cisco, Juniper, Arista, Nokia, etc.)
   - Most specific (longest) built-in match is used

**4. Speed-Based Detection**
   - If no patterns match, interface speed (from NAPALM) is used to determine type
   - Only applies when speed data is present and greater than 0
   - Maps speeds from 100 Mbps to 800G to appropriate interface types

**5. Default Fallback (Lowest Priority)**
   - If nothing else matches, uses `defaults.if_type`
   - Defaults to `other` if not specified

## User-Defined Interface Patterns

You can define custom interface patterns in the `defaults.interface_patterns` list. Each pattern consists of a regular expression match and a NetBox interface type.

**Configuration:**
```yaml
defaults:
  if_type: other  # Fallback type when nothing matches
  interface_patterns:
    - match: "^(GigabitEthernet|Gi).*"
      type: "1000base-t"
    - match: "^(TenGigE|Te).*"
      type: "10gbase-x-sfpp"
    - match: "^Loopback.*"
      type: "virtual"
```

**Pattern Matching Rules:**
- Patterns are **case-sensitive** regular expressions
- Within user patterns, the **most specific match wins** (longest match)
- If multiple patterns have equal length matches, the **first pattern wins**
- User patterns **always override built-in patterns**, regardless of specificity

**Example:**
```yaml
interface_patterns:
  - match: "^Gi.*"              # Matches "Gi" prefix (2 chars)
    type: "10gbase-x-sfpp"
  # Built-in pattern: "^(GigabitEthernet|Gi)\S+" would match 16 chars

# Result for "GigabitEthernet0/0": Uses user pattern "10gbase-x-sfpp"
# User pattern wins even though built-in is more specific
```

## Built-In Patterns

When no user patterns are configured (or none match), the system automatically applies built-in patterns for common network equipment:

**Cisco IOS/IOS-XE:**
- `HundredGig*`, `Hu*` → `100gbase-x-qsfp28`
- `FortyGig*`, `Fo*` → `40gbase-x-qsfpp`
- `TenGig*`, `Te*` → `10gbase-x-sfpp`
- `GigabitEthernet*`, `Gi*` → `1000base-t`
- `FastEthernet*`, `Fa*` → `100base-tx`

**Juniper:**
- `ge-*` → `1000base-t` (Gigabit Ethernet)
- `xe-*` → `10gbase-x-sfpp` (10 Gigabit Ethernet)
- `et-*` → `40gbase-x-qsfpp` (40 Gigabit Ethernet)
- `ae*` → `lag` (Link Aggregation)
- `lo*` → `virtual` (Loopback)

**Nokia SR OS:**
- `ethernet-*` → `1000base-t`

**Arista:**
- `Ethernet*` → `1000base-t`

**Virtual/Logical Interfaces:**
- `Loopback*`, `Lo*` → `virtual`
- `Vlan*`, `vlan*` → `virtual`
- `Tunnel*`, `Tu*` → `virtual`

**Management Interfaces:**
- `Management*`, `Mg*`, `mgmt*` → `1000base-t`
- `fxp*` → `1000base-t` (Juniper management)

**Linux Interfaces:**
- `eth*`, `ens*`, `enp*`, `swp*` → `1000base-t`

**LAG Interfaces:**
- `Port-channel*` → `lag` (Cisco)
- `Bundle-Ether*` → `lag` (Cisco IOS-XR)

## Speed-Based Detection

When no patterns match, the system uses interface speed (in Mbps from NAPALM) to determine the type:

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

**Note:** Speed-based detection is **skipped** if any pattern (user or built-in) matches the interface name, even if the speed suggests a different type.

## Complete Matching Flow Example

```yaml
defaults:
  if_type: other
  interface_patterns:
    - match: "^Gi.*"
      type: "10gbase-x-sfpp"  # User override for Gigabit interfaces
```

**Interface Matching Results:**

| Interface Name | Has Parent? | User Match? | Built-in Match? | Speed | Final Type | Reason |
|----------------|-------------|-------------|-----------------|-------|------------|--------|
| `GigabitEthernet0/0.100` | Yes | - | - | - | `virtual` | Tier 1: Subinterface |
| `GigabitEthernet0/0` | No | `^Gi.*` ✓ | - | 1000 | `10gbase-x-sfpp` | Tier 2: User pattern |
| `TenGigabitEthernet1/0/1` | No | ✗ | `^(TenGig\|Te).*` ✓ | 10000 | `10gbase-x-sfpp` | Tier 3: Built-in |
| `Ethernet1` | No | ✗ | ✗ | 25000 | `25gbase-x-sfp28` | Tier 4: Speed |
| `UnknownInt0` | No | ✗ | ✗ | 0 | `other` | Tier 5: Default |

## Zero-Configuration Support

If no `interface_patterns` are configured, the system automatically applies built-in patterns to provide intelligent defaults for 80-90% of deployments:

```yaml
defaults:
  if_type: other
  # No interface_patterns specified
```

**Automatic Results:**
- Cisco `GigabitEthernet0/0` → `1000base-t`
- Juniper `ge-0/0/0` → `1000base-t`
- Arista `Ethernet1` → `1000base-t`
- Any `Loopback0` → `virtual`
- Any `ae0` → `lag`
- Generic interfaces with speed data → Speed-based detection
- Unknown interfaces without speed → `other` (defaults.if_type)