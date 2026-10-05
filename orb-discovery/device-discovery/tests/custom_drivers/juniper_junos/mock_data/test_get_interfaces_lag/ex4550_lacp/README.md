# Junos LAG membership scenario: EX4550, two LACP bundles

`get-interface-information-terse.xml` is a terse reply captured from an
EX4550-32F running Junos 15.1R7-S13, reduced to the relevant interfaces.
Descriptions were removed and addresses replaced with documentation addresses;
interface names, hierarchy and the aggregation fields are as the device sent
them, namespaces included.

It pins three things:

- Membership is carried on the member's logical unit, as an `aenet` address
  family whose `ae-bundle-name` names the matching unit of the bundle.
- `xe-0/0/24` has two units, `.0` and `.1876`, pointing at `ae120.0` and
  `ae120.1876`. They are one physical membership, `xe-0/0/24 -> ae120`.
- The aggregates themselves (`ae0`, `ae120`) carry `inet` / `mpls` families and
  no `aenet`, so they are never read as members.
