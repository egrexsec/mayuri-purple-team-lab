# Network segmentation

## Logical segments

| Segment alias | Primary purpose | Expected systems |
|---|---|---|
| `MGMT-NET` | Hypervisor and authorized administration | Hypervisor, firewall management |
| `ENTERPRISE-NET` | Windows identity, endpoint, SOC, and CTI services | Identity server, target, SOC, CTI |
| `ATTACK-NET` | Authorized adversary simulation | Kali workstation |
| `DFIR-NET` | Evidence collection and analysis | DFIR workstation |

Exact CIDRs, gateways, interface names, routes, and firewall rules are intentionally not published.

## Policy intent

- Attack-to-enterprise access is denied unless a specific exercise requires a narrow target/service path.
- DFIR-to-enterprise access is limited to approved collection services and target assets.
- Lab systems do not receive unrestricted management access to the home or production network.
- Internet access supports updates and approved external enrichment, not inbound exposure.
- Management traffic is kept separate from simulated attack traffic.
- The virtual firewall remains the authoritative inter-zone policy point.

## Validation checklist

1. verify the guest is attached to the expected logical segment;
2. confirm gateway, DNS, and time before testing application traffic;
3. test required flows from the source guest, not only from the hypervisor;
4. confirm forbidden backend and management ports remain unreachable;
5. record the policy intent and result without publishing live rules;
6. remove temporary routes or interfaces after a validation workaround.

## Remote access

Remote administration uses a private overlay and authenticated management paths. Route advertisements, peer addresses, SSH identities, and access-control details are excluded from this public repository.
