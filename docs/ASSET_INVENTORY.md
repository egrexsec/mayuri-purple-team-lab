# Sanitized asset inventory

Aliases are intentionally decoupled from live VM IDs, hostnames, addresses, MACs, and internal DNS.

| Alias | Role | OS family | Segment | Verified capabilities |
|---|---|---|---|---|
| `LAB-HV` | Hypervisor | Proxmox VE | Management | VM lifecycle, thin storage, snapshots, QEMU guest operations |
| `LAB-FW` | Router/firewall | OPNsense | All lab segments | Inter-segment routing, NAT, DHCP/DNS policy boundaries |
| `LAB-DC` | Identity server | Windows Server | Enterprise | AD DS, DNS, Netlogon, GPO, Windows telemetry agents |
| `LAB-WIN` | Validation endpoint | Windows 11 | Enterprise | Domain trust, Defender, Sysmon, PowerShell logging, Wazuh, Splunk, Velociraptor |
| `LAB-SOC` | SOC platform | Ubuntu Server | Enterprise | Wazuh all-in-one, Splunk, Suricata, Sigma/YARA/packet tooling |
| `LAB-KALI` | Authorized attacker | Kali Linux | Attack | Nmap, NetExec, Impacket, BloodHound collector, Certipy, Atomic Operator |
| `LAB-DFIR` | Forensics workstation | Ubuntu/REMnux-style | DFIR | Evidence workspace, YARA, packet analysis, staged timeline/memory tooling |
| `LAB-CTI` | CTI/OSINT platform | Ubuntu Server | Enterprise | OpenCTI, worker, search/object dependencies, official Shodan connector |

## Status vocabulary

- **Verified:** observed live during a read-only or benign validation check.
- **Live validated:** exercised end-to-end with a new controlled event and confirmed output.
- **Partially verified:** components are staged, but the complete role should be revalidated before use.
- **Planned:** documented intent without current execution evidence.

## Deliberately omitted

- exact compute allocations and storage paths;
- VM IDs and snapshot names;
- addresses, ranges, gateways, and DNS zones;
- interface identifiers and MAC addresses;
- service URLs and administrative ports;
- usernames, keys, tokens, and credentials.
