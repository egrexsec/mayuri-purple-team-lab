# Public sanitization policy

## Never publish

- passwords, tokens, API keys, private keys, recovery material, cookies, or webhook URLs;
- exact private/overlay addresses, CIDRs, gateways, routes, or firewall rules;
- internal DNS names, public domain names tied to lab services, or service URLs;
- VM IDs, MAC addresses, interface identifiers, serials, or host-local paths;
- usernames or SSH identity locations;
- raw EVTX, PCAP, memory images, disk images, malware, or unredacted alert payloads;
- screenshots containing browser profiles, credentials, tokens, addresses, or internal names.

## Safe abstractions

Use role aliases such as:

- `LAB-HV`, `LAB-FW`, `LAB-DC`, `LAB-WIN`, `LAB-SOC`, `LAB-KALI`, `LAB-DFIR`, `LAB-CTI`;
- `MGMT-NET`, `ENTERPRISE-NET`, `ATTACK-NET`, `DFIR-NET`;
- `[REDACTED]` for intentionally removed values.

## Evidence transformation

1. extract the minimum facts needed to prove a control;
2. replace live identifiers with stable aliases;
3. omit payload bodies not required for the finding;
4. preserve timestamps only when they do not reveal sensitive operational patterns;
5. record status, technique, control, and result in text;
6. run automated checks and manual review before push.

## Review checklist

- [ ] No private or overlay address appears.
- [ ] No MAC address or live hostname appears.
- [ ] No internal/public service domain appears.
- [ ] No key, token, password, webhook, or credential value appears.
- [ ] No absolute operator path appears.
- [ ] No raw evidence or malware is present.
- [ ] Claims distinguish current, historical, partial, and planned state.
