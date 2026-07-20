# Known limitations

- This repository documents architecture and validated behavior; it does not reproduce live deployment configuration.
- Exact firewall policy and remote-access controls are intentionally omitted.
- Splunk field normalization is incomplete for some Windows raw XML sources.
- Wazuh and Splunk coexist for learning and validation; this is not presented as a production reference architecture.
- The DFIR role requires a fresh full-tool/service preflight before the next exercise.
- Velociraptor collection was validated during deployment, but historical proof is not current-service health evidence.
- OpenCTI is currently accessed over HTTP only inside the isolated lab; SSO/TLS are future hardening items.
- Automatic Shodan enrichment remains disabled by design.
- Snapshots exist, but complete application-consistent restore drills remain outstanding.
- The public repository contains no raw evidence, deployment secrets, or runnable attack automation.
