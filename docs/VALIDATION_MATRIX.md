# Validation matrix

| Control | Validation method | Status | Evidence location |
|---|---|---|---|
| Segment separation | Hypervisor bridge inventory and source-side reachability tests | Verified | Architecture/network docs |
| AD core services | Service and domain checks | Verified | Asset inventory |
| Domain member trust | Secure-channel test | Verified | Asset inventory |
| Windows telemetry agents | Service/log presence checks | Verified | Telemetry pipeline |
| Wazuh stack | Manager, indexer, dashboard service checks | Verified | Telemetry pipeline |
| Splunk runtime | Process and ingestion-path validation | Verified | PowerShell evidence summary |
| Suricata runtime | Service check and prior config validation | Verified | Telemetry pipeline |
| Detection-to-case | Fresh benign replay through alert/webhook/case path | Live validated | `evidence/powershell-detection-to-case.md` |
| Duplicate suppression | Subsequent scheduled search suppressed repeat | Live validated | `evidence/powershell-detection-to-case.md` |
| Velociraptor collection | Benign remote endpoint collection | Validated at deployment | `evidence/velociraptor-collection.md` |
| OpenCTI health | Container/application health and HTTP response | Verified | CTI evidence summary |
| Shodan enrichment | Benign observable work completed with zero errors | Live validated | `evidence/opencti-shodan-enrichment.md` |
| Reboot persistence | Guest reboot plus service/object checks | Verified | CTI evidence summary |
| Snapshot recovery point | Clean milestone snapshots enumerated | Verified | Recovery doc |
| Application-consistent restore | Full restore drill | Planned | Known limitations |

## Result language

- **Verified** means observed current state.
- **Live validated** means a new controlled event traversed the full path.
- **Validated at deployment** means historical evidence exists but a fresh preflight is required.
- **Planned** means no completed proof is claimed.
