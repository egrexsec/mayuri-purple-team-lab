# Sanitized evidence

This directory contains **text-only public summaries** of controlled lab validations.

Raw logs, EVTX, PCAP, memory images, malware, credentials, internal identifiers, and full payloads remain outside Git.

| Summary | Validation |
|---|---|
| [PowerShell detection to case](powershell-detection-to-case.md) | Endpoint event through Splunk and orchestration to a deduplicated case |
| [OpenCTI and Shodan enrichment](opencti-shodan-enrichment.md) | Official connector enrichment and reboot persistence |
| [Alert CTI enrichment](alert-cti-enrichment.md) | Wazuh and Splunk alerts enriched through a cached, fail-open broker |
| [Velociraptor collection](velociraptor-collection.md) | Benign endpoint collection during deployment validation |
