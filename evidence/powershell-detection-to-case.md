# PowerShell detection-to-case validation

## Objective

Prove that a controlled PowerShell behavior on the designated Windows target produces endpoint telemetry, matches the expected Splunk detection, traverses the constrained webhook path, and creates a structured investigation case.

## Result

**PASS — live validated on 2026-07-18**

This is the Mayuri execution/evidence leg of the [Validated PowerShell Detection Lifecycle v1](https://github.com/egrexsec/cybersecurity-playbook/tree/main/detections/packs/validated-powershell-lifecycle-v1). The playbook is authoritative for the canonical Sigma source, fixture set, generated-query hashes, and human-readable validation record. DetLab-DAC is the presentation and conversion surface.

- A benign PowerShell replay generated a fresh Operational event.
- The scheduled Splunk search returned one matching result.
- The webhook action fired through a source-restricted relay.
- The orchestration workflow normalized the alert.
- An authenticated receiver created a high-severity investigation case mapped to PowerShell execution.
- The following scheduler cycle suppressed the duplicate.

## Controls demonstrated

- victim-first controlled execution;
- native Windows event collection;
- Splunk search and alert action;
- segmented-network relay;
- authenticated webhook intake;
- deterministic case generation;
- duplicate suppression.

## Sanitization

Asset names, addresses, domains, exact timestamps, credentials, receiver locations, case IDs, and raw XML are omitted. The validation date is retained for portfolio traceability.
