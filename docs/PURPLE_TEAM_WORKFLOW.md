# Purple-team workflow

## Operating sequence

1. **Authorize** — define the asset, behavior, ATT&CK technique, expected telemetry, and cleanup.
2. **Preflight** — verify snapshot, identity, DNS, time, sensor health, and disk headroom.
3. **Execute** — run one low-impact behavior on the designated endpoint.
4. **Observe** — confirm native event and Sysmon records before tuning the SIEM.
5. **Detect** — validate Wazuh/Splunk logic against positive and negative evidence.
6. **Investigate** — collect supporting context and create a case/timeline.
7. **Clean up** — remove artifacts and verify the endpoint returns to baseline.
8. **Publish** — commit only sanitized, text-based proof and explicit limitations.

## Control gates

- Stop if AD trust or time synchronization is unhealthy.
- Do not run multiple persistence techniques at once.
- Do not disable Defender globally or add broad exclusions.
- Do not expand network policy to make a test easier without a narrow, reversible justification.
- Require explicit approval for containment, account changes, isolation, or deletes.

## Exercise template

| Field | Required content |
|---|---|
| Scenario ID | Stable public-safe identifier |
| ATT&CK mapping | Technique/sub-technique |
| Target alias | Authorized lab alias only |
| Preconditions | Snapshot, telemetry, identity, network |
| Execution | Small deterministic action |
| Expected telemetry | Native log, Sysmon, SIEM fields |
| Cleanup | Exact reversal and verification |
| Evidence | Sanitized summary and integrity metadata |
| Result | Pass, partial, blocked, or fail |

## Recommended next exercise

Validate a benign scheduled-task create/remove sequence on `LAB-WIN` with native Task Scheduler logs, Sysmon process evidence, SIEM detection, negative controls, cleanup, and a short DFIR timeline.
