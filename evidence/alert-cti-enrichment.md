# Wazuh and Splunk alert CTI enrichment

## Scope

This validation exercised credential-free reference implementations corresponding to the live Wazuh and Splunk enrichment path. Raw alerts, provider responses, route URLs, credentials, internal addresses, and private topology remain outside Git.

## Wazuh validation

1. A benign high-severity Wazuh-shaped alert containing a public IPv4 observable entered the source-restricted relay.
2. The authenticated broker returned bounded OpenCTI and Shodan context from cache.
3. The staged orchestration workflow returned structured triage with a `context_only` CTI verdict.
4. The Wazuh integration wrote a bounded summary rather than duplicating the raw alert.
5. Local rule `100950` ingested the summary at level 5, below the outbound integration threshold of level 10.
6. The manager restart completed with all previously connected agents active and no new configuration errors.

## Splunk validation

1. A controlled, harmless PowerShell script block matched the existing scheduled detection.
2. Splunk reported one result and fired its webhook action.
3. The rotated, tokenized relay path accepted the alert without recording the route token in logs.
4. The broker attached cached OpenCTI and Shodan context.
5. The credential-backed orchestration workflow forwarded the alert to the IR receiver.
6. A new case and evidence manifest were created with one bounded CTI block and a `context_only` verdict.

## Security checks

- Workflow exports contain a credential reference, not a static receiver token.
- OpenCTI, Shodan, broker, relay, and Wazuh route secrets were absent from the scanned artifacts.
- HTTP logs contain source and status only; tokenized paths are omitted.
- Authenticated HTTP clients reject redirects rather than forwarding credentials or alert bodies to a redirect target.
- Provider and relay responses, cache rows, cache entries, and the SQLite main database have explicit ceilings.
- Startup configuration rejects non-finite, non-positive, and excessive timeout or size values.
- Provider failure remains fail-open in unit coverage.
- Unsupported, multicast, and other non-unicast/non-public observables are skipped.
- Duplicate observables are normalized and capped.
- Repeated provider work is reduced through bounded SQLite caching.
- Wazuh summary fields are whitelisted and truncated, and a runtime recursion guard skips prior enrichment summaries.

## Result

Both SIEM paths were live validated. CTI remains advisory context: enrichment can raise an analyst review signal, but it cannot independently mark an alert malicious or suppress the original alert.