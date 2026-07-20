# OpenCTI and Shodan enrichment validation

## Objective

Validate the official Shodan connector against a benign public IPv4 observable while protecting the API credential and preserving application state across reboot.

## Result

**PASS — live validated**

- The external API credential passed an account check without being printed.
- OpenCTI registered the connector as active internal enrichment for IPv4 observables and indicators.
- An analyst-triggered benign enrichment completed with zero connector errors.
- The connector submitted a STIX bundle and completed all queued processing expectations.
- OpenCTI, its dependencies, the connector registration, and the observable persisted after reboot.
- Only the OpenCTI application interface was exposed; dependency ports remained private.

## Controls demonstrated

- pinned images;
- root-only runtime secrets;
- opt-in connector profile;
- automatic enrichment disabled;
- benign end-to-end API validation;
- reboot and rollback-checkpoint validation.

## Sanitization

The observable value, addresses, VM metadata, image digests, connector/work identifiers, credential details, and service URL are omitted.
