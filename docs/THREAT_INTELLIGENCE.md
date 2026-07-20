# Threat-intelligence enrichment

## Platform

The CTI role uses OpenCTI Community with one worker and the official Shodan internal-enrichment connector. Search, object storage, queue, and cache dependencies remain private to the container network; only the application interface is published to the isolated lab segment.

## Security posture

- platform and connector images are version-pinned;
- runtime secrets are root-owned and excluded from Git;
- the external API key is injected through a protected runtime path;
- automatic enrichment is disabled to control noise and API consumption;
- telemetry is disabled;
- backend database/queue ports are not published;
- application and connector persistence are tested across reboot.

## Validated enrichment

A benign public IPv4 observable was created through the supported OpenCTI client. The Shodan connector acknowledged the request, submitted a STIX bundle, and completed the work with zero connector errors. The observable and connector registration persisted across a guest reboot.

## Analyst workflow

1. create or select an IPv4 observable or indicator;
2. confirm data handling and TLP expectations;
3. manually request Shodan enrichment;
4. review returned infrastructure, service, and external-reference objects;
5. correlate with the case without treating enrichment as proof of maliciousness;
6. record only sanitized conclusions.

## Limitation

External enrichment quality and entitlement can change independently of OpenCTI health. Revalidate API access and connector compatibility after upgrades.
