# Recovery and snapshot model

## Snapshot strategy

Milestone snapshots are maintained around major changes for the firewall, identity server, Windows target, SOC, attacker workstation, DFIR workstation, and CTI platform.

Recommended labels are semantic rather than environment-revealing:

- `baseline-os-ready`
- `pre-identity-change`
- `post-telemetry-validation`
- `pre-tooling-stage`
- `post-tooling-validation`
- `pre-connector-enable`
- `post-enrichment-validation`

## Rules

- Never include RAM state in a running domain controller snapshot.
- Quiesce or stop stateful application stacks before clean snapshots when practical.
- Record why a snapshot exists and which validation preceded it.
- Treat snapshots as rollback points, not backups.
- Monitor thin-pool data and metadata capacity before adding snapshots.
- Remove obsolete checkpoints only under explicit change approval.

## Recovery sequence

1. stop the affected workflow;
2. preserve logs and failure evidence;
3. identify the last known-good milestone;
4. confirm snapshot/storage health;
5. restore only the affected system or plane;
6. boot without executing attack activity;
7. validate identity, DNS, time, networking, and sensors;
8. re-run a benign health check;
9. document the recovery result.

## Backup gap

A complete application-consistent export and restore drill for every stateful platform is not yet claimed. VM snapshots, OpenCTI volumes, SIEM indexes, directory services, and DFIR evidence require distinct backup methods.
