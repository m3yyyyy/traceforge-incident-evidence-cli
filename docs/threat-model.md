# Threat model

## Protected assets

- credentials accidentally present in operational logs;
- the integrity of generated reports and timelines;
- analyst workstations processing untrusted log files;
- incident identifiers and operational metadata.

## Trust boundaries

Input logs are untrusted. Structured values cross the persistence boundary only after recursive redaction. Plain-text values cross it only after pattern-based redaction. Output is written to a new or empty directory and is not transmitted over a network.

## Controls

| Risk | Control |
|---|---|
| Credential disclosure | Structured sensitive-key replacement plus text credential rules |
| Malformed input ambiguity | Fail-closed JSON and timestamp parsing with file and line diagnostics |
| Resource exhaustion | Configurable maximum line size and event count |
| Evidence modification | Source and artifact SHA-256 digests with a `verify` command |
| Path traversal from a manifest | Reject absolute, parent and duplicate artifact paths |
| Accidental overwrite | Refuse non-empty output directories |
| Hidden network exfiltration | Standard-library-only runtime with no network package or telemetry |

## Residual risks

Pattern redaction cannot guarantee removal of unknown secret formats. Source filenames, hostnames, trace IDs and request IDs are intentionally preserved for correlation and may themselves be sensitive. Analysts must review bundles before external distribution.

A local attacker who can replace both artifacts and `manifest.json` can create a new internally consistent bundle. Authenticity requires signing the manifest or storing its digest in an independent trusted system.
