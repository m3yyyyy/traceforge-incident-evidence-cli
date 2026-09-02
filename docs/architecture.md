# Architecture

TraceForge is a zero-dependency Go CLI with a one-way evidence pipeline:

```text
files/directories
      |
      v
bounded line scanner --> format parser --> redaction boundary
                                             |
                                             v
                                      sanitized events
                                             |
                                             v
                                  deterministic correlation
                                             |
                                             v
                              Markdown + JSON + SHA-256 manifest
```

## Package boundaries

- `internal/ingest` expands inputs deterministically and scans files without loading the entire source into memory. It rejects oversized lines, unsupported timestamp formats and malformed JSON records.
- `internal/redact` recursively replaces credential-shaped JSON fields and sanitizes common credentials in text values.
- `internal/correlate` sorts by timestamp, source and line, assigns stable sequence numbers and groups repeated trace IDs, request IDs and hosts.
- `internal/evidence` writes a human-readable report, a machine-readable timeline and a manifest containing artifact digests.
- `internal/cli` validates the command boundary and composes the pipeline.

## Determinism and resource limits

Input paths and correlations are sorted. Events with equal timestamps use source path and line number as stable tie-breakers. `--max-events` and `--max-line-bytes` cap memory and per-record work; exceeding either limit stops the run.

The scanner streams source bytes and records a SHA-256 digest for each input. Timeline sorting retains sanitized events in memory, so the event cap is an explicit safety boundary rather than an unlimited-memory promise.
