# TraceForge Incident Evidence CLI

[![CI](https://github.com/m3yyyyy/traceforge-incident-evidence-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/m3yyyyy/traceforge-incident-evidence-cli/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.27.1-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

TraceForge turns scattered JSON, NDJSON and text logs into a redacted, correlated and tamper-evident incident bundle. It is designed for IT operations, platform engineering and security-response workflows where raw logs may contain credentials and the final timeline must be easy to review and verify.

## Why this project exists

During an incident, useful events are spread across services and hosts. Copying them into a document by hand is slow, inconsistent and risky when logs contain tokens or passwords. TraceForge provides a local-first pipeline that:

- streams supported log files and directories in deterministic order;
- requires RFC3339 timestamps and fails clearly on ambiguous records;
- redacts common passwords, tokens, API keys, authorization headers, cookies and URL credentials before persistence;
- correlates events by trace ID, request ID and hostname;
- exports a Markdown report for responders and JSON for automation;
- records SHA-256 hashes for every input and generated artifact;
- verifies that a completed evidence bundle has not been modified.

The runtime uses only the Go standard library and makes no network requests.

## Quick start

Open a new PowerShell window after installing Go, then confirm the toolchain:

```powershell
go version
```

Build TraceForge:

```powershell
git clone https://github.com/m3yyyyy/traceforge-incident-evidence-cli.git
Set-Location .\traceforge-incident-evidence-cli
go build -trimpath -o traceforge.exe .\cmd\traceforge
```

Create an evidence bundle from the included synthetic logs:

```powershell
.\traceforge.exe analyze `
  --incident INC-DEMO-001 `
  --input .\testdata\api.jsonl `
  --input .\testdata\worker.log `
  --output .\bundles\INC-DEMO-001
```

Expected summary:

```text
bundle created: .\bundles\INC-DEMO-001
incident: INC-DEMO-001 | sources: 2 | events: 6 | correlations: 4 | redactions: 3
artifacts: report.md, timeline.json, manifest.json
```

Verify the bundle later:

```powershell
.\traceforge.exe verify --bundle .\bundles\INC-DEMO-001
```

```text
verified: .\bundles\INC-DEMO-001 | incident: INC-DEMO-001 | artifacts: 2 | algorithm: SHA-256
```

## Supported input

Directories are searched recursively for `.json`, `.jsonl`, `.ndjson`, `.log` and `.txt` files.

Structured records are one JSON object per line. Recognized fields include:

| Purpose | Accepted fields |
|---|---|
| Timestamp | `timestamp`, `@timestamp`, `time`, `ts` |
| Message | `message`, `msg`, `event`, `description` |
| Severity | `level`, `severity`, `log.level` |
| Service | `service`, `service.name`, `app`, `application` |
| Host | `host`, `hostname`, `host.name` |
| Trace | `traceId`, `trace_id`, `trace.id` |
| Request | `requestId`, `request_id`, `request.id`, `correlationId`, `correlation_id` |

Text records must start with an RFC3339 timestamp. An optional severity may follow, and correlation fields use `key=value` syntax:

```text
2026-09-02T10:14:01.910Z ERROR service=worker host=worker-02 trace_id=trace-demo-7 request_id=req-demo-21 dependency_timeout
```

## Evidence bundle

| File | Purpose |
|---|---|
| `report.md` | Human-readable sources, correlation summary and ordered timeline |
| `timeline.json` | Machine-readable sanitized evidence using the `traceforge/v1` schema |
| `manifest.json` | SHA-256 and byte length for each generated artifact |

Input hashes are stored inside the protected timeline and report. Absolute input paths outside the working directory are reduced to filenames so local usernames and directory structures are not exposed.

## Safety behavior

- Malformed JSON and missing or invalid timestamps stop analysis with the exact file and line.
- Lines default to a 2 MiB maximum and analysis defaults to 250,000 events.
- Existing non-empty output directories are never overwritten.
- Manifest verification rejects absolute paths, parent traversal and duplicate artifacts.
- Reports preserve operational identifiers for correlation, so review them before sharing.

TraceForge provides tamper evidence, not proof of authorship. For a formal chain of custody, sign the manifest or record its hash in an independent trusted system. See the [threat model](docs/threat-model.md) and [architecture notes](docs/architecture.md).

## Development

```powershell
go fmt "./cmd/..." "./internal/..."
go test ./...
go vet "./cmd/..." "./internal/..."
go test -bench=. ./internal/redact
```

CI tests Windows, Linux and macOS, runs static analysis and uses the race detector on Linux. Tags matching `v*` build five cross-platform binaries, publish a checksum file and create a GitHub release.

## License

[MIT](LICENSE)
