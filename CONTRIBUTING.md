# Contributing

Thank you for helping improve TraceForge.

## Local verification

Use Go 1.27.1 or the version declared in `go.mod`:

```console
go fmt "./cmd/..." "./internal/..."
go test ./...
go vet "./cmd/..." "./internal/..."
go build -trimpath ./cmd/traceforge
```

Changes to parsing or redaction require focused tests. Test fixtures must be synthetic and must never contain real credentials, customer logs or personal data.

## Pull requests

Keep each change focused, explain its security impact and document any new input format or output field. All required CI checks must pass before merging.
