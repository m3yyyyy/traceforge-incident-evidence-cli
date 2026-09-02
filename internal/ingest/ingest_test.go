package ingest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/redact"
)

func TestReaderParsesAndSanitizesJSONL(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "app.jsonl")
	content := strings.Join([]string{
		`{"timestamp":"2026-09-02T12:00:00Z","level":"error","message":"request failed token=secret","trace_id":"tr-1","request_id":"req-1","service":{"name":"api"}}`,
		`{"timestamp":"2026-09-02T12:00:01Z","message":"retry","trace_id":"tr-1","password":"hidden"}`,
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	reader, err := New(Config{MaxEvents: 10, MaxLineBytes: 4096}, redact.New())
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.Read([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 2 || result.Sources[0].Redactions != 2 {
		t.Fatalf("unexpected result: %#v", result)
	}
	if result.Sources[0].Path != "app.jsonl" || len(result.Sources[0].SHA256) != 64 {
		t.Fatalf("source provenance not safely recorded: %#v", result.Sources[0])
	}
	if result.Events[0].Service != "api" || result.Events[0].TraceID != "tr-1" {
		t.Fatalf("fields not extracted: %#v", result.Events[0])
	}
	if strings.Contains(result.Events[0].Message, "secret") {
		t.Fatalf("secret leaked: %s", result.Events[0].Message)
	}
}

func TestReaderRejectsMalformedStructuredRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte(`{"timestamp":`), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, _ := New(Config{MaxEvents: 10, MaxLineBytes: 4096}, redact.New())
	_, err := reader.Read([]string{path})
	if err == nil || !strings.Contains(err.Error(), "invalid JSON record") {
		t.Fatalf("expected malformed JSON error, got %v", err)
	}
}

func TestReaderParsesText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "app.log")
	line := "2026-09-02T12:00:00.123Z ERROR service=api host=web-1 trace_id=tr-1 request_id=req-1 failure token=secret"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	reader, _ := New(Config{MaxEvents: 10, MaxLineBytes: 4096}, redact.New())
	result, err := reader.Read([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	event := result.Events[0]
	if event.Level != "ERROR" || event.Service != "api" || event.Host != "web-1" || event.RequestID != "req-1" {
		t.Fatalf("unexpected event: %#v", event)
	}
}
