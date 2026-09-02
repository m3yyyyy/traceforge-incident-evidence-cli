package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAnalyzeAndVerify(t *testing.T) {
	directory := t.TempDir()
	input := filepath.Join(directory, "events.jsonl")
	bundle := filepath.Join(directory, "bundle")
	logs := strings.Join([]string{
		`{"timestamp":"2026-09-02T12:00:00Z","level":"info","message":"start","trace_id":"tr-1","token":"secret"}`,
		`{"timestamp":"2026-09-02T12:00:01Z","level":"error","message":"failed","trace_id":"tr-1"}`,
	}, "\n")
	if err := os.WriteFile(input, []byte(logs), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	app := App{Version: "test", Stdout: &stdout, Stderr: &stderr, Now: func() time.Time {
		return time.Date(2026, 9, 2, 13, 0, 0, 0, time.UTC)
	}}
	if code := app.Run([]string{"analyze", "--incident", "INC-42", "--input", input, "--output", bundle}); code != 0 {
		t.Fatalf("analyze exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "redactions: 1") {
		t.Fatalf("unexpected stdout: %s", stdout.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.Run([]string{"verify", "--bundle", bundle}); code != 0 {
		t.Fatalf("verify exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "verified:") {
		t.Fatalf("unexpected verify output: %s", stdout.String())
	}
}

func TestUnknownCommandFails(t *testing.T) {
	var stderr bytes.Buffer
	app := App{Version: "test", Stderr: &stderr}
	if code := app.Run([]string{"destroy"}); code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
}
