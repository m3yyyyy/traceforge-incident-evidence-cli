package evidence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
)

func TestWriteBundleAndVerify(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "bundle")
	generated := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	timeline := model.Timeline{
		SchemaVersion: model.SchemaVersion,
		IncidentID:    "INC-42",
		GeneratedAt:   generated,
		EventCount:    1,
		Events:        []model.Event{{Sequence: 1, Timestamp: generated, Level: "ERROR", Message: "sanitized", Source: "app.log", Line: 1}},
	}
	manifest, err := WriteBundle(directory, timeline)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Artifacts) != 2 {
		t.Fatalf("artifacts = %d, want 2", len(manifest.Artifacts))
	}
	result, err := Verify(directory)
	if err != nil {
		t.Fatal(err)
	}
	if result.IncidentID != "INC-42" || result.Artifacts != 2 {
		t.Fatalf("unexpected verification: %#v", result)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "bundle")
	timeline := model.Timeline{SchemaVersion: model.SchemaVersion, IncidentID: "INC-42", GeneratedAt: time.Now().UTC()}
	if _, err := WriteBundle(directory, timeline); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "report.md"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Verify(directory)
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected tamper error, got %v", err)
	}
}

func TestWriteBundleRefusesNonEmptyDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "keep.txt"), []byte("user data"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := WriteBundle(directory, model.Timeline{IncidentID: "INC-42"})
	if err == nil || !strings.Contains(err.Error(), "must be empty") {
		t.Fatalf("expected non-empty error, got %v", err)
	}
}

func TestVerifyRejectsTrailingManifestData(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "bundle")
	timeline := model.Timeline{SchemaVersion: model.SchemaVersion, IncidentID: "INC-42", GeneratedAt: time.Now().UTC()}
	if _, err := WriteBundle(directory, timeline); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	content, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, []byte("{}")...)
	if err := os.WriteFile(manifestPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(directory)
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("expected trailing-data error, got %v", err)
	}
}
