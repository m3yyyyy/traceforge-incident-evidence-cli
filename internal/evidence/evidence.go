package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
)

const maxManifestBytes = 10 * 1024 * 1024

type Verification struct {
	IncidentID string
	Artifacts  int
}

func WriteBundle(directory string, timeline model.Timeline) (model.Manifest, error) {
	if strings.TrimSpace(directory) == "" {
		return model.Manifest{}, errors.New("output directory is required")
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return model.Manifest{}, fmt.Errorf("resolve output directory: %w", err)
	}
	if info, statErr := os.Stat(absolute); statErr == nil {
		if !info.IsDir() {
			return model.Manifest{}, fmt.Errorf("output path is not a directory: %s", absolute)
		}
		entries, readErr := os.ReadDir(absolute)
		if readErr != nil {
			return model.Manifest{}, fmt.Errorf("inspect output directory: %w", readErr)
		}
		if len(entries) != 0 {
			return model.Manifest{}, fmt.Errorf("output directory must be empty: %s", absolute)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return model.Manifest{}, fmt.Errorf("inspect output directory: %w", statErr)
	}
	if err := os.MkdirAll(absolute, 0o700); err != nil {
		return model.Manifest{}, fmt.Errorf("create output directory: %w", err)
	}

	jsonBytes, err := json.MarshalIndent(timeline, "", "  ")
	if err != nil {
		return model.Manifest{}, fmt.Errorf("encode timeline: %w", err)
	}
	jsonBytes = append(jsonBytes, '\n')
	if err := atomicWrite(filepath.Join(absolute, "timeline.json"), jsonBytes); err != nil {
		return model.Manifest{}, err
	}

	reportPath := filepath.Join(absolute, "report.md")
	if err := writeReport(reportPath, timeline); err != nil {
		return model.Manifest{}, err
	}

	manifest := model.Manifest{
		SchemaVersion: model.SchemaVersion,
		IncidentID:    timeline.IncidentID,
		GeneratedAt:   timeline.GeneratedAt,
		Algorithm:     "SHA-256",
	}
	for _, name := range []string{"report.md", "timeline.json"} {
		digest, err := digestFile(filepath.Join(absolute, name), name)
		if err != nil {
			return model.Manifest{}, err
		}
		manifest.Artifacts = append(manifest.Artifacts, digest)
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return model.Manifest{}, fmt.Errorf("encode manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if err := atomicWrite(filepath.Join(absolute, "manifest.json"), manifestBytes); err != nil {
		return model.Manifest{}, err
	}
	return manifest, nil
}

func Verify(directory string) (Verification, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return Verification{}, fmt.Errorf("resolve bundle directory: %w", err)
	}
	manifestPath := filepath.Join(absolute, "manifest.json")
	file, err := os.Open(manifestPath)
	if err != nil {
		return Verification{}, fmt.Errorf("open manifest: %w", err)
	}
	defer file.Close()

	limited := io.LimitReader(file, maxManifestBytes+1)
	manifestBytes, err := io.ReadAll(limited)
	if err != nil {
		return Verification{}, fmt.Errorf("read manifest: %w", err)
	}
	if len(manifestBytes) > maxManifestBytes {
		return Verification{}, errors.New("manifest exceeds safety limit")
	}
	var manifest model.Manifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestBytes)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Verification{}, fmt.Errorf("decode manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Verification{}, errors.New("manifest contains trailing JSON data")
		}
		return Verification{}, fmt.Errorf("decode trailing manifest data: %w", err)
	}
	if manifest.SchemaVersion != model.SchemaVersion {
		return Verification{}, fmt.Errorf("unsupported schema version %q", manifest.SchemaVersion)
	}
	if manifest.Algorithm != "SHA-256" {
		return Verification{}, fmt.Errorf("unsupported digest algorithm %q", manifest.Algorithm)
	}
	if manifest.IncidentID == "" || len(manifest.Artifacts) == 0 {
		return Verification{}, errors.New("manifest is incomplete")
	}

	seen := make(map[string]struct{}, len(manifest.Artifacts))
	for _, expected := range manifest.Artifacts {
		clean := filepath.Clean(expected.Path)
		if filepath.IsAbs(expected.Path) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return Verification{}, fmt.Errorf("unsafe artifact path %q", expected.Path)
		}
		if _, exists := seen[clean]; exists {
			return Verification{}, fmt.Errorf("duplicate artifact path %q", expected.Path)
		}
		seen[clean] = struct{}{}
		actual, err := digestFile(filepath.Join(absolute, clean), filepath.ToSlash(clean))
		if err != nil {
			return Verification{}, err
		}
		if actual.Bytes != expected.Bytes || !strings.EqualFold(actual.SHA256, expected.SHA256) {
			return Verification{}, fmt.Errorf("artifact verification failed: %s", expected.Path)
		}
	}
	return Verification{IncidentID: manifest.IncidentID, Artifacts: len(manifest.Artifacts)}, nil
}

func writeReport(path string, timeline model.Timeline) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	writer := bufio.NewWriter(file)
	write := func(format string, values ...any) error {
		_, writeErr := fmt.Fprintf(writer, format, values...)
		return writeErr
	}

	if err = write("# TraceForge incident report: %s\n\n", markdown(timeline.IncidentID)); err == nil {
		err = write("Generated: `%s`  \nSchema: `%s`  \nEvents: **%d**\n\n", timeline.GeneratedAt.Format(time.RFC3339Nano), timeline.SchemaVersion, timeline.EventCount)
	}
	if err == nil {
		err = write("## Evidence sources\n\n| Source | Bytes | Lines | Events | Redactions | SHA-256 |\n|---|---:|---:|---:|---:|---|\n")
	}
	for _, source := range timeline.Sources {
		if err == nil {
			err = write("| `%s` | %d | %d | %d | %d | `%s` |\n", markdown(source.Path), source.Bytes, source.Lines, source.Events, source.Redactions, source.SHA256)
		}
	}
	if err == nil {
		err = write("\n## Correlations\n\n| Type | Value | First seen | Last seen | Events |\n|---|---|---|---|---:|\n")
	}
	if len(timeline.Correlations) == 0 && err == nil {
		err = write("| _None_ | | | | 0 |\n")
	}
	for _, group := range timeline.Correlations {
		if err == nil {
			err = write("| %s | `%s` | %s | %s | %d |\n", markdown(group.Kind), markdown(group.Value), group.FirstSeen.Format(time.RFC3339Nano), group.LastSeen.Format(time.RFC3339Nano), len(group.Events))
		}
	}
	if err == nil {
		err = write("\n## Timeline\n\n| # | Timestamp | Level | Service | Host | Trace / Request | Message |\n|---:|---|---|---|---|---|---|\n")
	}
	for _, event := range timeline.Events {
		if err == nil {
			ids := strings.Trim(strings.Join([]string{event.TraceID, event.RequestID}, " / "), " / ")
			err = write("| %d | %s | %s | %s | %s | `%s` | %s |\n", event.Sequence, event.Timestamp.Format(time.RFC3339Nano), markdown(event.Level), markdown(event.Service), markdown(event.Host), markdown(ids), markdown(event.Message))
		}
	}
	if err == nil {
		err = write("\n---\nGenerated offline by TraceForge. Verify this bundle with `traceforge verify --bundle <directory>`.\n")
	}
	if flushErr := writer.Flush(); err == nil {
		err = flushErr
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("write report: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish report: %w", err)
	}
	return nil
}

func atomicWrite(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("publish %s: %w", filepath.Base(path), err)
	}
	return nil
}

func digestFile(path, manifestPath string) (model.ArtifactDigest, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.ArtifactDigest{}, fmt.Errorf("open artifact %s: %w", manifestPath, err)
	}
	defer file.Close()
	hasher := sha256.New()
	bytesWritten, err := io.Copy(hasher, file)
	if err != nil {
		return model.ArtifactDigest{}, fmt.Errorf("hash artifact %s: %w", manifestPath, err)
	}
	return model.ArtifactDigest{Path: filepath.ToSlash(manifestPath), SHA256: hex.EncodeToString(hasher.Sum(nil)), Bytes: bytesWritten}, nil
}

func markdown(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "\r", " ", "\n", " ", "`", "\\`")
	return replacer.Replace(value)
}

func SortedArtifactNames(manifest model.Manifest) []string {
	names := make([]string, 0, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		names = append(names, artifact.Path)
	}
	sort.Strings(names)
	return names
}
