package ingest

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/redact"
)

const (
	DefaultMaxEvents    = 250_000
	DefaultMaxLineBytes = 2 * 1024 * 1024
)

var (
	textPattern  = regexp.MustCompile(`^(\S+)\s+(?:\[?([A-Za-z]+)\]?\s+)?(.*)$`)
	fieldPattern = regexp.MustCompile(`\b(trace[_-]?id|request[_-]?id|correlation[_-]?id|service|host(?:name)?)=([^\s]+)`)
)

type Config struct {
	MaxEvents    int
	MaxLineBytes int
}

type Result struct {
	Events  []model.Event
	Sources []model.SourceSummary
}

type Reader struct {
	config   Config
	redactor *redact.Redactor
}

func New(config Config, redactor *redact.Redactor) (*Reader, error) {
	if config.MaxEvents <= 0 {
		return nil, errors.New("max events must be greater than zero")
	}
	if config.MaxLineBytes < 1024 {
		return nil, errors.New("max line bytes must be at least 1024")
	}
	if redactor == nil {
		return nil, errors.New("redactor is required")
	}
	return &Reader{config: config, redactor: redactor}, nil
}

func (r *Reader) Read(inputs []string) (Result, error) {
	paths, err := expandInputs(inputs)
	if err != nil {
		return Result{}, err
	}
	if len(paths) == 0 {
		return Result{}, errors.New("no supported log files found")
	}

	result := Result{Events: make([]model.Event, 0, min(r.config.MaxEvents, 4096))}
	for _, path := range paths {
		summary, events, err := r.readFile(path)
		if err != nil {
			return Result{}, err
		}
		if len(result.Events)+len(events) > r.config.MaxEvents {
			return Result{}, fmt.Errorf("event limit exceeded: maximum is %d", r.config.MaxEvents)
		}
		result.Events = append(result.Events, events...)
		result.Sources = append(result.Sources, summary)
	}
	return result, nil
}

func expandInputs(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, errors.New("at least one --input path is required")
	}
	seen := make(map[string]struct{})
	var paths []string
	for _, input := range inputs {
		absolute, err := filepath.Abs(input)
		if err != nil {
			return nil, fmt.Errorf("resolve input %q: %w", input, err)
		}
		info, err := os.Stat(absolute)
		if err != nil {
			return nil, fmt.Errorf("inspect input %q: %w", input, err)
		}
		if !info.IsDir() {
			if _, exists := seen[absolute]; !exists {
				seen[absolute] = struct{}{}
				paths = append(paths, absolute)
			}
			continue
		}

		err = filepath.WalkDir(absolute, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			extension := strings.ToLower(filepath.Ext(path))
			if extension != ".json" && extension != ".jsonl" && extension != ".ndjson" && extension != ".log" && extension != ".txt" {
				return nil
			}
			if _, exists := seen[path]; !exists {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk input %q: %w", input, err)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func (r *Reader) readFile(path string) (model.SourceSummary, []model.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return model.SourceSummary{}, nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return model.SourceSummary{}, nil, fmt.Errorf("inspect %s: %w", path, err)
	}
	summary := model.SourceSummary{Path: displayPath(path), Bytes: info.Size()}
	events := make([]model.Event, 0, 1024)
	hasher := sha256.New()
	scanner := bufio.NewScanner(io.TeeReader(file, hasher))
	scanner.Buffer(make([]byte, 64*1024), r.config.MaxLineBytes)
	for scanner.Scan() {
		summary.Lines++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		event, redactions, err := r.parseLine(line, summary.Path, summary.Lines)
		if err != nil {
			return model.SourceSummary{}, nil, fmt.Errorf("%s:%d: %w", path, summary.Lines, err)
		}
		summary.Redactions += redactions
		summary.Events++
		events = append(events, event)
		if len(events) > r.config.MaxEvents {
			return model.SourceSummary{}, nil, fmt.Errorf("event limit exceeded: maximum is %d", r.config.MaxEvents)
		}
	}
	if err := scanner.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return model.SourceSummary{}, nil, fmt.Errorf("line exceeds the %d-byte safety limit", r.config.MaxLineBytes)
		}
		return model.SourceSummary{}, nil, fmt.Errorf("read: %w", err)
	}
	summary.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	return summary, events, nil
}

func displayPath(path string) string {
	workingDirectory, err := os.Getwd()
	if err == nil {
		relative, relativeErr := filepath.Rel(workingDirectory, path)
		if relativeErr == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return filepath.ToSlash(relative)
		}
	}
	return filepath.Base(path)
}

func (r *Reader) parseLine(line []byte, source string, lineNumber int) (model.Event, int, error) {
	if line[0] == '{' {
		sanitized, count, err := r.redactor.JSON(line)
		if err != nil {
			return model.Event{}, 0, fmt.Errorf("invalid JSON record: %w", err)
		}
		event, err := parseJSONEvent(sanitized)
		if err != nil {
			return model.Event{}, 0, err
		}
		event.Source, event.Line = source, lineNumber
		return event, count, nil
	}

	sanitized, count := r.redactor.Text(string(line))
	event, err := parseTextEvent(sanitized)
	if err != nil {
		return model.Event{}, 0, err
	}
	event.Source, event.Line = source, lineNumber
	return event, count, nil
}

func parseJSONEvent(line []byte) (model.Event, error) {
	var fields map[string]any
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		return model.Event{}, fmt.Errorf("decode JSON event: %w", err)
	}
	timestamp, err := timestampField(fields)
	if err != nil {
		return model.Event{}, err
	}
	message := stringField(fields, "message", "msg", "event", "description")
	if message == "" {
		message = "structured event"
	}
	return model.Event{
		Timestamp: timestamp,
		Level:     strings.ToUpper(stringField(fields, "level", "severity", "log.level")),
		Message:   message,
		Service:   stringField(fields, "service", "service.name", "app", "application"),
		Host:      stringField(fields, "host", "hostname", "host.name"),
		TraceID:   stringField(fields, "traceId", "trace_id", "trace.id"),
		RequestID: stringField(fields, "requestId", "request_id", "request.id", "correlationId", "correlation_id"),
	}, nil
}

func parseTextEvent(line string) (model.Event, error) {
	parts := textPattern.FindStringSubmatch(line)
	if parts == nil {
		return model.Event{}, errors.New("text record must begin with an RFC3339 timestamp")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, parts[1])
	if err != nil {
		return model.Event{}, errors.New("text record must begin with an RFC3339 timestamp")
	}
	event := model.Event{Timestamp: timestamp.UTC(), Level: strings.ToUpper(parts[2]), Message: strings.TrimSpace(parts[3])}
	for _, match := range fieldPattern.FindAllStringSubmatch(parts[3], -1) {
		key := strings.ToLower(strings.ReplaceAll(match[1], "-", "_"))
		value := strings.Trim(match[2], `"'`)
		switch key {
		case "traceid", "trace_id":
			event.TraceID = value
		case "requestid", "request_id", "correlationid", "correlation_id":
			event.RequestID = value
		case "service":
			event.Service = value
		case "host", "hostname":
			event.Host = value
		}
	}
	return event, nil
}

func timestampField(fields map[string]any) (time.Time, error) {
	value := valueAt(fields, "timestamp", "@timestamp", "time", "ts")
	switch typed := value.(type) {
	case string:
		parsed, err := time.Parse(time.RFC3339Nano, typed)
		if err != nil {
			return time.Time{}, fmt.Errorf("timestamp must use RFC3339: %w", err)
		}
		return parsed.UTC(), nil
	case json.Number:
		number, err := strconv.ParseFloat(string(typed), 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("invalid numeric timestamp: %w", err)
		}
		seconds, fraction := mathModf(number)
		return time.Unix(seconds, int64(fraction*1e9)).UTC(), nil
	default:
		return time.Time{}, errors.New("event is missing a valid timestamp")
	}
}

func mathModf(value float64) (int64, float64) {
	seconds := int64(value)
	return seconds, value - float64(seconds)
}

func stringField(fields map[string]any, keys ...string) string {
	for _, key := range keys {
		value := valueAt(fields, key)
		switch typed := value.(type) {
		case string:
			return typed
		case json.Number:
			return string(typed)
		case float64:
			return strconv.FormatFloat(typed, 'f', -1, 64)
		}
	}
	return ""
}

func valueAt(fields map[string]any, keys ...string) any {
	for _, key := range keys {
		if direct, found := fields[key]; found {
			return direct
		}
		segments := strings.Split(key, ".")
		var current any = fields
		found := true
		for _, segment := range segments {
			object, ok := current.(map[string]any)
			if !ok {
				found = false
				break
			}
			current, ok = object[segment]
			if !ok {
				found = false
				break
			}
		}
		if found {
			return current
		}
	}
	return nil
}

func CopyLimited(destination io.Writer, source io.Reader, limit int64) error {
	written, err := io.CopyN(destination, source, limit+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if written > limit {
		return fmt.Errorf("input exceeds the %d-byte limit", limit)
	}
	return nil
}
