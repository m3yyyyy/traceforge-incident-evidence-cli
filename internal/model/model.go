package model

import "time"

const SchemaVersion = "traceforge/v1"

// Event is a sanitized log record. Secret-bearing source data must never be
// stored in this type.
type Event struct {
	Sequence    int64     `json:"sequence"`
	Timestamp   time.Time `json:"timestamp"`
	Level       string    `json:"level,omitempty"`
	Message     string    `json:"message"`
	Service     string    `json:"service,omitempty"`
	Host        string    `json:"host,omitempty"`
	TraceID     string    `json:"traceId,omitempty"`
	RequestID   string    `json:"requestId,omitempty"`
	Source      string    `json:"source"`
	Line        int       `json:"line"`
	Fingerprint string    `json:"fingerprint"`
}

type SourceSummary struct {
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Lines      int    `json:"lines"`
	Events     int    `json:"events"`
	Redactions int    `json:"redactions"`
}

type CorrelationGroup struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
	Events    []int64   `json:"events"`
}

type Timeline struct {
	SchemaVersion string             `json:"schemaVersion"`
	IncidentID    string             `json:"incidentId"`
	GeneratedAt   time.Time          `json:"generatedAt"`
	Sources       []SourceSummary    `json:"sources"`
	EventCount    int                `json:"eventCount"`
	Correlations  []CorrelationGroup `json:"correlations"`
	Events        []Event            `json:"events"`
}

type ArtifactDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type Manifest struct {
	SchemaVersion string           `json:"schemaVersion"`
	IncidentID    string           `json:"incidentId"`
	GeneratedAt   time.Time        `json:"generatedAt"`
	Algorithm     string           `json:"algorithm"`
	Artifacts     []ArtifactDigest `json:"artifacts"`
}
