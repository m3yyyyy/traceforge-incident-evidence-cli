package correlate

import (
	"testing"
	"time"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
)

func TestBuildSortsAndCorrelates(t *testing.T) {
	later := time.Date(2026, 9, 2, 12, 0, 1, 0, time.UTC)
	earlier := later.Add(-time.Second)
	events := []model.Event{
		{Timestamp: later, Message: "done", TraceID: "tr-1", Source: "b.log", Line: 1},
		{Timestamp: earlier, Message: "start", TraceID: "tr-1", Source: "a.log", Line: 1},
	}
	timeline, groups := Build(events)
	if timeline[0].Message != "start" || timeline[0].Sequence != 1 {
		t.Fatalf("timeline not sorted: %#v", timeline)
	}
	if len(groups) != 1 || groups[0].Kind != "traceId" || len(groups[0].Events) != 2 {
		t.Fatalf("unexpected groups: %#v", groups)
	}
	if timeline[0].Fingerprint == "" {
		t.Fatal("fingerprint was not assigned")
	}
}
