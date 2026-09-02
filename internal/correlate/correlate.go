package correlate

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"

	"github.com/m3yyyyy/traceforge-incident-evidence-cli/internal/model"
)

type key struct {
	kind  string
	value string
}

func Build(events []model.Event) ([]model.Event, []model.CorrelationGroup) {
	timeline := append([]model.Event(nil), events...)
	sort.SliceStable(timeline, func(i, j int) bool {
		if !timeline[i].Timestamp.Equal(timeline[j].Timestamp) {
			return timeline[i].Timestamp.Before(timeline[j].Timestamp)
		}
		if timeline[i].Source != timeline[j].Source {
			return timeline[i].Source < timeline[j].Source
		}
		return timeline[i].Line < timeline[j].Line
	})

	groups := make(map[key][]int64)
	for index := range timeline {
		timeline[index].Sequence = int64(index + 1)
		timeline[index].Fingerprint = fingerprint(timeline[index])
		for _, candidate := range []key{
			{kind: "traceId", value: timeline[index].TraceID},
			{kind: "requestId", value: timeline[index].RequestID},
			{kind: "host", value: timeline[index].Host},
		} {
			if candidate.value != "" {
				groups[candidate] = append(groups[candidate], timeline[index].Sequence)
			}
		}
	}

	correlations := make([]model.CorrelationGroup, 0, len(groups))
	for groupKey, sequences := range groups {
		if len(sequences) < 2 {
			continue
		}
		first := timeline[sequences[0]-1].Timestamp
		last := timeline[sequences[len(sequences)-1]-1].Timestamp
		correlations = append(correlations, model.CorrelationGroup{
			Kind: groupKey.kind, Value: groupKey.value, FirstSeen: first, LastSeen: last, Events: sequences,
		})
	}
	sort.Slice(correlations, func(i, j int) bool {
		if correlations[i].Kind != correlations[j].Kind {
			return correlations[i].Kind < correlations[j].Kind
		}
		return correlations[i].Value < correlations[j].Value
	})
	return timeline, correlations
}

func fingerprint(event model.Event) string {
	normalized := strings.Join([]string{
		strings.ToUpper(strings.TrimSpace(event.Level)),
		strings.ToLower(strings.TrimSpace(event.Service)),
		strings.Join(strings.Fields(event.Message), " "),
	}, "\x00")
	digest := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(digest[:8])
}
