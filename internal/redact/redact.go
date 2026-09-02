package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

const Replacement = "[REDACTED]"

var sensitiveKeys = map[string]struct{}{
	"accesskey": {}, "accesskeyid": {}, "accesstoken": {}, "apikey": {}, "authorization": {},
	"clientsecret": {}, "connectionstring": {}, "cookie": {}, "credential": {}, "databaseurl": {},
	"dsn": {}, "password": {}, "passwd": {}, "privatekey": {}, "refreshtoken": {}, "secret": {},
	"session": {}, "sessionid": {}, "token": {},
}

type rule struct {
	expression  *regexp.Regexp
	replacement string
}

// Redactor removes common credentials from structured and unstructured logs.
// It intentionally preserves operational identifiers such as hosts, IPs,
// request IDs and trace IDs because they are required for incident correlation.
type Redactor struct {
	rules []rule
}

func New() *Redactor {
	return &Redactor{rules: []rule{
		{regexp.MustCompile(`(?i)\b(authorization)\s*([:=])\s*(?:"[^"]*"|'[^']*'|(?:(?:Bearer|Basic)\s+)?[^\s,;]+)`), `${1}${2}` + Replacement},
		{regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+`), "Bearer " + Replacement},
		{regexp.MustCompile(`(?i)\b(password|passwd|pwd|token|access[_-]?token|refresh[_-]?token|api[_-]?key|access[_-]?key(?:[_-]?id)?|client[_-]?secret|private[_-]?key|connection[_-]?string|database[_-]?url|dsn|secret|cookie|session(?:id)?)\s*([:=])\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)`), `${1}${2}` + Replacement},
		{regexp.MustCompile(`(?i)(https?://[^\s:/]+:)[^\s@/]+@`), `${1}` + Replacement + `@`},
	}}
}

func (r *Redactor) Text(input string) (string, int) {
	output := input
	count := 0
	for _, current := range r.rules {
		matches := current.expression.FindAllStringIndex(output, -1)
		count += len(matches)
		output = current.expression.ReplaceAllString(output, current.replacement)
	}
	return output, count
}

// JSON sanitizes values whose field names imply credentials and then applies
// text rules to every string value. The returned bytes are safe to persist.
func (r *Redactor) JSON(input []byte) ([]byte, int, error) {
	var value any
	if err := json.Unmarshal(input, &value); err != nil {
		return nil, 0, err
	}

	count := r.walk(&value)
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, 0, err
	}
	return encoded, count, nil
}

func (r *Redactor) walk(value *any) int {
	count := 0
	switch typed := (*value).(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitive(key) {
				if child != nil && child != Replacement {
					typed[key] = Replacement
					count++
				}
				continue
			}
			count += r.walk(&child)
			typed[key] = child
		}
	case []any:
		for index, child := range typed {
			count += r.walk(&child)
			typed[index] = child
		}
	case string:
		sanitized, replacements := r.Text(typed)
		*value = sanitized
		count += replacements
	}
	return count
}

func isSensitive(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(strings.ToLower(key))
	_, found := sensitiveKeys[normalized]
	return found
}
