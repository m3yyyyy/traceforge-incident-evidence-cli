package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsCredentials(t *testing.T) {
	redactor := New()
	input := "authorization=Bearer abc.def token=topsecret url=https://user:pass@example.test/path"
	got, count := redactor.Text(input)
	if count != 3 {
		t.Fatalf("redactions = %d, want 3 (%s)", count, got)
	}
	for _, secret := range []string{"abc.def", "topsecret", ":pass@"} {
		if strings.Contains(got, secret) {
			t.Fatalf("output still contains %q: %s", secret, got)
		}
	}
}

func TestJSONRedactsNestedKeys(t *testing.T) {
	redactor := New()
	got, count, err := redactor.JSON([]byte(`{"message":"login failed","context":{"api_key":"secret-value"},"token":"another"}`))
	if err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("redactions = %d, want 2", count)
	}
	if strings.Contains(string(got), "secret-value") || strings.Contains(string(got), "another") {
		t.Fatalf("sanitized JSON leaked a secret: %s", got)
	}
}

func TestTextRedactsQuotedAuthorizationAndClientSecret(t *testing.T) {
	redactor := New()
	input := `authorization="Bearer quoted-token" client_secret='quoted secret'`
	got, count := redactor.Text(input)
	if count != 2 {
		t.Fatalf("redactions = %d, want 2 (%s)", count, got)
	}
	if strings.Contains(got, "quoted-token") || strings.Contains(got, "quoted secret") {
		t.Fatalf("quoted credential leaked: %s", got)
	}
}

func BenchmarkText(b *testing.B) {
	redactor := New()
	line := "2026-09-02T12:00:00Z ERROR service=api authorization=Bearer abc.def request_id=req-1"
	b.ReportAllocs()
	for range b.N {
		redactor.Text(line)
	}
}
