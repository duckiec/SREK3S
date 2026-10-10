package emitter

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// The pass that found this: a malformed 200 whose body carried a planted
// credential produced 12 verbatim occurrences of it in sentinel.log. Two paths
// carried it - EmitError.Detail, interpolated by Error(), and verifyVerdict's own
// message, which quoted the field values.
//
// These tests pin both halves. A test on verifyVerdict alone would pass while the
// caller still attached the body, which is how the first version shipped.

const planted = "AKIAIOSFODNN7EXAMPLE-sk-live-PLANTED9f3a2b1c"

func verdictWithField(name, value string) string {
	return `{"schema_version":"1.0.0","incident_id":"inc_x","status":"TRIAGED",` +
		`"classification":"RESOURCE_EXHAUSTION","severity":"HIGH","confidence":0.9,` +
		`"blast_radius_tier":"TIER_2_ARCHITECTURAL",` +
		`"root_cause":{"summary":"s","evidence":[],"affected_scope":"container"},` +
		`"remediation":{"summary":"s","risk_level":"HIGH","target_manifest":"","git_patch":"","patch_validated":false},` +
		`"verification_policy":{"slo_targets":[],"rollback_plan":"none"},` +
		`"rca_markdown":"# RCA: ` + value + `","analysis_latency_ms":1,"agent_version":"0.1.0",` +
		`"` + name + `":"` + value + `"}`
}

// sequenced answers with bodies in order, repeating the last one once exhausted.
type sequenced struct {
	mu     sync.Mutex
	codes  []int
	bodies []string
	calls  int
}

func (s *sequenced) handler(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	i := s.calls
	s.calls++
	if i >= len(s.bodies) {
		i = len(s.bodies) - 1
	}
	code, body := s.codes[i], s.bodies[i]
	s.mu.Unlock()
	w.WriteHeader(code)
	_, _ = w.Write([]byte(body))
}

// The end-to-end property: a malformed 2xx carrying a secret produces an error,
// and the secret is in neither the error string nor Detail.
func TestAPlantedSecretNeverReachesTheEmitError(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)

	cases := []struct {
		name string
		body string
	}{
		{"secret in rca_markdown", verdictWithField("rca_markdown", planted)},
		{"secret as a stray key", `{"message":"` + planted + `"}`},
		{"secret in incident_id", `{"incident_id":"` + planted + `","status":"TRIAGED","blast_radius_tier":"TIER_2_ARCHITECTURED"}`},
		{"secret as the tier", `{"incident_id":"inc_x","status":"TRIAGED","blast_radius_tier":"` + planted + `"}`},
		{"html portal carrying a secret", "<html>" + planted + "</html>"},
		{"plain text", planted},
		{"oversized", verdictWithField("rca_markdown", planted) + strings.Repeat(" ", MaxResponseBody*2)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := postThrough(t, okWithBody(tc.body), payload)
			if err == nil {
				t.Fatal("a malformed 2xx must fail")
			}
			if strings.Contains(err.Error(), planted) {
				t.Errorf("the planted secret reached the error, which is logged verbatim:\n%v", err)
			}
			emitErr, ok := err.(*EmitError)
			if !ok {
				t.Fatalf("want *EmitError, got %T", err)
			}
			if emitErr.Detail != "" {
				t.Errorf("Detail must be empty on the 2xx path, got %d bytes: %q",
					len(emitErr.Detail), emitErr.Detail)
			}
			// The diagnosis must survive the redaction, or the log line is useless.
			msg := err.Error()
			for _, want := range []string{"triage verdict", "missing", "drifted", "not the one that was sent"} {
				if strings.Contains(msg, want) {
					return
				}
			}
			t.Errorf("the error lost its diagnosis: %v", err)
		})
	}
}

// Detail is still populated where the body is the input to a decision: Retry-After
// lives in a 429 body and the retry loop reads it. Without this test the fix above
// could be "never set Detail anywhere" and every other test would still pass.
func TestRetryAfterStillComesFromTheBody(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	seq := &sequenced{
		codes:  []int{429, 200},
		bodies: []string{`{"error":"sandbox_busy","retry_after_ms":1}`, verdictBody(payload.IncidentID)},
	}
	server := httptest.NewServer(http.HandlerFunc(seq.handler))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()
	if err := client.Emit(t.Context(), payload); err != nil {
		t.Fatalf("the 429 must still recover: %v", err)
	}
	if seq.calls != 2 {
		t.Errorf("attempts = %d, want 2", seq.calls)
	}
}

func TestDetailIsCarriedOnTheSheddingPath(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	seq := &sequenced{
		codes:  []int{429, 429, 429},
		bodies: []string{`{"error":"sandbox_busy","retry_after_ms":1}`},
	}
	server := httptest.NewServer(http.HandlerFunc(seq.handler))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()
	err := client.Emit(t.Context(), payload)
	if err == nil {
		t.Fatal("want an error")
	}
	emitErr, ok := err.(*EmitError)
	if !ok {
		t.Fatalf("want *EmitError, got %T", err)
	}
	if emitErr.Detail == "" || !strings.Contains(emitErr.Detail, "sandbox_busy") {
		t.Errorf("the 429 branch needs the body for Retry-After; Detail = %q", emitErr.Detail)
	}
}

// A well-formed verdict for the right incident still passes, so the fix did not
// cost the happy path anything.
func TestAValidVerdictStillDelivers(t *testing.T) {
	t.Parallel()
	if err := postThrough(t, okWithBody(verdictBody(buildGolden(t).IncidentID)), buildGolden(t)); err != nil {
		t.Fatalf("a real verdict must be accepted: %v", err)
	}
}
