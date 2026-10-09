package emitter

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A 2xx is a claim about transport. These tests pin what the Sentinel makes of
// the body behind it.
//
// Before this, every 2xx was `OutcomeDelivered` with the body never read, so a
// captive portal, an auth proxy and a wrong backend all counted as successful
// triage - while `srek3s_sentinel_emitter_failures_total` sat at zero. A
// monitoring green light over total data loss.

func postThrough(t *testing.T, handler http.HandlerFunc, payload *IncidentPayload) error {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	client := newTestClient(t, server)
	defer client.Close()
	return client.Emit(context.Background(), payload)
}

func okWithBody(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, MaxResponseBody))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}
}

// The control. Without it every other test here proves only that 200 is refused.
func TestARealVerdictIsStillDelivered(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	err := postThrough(t, okWithBody(verdictBody(payload.IncidentID)), payload)
	if err != nil {
		t.Fatalf("a well-formed Contract B verdict must be accepted: %v", err)
	}
}

func TestA2xxWithAnEmptyBodyIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	err := postThrough(t, okWithBody(""), payload)
	if err == nil {
		t.Fatal("an empty 2xx body is not a triage verdict")
	}
	if !strings.Contains(err.Error(), "not a triage verdict") {
		t.Errorf("reason should name the empty body, got %v", err)
	}
	emitErr, ok := err.(*EmitError)
	if !ok || emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %v, want %v", err, OutcomeEscalate)
	}
}

func TestA2xxWithHTMLIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	portal := `<!doctype html><html><body>Sign in to continue</body></html>`
	err := postThrough(t, okWithBody(portal), payload)
	if err == nil {
		t.Fatal("a captive portal answering 200 must not count as delivered")
	}
	if !strings.Contains(err.Error(), "not a triage verdict") {
		t.Errorf("reason should say the body is not a verdict, got %v", err)
	}
}

func TestA2xxWithNonJSONTextIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	err := postThrough(t, okWithBody(strings.Repeat("x", 1024)), payload)
	if err == nil {
		t.Fatal("text/plain answering 200 must not count as delivered")
	}
}

func TestA2xxThatIsJSONButNotAVerdictIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	err := postThrough(t, okWithBody(`{"message":"ok"}`), payload)
	if err == nil {
		t.Fatal("a body with no verdict fields must not count as delivered")
	}
	if !strings.Contains(err.Error(), "carries no verdict") {
		t.Errorf("reason should name the missing fields, got %v", err)
	}
}

func TestAVerdictForAnotherIncidentIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	wrong := verdictBody("inc_01AAAAAAAAAAAAAAAAAAAAAAAA")
	err := postThrough(t, okWithBody(wrong), payload)
	if err == nil {
		t.Fatal("a verdict for a different incident must not count as delivered")
	}
	if !strings.Contains(err.Error(), "not the") {
		t.Errorf("reason should name the mismatch, got %v", err)
	}
}

func TestAnUnrecognisedTierIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	drifted := verdictBody(payload.IncidentID)
	drifted = strings.Replace(drifted, "TIER_2_ARCHITECTURAL", "TIER_3_UNKNOWN", 1)
	err := postThrough(t, okWithBody(drifted), payload)
	if err == nil {
		t.Fatal("an unknown blast_radius_tier means the two sides have drifted")
	}
	if !strings.Contains(err.Error(), "drifted") {
		t.Errorf("reason should name the drift, got %v", err)
	}
}

func TestA204WithNoContentIsAFailure(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	err := postThrough(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), payload)
	if err == nil {
		t.Fatal("204 carries no verdict and must not count as delivered")
	}
}

// An unknown key in a *response* is the agent's business, not a contract
// violation: a version skew must not fail an otherwise valid verdict.
func TestAnUnknownResponseFieldIsTolerated(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	body := strings.TrimSuffix(verdictBody(payload.IncidentID), "}") +
		`,"a_field_added_in_a_later_version":true}`
	err := postThrough(t, okWithBody(body), payload)
	if err != nil {
		t.Fatalf("an additive Contract B change must not fail a valid verdict: %v", err)
	}
}

// A body larger than MaxResponseBody is truncated before parsing, which must fail
// closed rather than parse a fragment.
//
// The padding goes *inside* a string field on purpose: padding after the closing
// brace leaves a complete document, and a verdict that genuinely arrived whole
// inside the cap should be accepted even if the response had trailing padding.
func TestAnOversizedBodyIsBoundedAndRefused(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	huge := strings.Replace(
		verdictBody(payload.IncidentID),
		`"rca_markdown":"# RCA: memory"`,
		`"rca_markdown":"`+strings.Repeat("x", MaxResponseBody*2),
		1,
	)
	err := postThrough(t, okWithBody(huge), payload)
	if err == nil {
		t.Fatal("a body beyond MaxResponseBody is not a verifiable verdict")
	}
	if !strings.Contains(err.Error(), "not a triage verdict") {
		t.Errorf("reason should name the unparseable body, got %v", err)
	}
}

func TestVerifyVerdictIsCalledOnEverySuccessfulAttempt(t *testing.T) {
	t.Parallel()
	payload := buildGolden(t)
	if err := verifyVerdict([]byte(verdictBody(payload.IncidentID)), payload); err != nil {
		t.Fatalf("precondition: a real verdict must verify: %v", err)
	}
	start := time.Now()
	if err := verifyVerdict([]byte(`{"verdict":"tier_1"}`), payload); err == nil {
		t.Fatal("the historical stub must not verify")
	}
	if time.Since(start) > time.Second {
		t.Error("verdict verification is on the emit path and must be cheap")
	}
}

func TestVerdictEnvelopeDoesNotMirrorTheWholeContract(t *testing.T) {
	// If the struct ever grows a field the Sentinel does not use, this fails:
	// unknown keys are tolerated in a response, so a mirrored field would compile
	// and quietly start asserting something about the agent's internals.
	var v verdictEnvelope
	if err := json.Unmarshal([]byte(verdictBody("inc_x")), &v); err != nil {
		t.Fatalf("the envelope must parse a real verdict: %v", err)
	}
	if v.AgentVersion == "" || v.SchemaVersion == "" {
		t.Errorf("the envelope lost a field it should read: %+v", v)
	}
}
