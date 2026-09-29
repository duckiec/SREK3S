package emitter

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/srek3s/sentinel/internal/k8s"
)

// TestIncidentPayloadContract is the Milestone 3 terminal validation test's item 3
// and item 5, in one place:
//
//   - every mandatory ARCH §4 field is present;
//   - the payload is schema-valid (against the bounds transcribed in validate.go);
//   - its scrubbed strings contain zero fixture-corpus plaintexts;
//   - detection_latency_ms <= 2000 on the synthetic OOM corpus.
//
// It is a single test on purpose. The terminal command runs it by name, and four
// separate tests would each need to be added to that name list - a list that rots
// exactly the way a checklist does.

// mandatoryFields are the keys agent/models.py declares as required, plus the
// nullable ones ARCH §4.1 requires to be *present*.
//
// Presence, not just validity: a Pydantic field with a default would validate
// whether it is present or absent, so "the model accepted it" is not the same
// claim as "the producer sent it". Both are asserted.
var mandatoryFields = []string{
	"schema_version", "incident_id", "timestamp", "namespace", "pod_name",
	"container_name", "exit_code", "reason", "resource_limits", "restart_count",
	"previous_reason", "scrubbed_logs", "cluster_events", "redaction_report",
	"detection_latency_ms", "sentinel_version",
}

func TestIncidentPayloadContract(t *testing.T) {
	payload := buildGolden(t)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// --- 3a. every mandatory field is present -------------------------------
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, name := range mandatoryFields {
		if _, present := fields[name]; !present {
			t.Errorf("%q is absent; ARCH §4.1 requires it explicitly, null or not", name)
		}
	}

	// --- 3b. schema-valid ---------------------------------------------------
	if err := Validate(payload); err != nil {
		t.Errorf("payload is not schema-valid: %v", err)
	}

	// --- 3c. zero corpus plaintexts in the scrubbed strings ------------------
	secrets := corpusSecrets(t)
	if len(secrets) == 0 {
		t.Fatal("the corpus yielded no secrets; the leak assertion would pass vacuously")
	}
	for _, secret := range secrets {
		if strings.Contains(string(body), secret) {
			t.Errorf("corpus secret %q appears in the emitted payload", secret)
		}
	}

	// --- 5. detection latency within the PRD AC-1 budget ---------------------
	if payload.DetectionLatency < 0 || payload.DetectionLatency > MaxDetectionLatencyMS {
		t.Errorf("detection_latency_ms = %d, want 0..%d (PRD AC-1)",
			payload.DetectionLatency, MaxDetectionLatencyMS)
	}
	if Clamped(payload) {
		t.Error("the synthetic corpus clamped its latency; the measurement " +
			"exceeded the budget before the contract cap was applied")
	}
}

// TestIncidentPayloadContractOnTheWholeCorpus runs the same contract over every
// case in the ratified corpus rather than one hand-written incident.
//
// The single-case version can pass by having chosen well. The corpus is the
// ratified reference for what a secret looks like, so running the leak assertion
// over all of it is the difference between "this payload is clean" and "this
// pipeline does not leak".
func TestIncidentPayloadContractOnTheWholeCorpus(t *testing.T) {
	cases := corpusCases(t)
	if len(cases) == 0 {
		t.Fatal("the corpus yielded no cases; the assertions would pass vacuously")
	}

	for _, c := range cases {
		t.Run(c.id, func(t *testing.T) {
			// The corpus line goes in as raw telemetry and is scrubbed by the real
			// scrubber, so this exercises the pipeline rather than a fixture of
			// already-masked strings.
			incident := goldenIncident(t)
			incident.Record.Kind = k8s.FailureOOMKilled
			incident.Record.ExitCode = 137
			incident.Kind = string(k8s.FailureOOMKilled)
			incident.ExitCode = 137
			incident.ScrubbedLogs, incident.Redaction = scrubLines(strings.Split(c.text, "\n"))

			payload, err := Build(incident, BuildOptions{
				SentinelVersion: "0.1.0",
				Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
				Events:          goldenEvents,
			})
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			body, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if c.expectMasked && c.secret != "" && strings.Contains(string(body), c.secret) {
				t.Errorf("secret %q reached the payload for case %q", c.secret, c.id)
			}
			if payload.DetectionLatency > MaxDetectionLatencyMS {
				t.Errorf("detection_latency_ms = %d", payload.DetectionLatency)
			}
		})
	}
}

// TestOmittedIncidentIsARejectedIncident is the negative control for the whole
// contract.
//
// ARCH's fail-closed rule: an incident whose shape cannot be proven must not be
// emitted as though nothing were wrong. This is the assertion that the emit path
// can refuse, which is what every other assertion here depends on to mean
// something.
func TestOmittedIncidentIsARejectedIncident(t *testing.T) {
	// A non-OOM termination: a real observation, with no enum member to carry it.
	incident := goldenIncident(t)
	incident.Kind = "Terminated"
	incident.Record.Kind = "Terminated"
	incident.Record.ExitCode = 1

	if _, err := Build(incident, BuildOptions{SentinelVersion: "0.1.0"}); err == nil {
		t.Fatal("an unmappable reason was emitted; the fail-closed rule is not " +
			"load-bearing if a guessed reason goes out as valid")
	}

	// And through the transport, so the refusal is at the boundary rather than in
	// a helper the HTTP path might not call.
	server := httptestServer(t, 200, `{}`)
	client := newTestClient(t, server)
	defer client.Close()
	if err := client.Dispatch(contextTODO(), incident); err == nil {
		t.Error("Dispatch emitted an unmappable incident")
	}
}

// TestTheGoldenFixtureIsTheContract keeps the terminal test and the cross-language
// test reading the same bytes.
//
// The Python suite validates tests/fixtures/emitted_incident.json; this suite
// regenerates it and fails on drift. If they read different artefacts, the
// round trip would be validating a payload no production request resembles.
func TestTheGoldenFixtureIsTheContract(t *testing.T) {
	// goldenPath is already relative to the package directory; filepath.Join on a
	// second copy of ".." would climb past the repository root. (An earlier version
	// of this line did exactly that, and the failure was a 4-level path.)
	data, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	var fromFixture IncidentPayload
	if err := json.Unmarshal(data, &fromFixture); err != nil {
		t.Fatalf("the golden fixture does not decode into IncidentPayload: %v", err)
	}
	if err := Validate(&fromFixture); err != nil {
		t.Errorf("the golden fixture is not schema-valid: %v", err)
	}
	if fromFixture.IncidentID != buildGolden(t).IncidentID {
		t.Errorf("golden incident_id = %q, want %q; the fixture is stale",
			fromFixture.IncidentID, buildGolden(t).IncidentID)
	}
}
