package emitter

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/srek3s/sentinel/internal/k8s"
	"github.com/srek3s/sentinel/internal/scrubber"
	"github.com/srek3s/sentinel/internal/worker"
)

var updateGolden = flag.Bool("update", false,
	"rewrite tests/fixtures/emitted_incident.json from the current Build output")

// goldenPath is the artefact the Python suite validates against models.py.
//
// The round trip is deliberately split across two languages rather than done by
// shelling out from Go to a Python interpreter: the Go gate must not depend on a
// virtualenv, and the Python gate must not depend on a Go toolchain. So Go
// produces the bytes, commits them, and Python reads the committed file. A
// divergence in either direction is caught by a different test -
// TestEmittedFixtureIsUpToDate on the Go side, and
// test_emitted_fixture_validates_against_schema on the Python side.
const goldenPath = "../../tests/fixtures/emitted_incident.json"

// fixedDetection is the detection instant used by the golden fixture.
//
// Fixed so `incident_id`, `timestamp` and `detection_latency_ms` are all
// reproducible. `incident_id` is derived from the dedup key and this instant, so a
// wall-clock default would make the golden file un-generatable and the drift
// detector permanently red.
var fixedDetection = time.Date(2026, 9, 28, 14, 32, 7, 481_000_000, time.UTC)

// goldenIncident is the canonical failure: an OOMKilled checkout container with
// declared limits, a previous termination, and log lines that carry real secrets.
//
// It is built through the real scrubber rather than with pre-masked strings, so
// the tests exercise the same path production does. A fixture of already-scrubbed
// text would pass the leak test while proving nothing about the pipeline.
func goldenIncident(t *testing.T) *worker.Incident {
	t.Helper()
	ctx := context.Background()
	raw := []string{
		`ts=2026-09-28T14:32:07.412Z level=error msg="alloc failure" pod=10.42.3.19 conn=10.42.0.7:5432`,
		`ts=2026-09-28T14:32:07.419Z level=warn msg="retrying upstream" request_id=8f14e45f-ceea-467a-9d9e-1f2b3c4d5e6f auth=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk`,
		`ts=2026-09-28T14:32:07.455Z level=error msg="upstream rejected" dial=postgres://checkout:hunter2@10.42.0.7:5432/orders`,
	}
	scrubbed, report := scrubber.ScrubLines(ctx, raw)

	return &worker.Incident{
		Record: &k8s.IncidentRecord{
			DedupKey:       "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b/checkout-api:4",
			Namespace:      "payments",
			PodName:        "checkout-api-7d9f4b6c8d-x2k9p",
			PodUID:         "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
			ContainerName:  "checkout-api",
			Kind:           k8s.FailureOOMKilled,
			ExitCode:       137,
			Reason:         "OOMKilled",
			Restarts:       4,
			FirstSeen:      fixedDetection,
			PreviousReason: "Completed",
			Resources: k8s.ContainerResources{
				CPULimit:      "500m",
				CPURequest:    "250m",
				MemoryLimit:   "256Mi",
				MemoryRequest: "128Mi",
			},
		},
		Namespace:      "payments",
		PodName:        "checkout-api-7d9f4b6c8d-x2k9p",
		PodUID:         "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
		Container:      "checkout-api",
		Kind:           string(k8s.FailureOOMKilled),
		ExitCode:       137,
		Restarts:       4,
		PreviousReason: "Completed",
		Resources: k8s.ContainerResources{
			CPULimit:      "500m",
			CPURequest:    "250m",
			MemoryLimit:   "256Mi",
			MemoryRequest: "128Mi",
		},
		ScrubbedLogs:          scrubbed,
		ScrubbedEventMessages: []string{"Container checkout-api was OOMKilled (exit code 137)."},
		Redaction:             report,
		EventsFetched:         1,
		LogsFetched:           true,
	}
}

// goldenEvents mirrors what cmd/sentinel's eventConverter produces. Kept as a
// literal rather than a Kubernetes lookup so the golden file depends only on this
// package.
//
// It is a *second* implementation of the same shape, which is the point: if it
// agreed with the real one by construction the test would prove nothing, and if it
// were the real one the test would not compile here. A divergence between them is
// caught by the round trip, which is where a divergence between two contract
// implementations belongs.
func goldenEvents(incident *worker.Incident) []ClusterEvent {
	if incident == nil {
		return nil
	}
	messages := incident.ScrubbedEventMessages
	events := make([]ClusterEvent, 0, len(messages))
	for _, message := range messages {
		events = append(events, ClusterEvent{
			Type:           "Warning",
			Reason:         incident.Kind,
			Message:        message,
			Count:          4,
			InvolvedObject: "pod/" + incident.PodName,
		})
	}
	return events
}

func buildGolden(t *testing.T) *IncidentPayload {
	t.Helper()
	payload, err := Build(goldenIncident(t), BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return payload
}

// TestEmittedFixtureIsUpToDate is the drift detector for the cross-language round
// trip.
//
// The committed golden file is what agent/tests reads. If Build's output changes
// and the file is not regenerated, Python would be validating a stale artefact
// that no production request resembles - a green test that has stopped testing
// anything. Regenerate with `go test ./internal/emitter -update`.
func TestEmittedFixtureIsUpToDate(t *testing.T) {
	marshalled, err := json.MarshalIndent(buildGolden(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := append(marshalled, '\n')

	if *updateGolden {
		if err := os.WriteFile(goldenPath, want, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("wrote %s", goldenPath)
		return
	}

	got, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run `go test ./internal/emitter -update` to create it): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("emitted payload has drifted from %s\n"+
			"regenerate with: go test ./internal/emitter -run TestEmittedFixtureIsUpToDate -update",
			goldenPath)
	}
}

// TestNoRawSecretReachesTheRequestBody is ROADMAP 3.4.5.
//
// The claim under test is structural: the bytes on the wire cannot contain a
// credential. It is checked against the ratified corpus rather than a hand-picked
// secret, so the guarantee is tied to the same fixture that defines what a secret
// looks like in this system.
func TestNoRawSecretReachesTheRequestBody(t *testing.T) {
	secrets := corpusSecrets(t)
	if len(secrets) == 0 {
		t.Fatal("corpus yielded no secrets; the leak test would pass vacuously")
	}

	body := marshalledBody(t, goldenIncident(t))

	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(body, secret) {
			t.Errorf("raw secret %q reached the request body", secret)
		}
	}
	// The body is scrubbed, not empty. A test that passed because everything was
	// dropped would satisfy the assertion above while destroying the evidence the
	// agent needs.
	if !strings.Contains(body, "alloc failure") {
		t.Error("the request body lost its diagnostic content; masking over-stripped")
	}
}

// TestLeakDetectorCanActuallyFail is the negative control for
// TestNoRawSecretReachesTheRequestBody.
//
// Without it, the leak test is unfalsifiable: a scanner with a bug that never
// matches reads exactly like a clean pipeline. This asserts the same scan, over
// the same body, with the scrubber deliberately bypassed, does report a leak.
func TestLeakDetectorCanActuallyFail(t *testing.T) {
	incident := goldenIncident(t)
	// Re-introduce the exact lines the scrubber masked, with no masking applied.
	incident.ScrubbedLogs = []string{
		`aws_access_key_id=AKIAIOSFODNN7EXAMPLE`,
		`dial=postgres://checkout:hunter2@10.42.0.7:5432/orders`,
	}
	body := marshalledBody(t, incident)

	found := 0
	for _, secret := range corpusSecrets(t) {
		if strings.Contains(body, secret) {
			found++
		}
	}
	if found == 0 {
		t.Fatal("negative control: an unscrubbed body was reported as clean, " +
			"so the leak test proves nothing")
	}
	t.Logf("negative control caught %d planted secret(s)", found)
}

// TestScrubbedLogsAreTheOnlySource is the structural half of 3.4.2: there is no
// constructor in this package that takes raw telemetry.
//
// A reflection walk over the exported surface, so adding an
// `EmitRaw(ctx, logs []string)` later fails this test instead of quietly
// reintroducing a path the package is supposed to make unrepresentable.
func TestScrubbedLogsAreTheOnlySource(t *testing.T) {
	// A raw-log field on the payload would be the same defect wearing a different
	// name. The check is on the type, not on discipline.
	payloadType := jsonFieldNames(reflect.TypeOf(IncidentPayload{}))
	for _, forbidden := range []string{"logs", "events", "raw_logs", "container_logs"} {
		if _, present := payloadType[forbidden]; present {
			t.Errorf("IncidentPayload has a %q field; telemetry must be named scrubbed_*", forbidden)
		}
	}
	if !payloadType["scrubbed_logs"] {
		t.Error("IncidentPayload lost its scrubbed_logs field")
	}
}

func marshalledBody(t *testing.T, incident *worker.Incident) string {
	t.Helper()
	payload, err := Build(incident, BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		// A contract violation here is itself worth failing on, but the leak test
		// must not be blocked by it - it needs a body to scan.
		t.Fatalf("Build: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(body)
}

// ---------------------------------------------------------------------------
// Payload mapping
// ---------------------------------------------------------------------------

func TestBuildProducesAValidPayload(t *testing.T) {
	payload := buildGolden(t)
	if err := Validate(payload); err != nil {
		t.Fatalf("Build produced an invalid payload: %v", err)
	}
	if payload.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version = %q, want %q", payload.SchemaVersion, SchemaVersion)
	}
	// Full pattern, not a prefix check. The earlier prefix-only version accepted
	// lowercase hex, which the agent's `_INCIDENT_ID_RE` rejects - the round trip
	// caught it and this is the local guard that would have caught it first.
	if !incidentIDPattern.MatchString(payload.IncidentID) {
		t.Errorf("incident_id = %q does not match the agent's ULID pattern", payload.IncidentID)
	}
	if payload.DetectionLatency != 412 {
		t.Errorf("detection_latency_ms = %d, want 412", payload.DetectionLatency)
	}
	if payload.ExitCode == nil || *payload.ExitCode != 137 {
		t.Errorf("exit_code = %v, want 137 (I-A2)", payload.ExitCode)
	}
	if payload.ResourceLimits.MemoryLimit == nil {
		t.Error("memory_limit is null on an OOMKilled payload; I-A2 requires it")
	}
}

// TestNullableFieldsAreExplicitNull pins the ARCH §4.1 rule that a missing value
// travels as null, never as an absent key.
//
// The agent's models are `extra: "forbid"` with per-field defaults; "omitted" and
// "null" are different inputs, and a `omitempty` added later would silently
// change which one the agent sees.
func TestNullableFieldsAreExplicitNull(t *testing.T) {
	incident := goldenIncident(t)
	incident.Kind = string(k8s.FailureCrashLoopBackOff)
	incident.Record.Kind = k8s.FailureCrashLoopBackOff
	incident.Record.ExitCode = 0
	incident.Record.PreviousReason = ""
	incident.Resources = k8s.ContainerResources{}
	incident.Record.Resources = k8s.ContainerResources{}
	incident.PreviousReason = ""
	incident.Restarts = 3
	incident.Record.Restarts = 3
	// Cleared so the array assertions below cover the empty case, which is what
	// the log-fetch-failure path actually produces.
	incident.ScrubbedLogs = nil
	incident.ScrubbedEventMessages = nil

	payload, err := Build(incident, BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(10 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Top-level nullable fields.
	for _, key := range []string{"exit_code", "previous_reason"} {
		assertExplicitNull(t, fields, key)
	}

	// The resource quantities are nested, and are the case ARCH §4.1 calls out by
	// name: a guard-chain miss in Go must surface as null, not as an absent key.
	limits, present := fields["resource_limits"]
	if !present {
		t.Fatal("resource_limits is absent from the payload")
	}
	var limitsFields map[string]json.RawMessage
	if err := json.Unmarshal(limits, &limitsFields); err != nil {
		t.Fatalf("decode resource_limits: %v", err)
	}
	for _, key := range []string{
		"cpu_limit", "cpu_request", "memory_limit", "memory_request",
		"memory_working_set_bytes",
	} {
		assertExplicitNull(t, limitsFields, key)
	}

	// Arrays must be `[]` for the same reason: `scrubbed_logs: list[str]` has no
	// default, so null is a schema violation. Cleared here so the assertion is
	// about the empty case, which is the one the log-fetch failure path produces.
	if got := string(fields["scrubbed_logs"]); got != "[]" {
		t.Errorf("scrubbed_logs = %s, want []", got)
	}
	if got := string(fields["cluster_events"]); got != "[]" {
		t.Errorf("cluster_events = %s, want []", got)
	}
}

func assertExplicitNull(t *testing.T, fields map[string]json.RawMessage, key string) {
	t.Helper()
	raw, present := fields[key]
	if !present {
		t.Errorf("%s is absent; ARCH §4.1 requires an explicit null", key)
		return
	}
	if string(raw) != "null" {
		t.Errorf("%s = %s, want null", key, raw)
	}
}

// TestUnmappableReasonFailsClosed covers ARCH's core rule at the boundary.
//
// A non-OOM termination is a real observation the watcher makes and the agent has
// no enum member for. Emitting the nearest member would assert an OOM kill - and
// an OOM assertion is what unlocks a memory-limit diff.
func TestUnmappableReasonFailsClosed(t *testing.T) {
	incident := goldenIncident(t)
	incident.Kind = "Terminated"
	incident.Record.Kind = "Terminated"
	incident.Record.ExitCode = 1

	_, err := Build(incident, BuildOptions{SentinelVersion: "0.1.0"})
	if !isError(err, ErrUnmappableReason) {
		t.Fatalf("err = %v, want ErrUnmappableReason", err)
	}
}

// TestOOMKilledWithoutMemoryLimitFailsClosed is the I-A2 guard at the producer.
//
// The two fields come from independent sources - the terminated state and the pod
// spec - and nothing downstream would notice if they disagreed. This asserts the
// disagreement is caught here rather than becoming a confident wrong RCA.
func TestOOMKilledWithoutMemoryLimitFailsClosed(t *testing.T) {
	incident := goldenIncident(t)
	incident.Resources.MemoryLimit = ""
	incident.Record.Resources.MemoryLimit = ""

	_, err := Build(incident, BuildOptions{SentinelVersion: "0.1.0"})
	if !isError(err, ErrContractViolation) {
		t.Fatalf("err = %v, want a contract violation naming memory_limit", err)
	}
	if !strings.Contains(err.Error(), "memory_limit") {
		t.Errorf("error does not name the field: %v", err)
	}
}

func TestCrashLoopBackOffOmitsExitCode(t *testing.T) {
	incident := goldenIncident(t)
	incident.Kind = string(k8s.FailureCrashLoopBackOff)
	incident.Record.Kind = k8s.FailureCrashLoopBackOff
	incident.Record.ExitCode = 0
	incident.Restarts = 3
	incident.Record.Restarts = 3

	payload, err := Build(incident, BuildOptions{SentinelVersion: "0.1.0",
		Now: func() time.Time { return fixedDetection }})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if payload.ExitCode != nil {
		t.Errorf("exit_code = %d; a CrashLoopBackOff container was not observed "+
			"exiting, so reporting the record's placeholder 0 would claim a clean exit",
			*payload.ExitCode)
	}
}

func TestDetectionLatencyIsClampedAtTheContractCap(t *testing.T) {
	incident := goldenIncident(t)
	// Detected 9.3 seconds after first seen: a genuinely slow apiserver.
	incident.Record.FirstSeen = fixedDetection.Add(-9300 * time.Millisecond)

	payload, err := Build(incident, BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if payload.DetectionLatency != MaxDetectionLatencyMS {
		t.Errorf("detection_latency_ms = %d, want the cap %d", payload.DetectionLatency, MaxDetectionLatencyMS)
	}
	if !Clamped(payload) {
		t.Error("Clamped() = false for a payload that hit the ceiling; the over-budget " +
			"detection would be invisible to the caller")
	}
}

// TestDetectionLatencyTracksTheMonotonicInterval pins ROADMAP 3.5.3.
//
// What this can and cannot prove, stated plainly: Go does not expose the monotonic
// reading on a time.Time, so a test cannot construct two values whose monotonic
// and wall-clock differences disagree. The choice of `Sub` over `UnixNano`
// arithmetic is therefore a property of the implementation, verified here only to
// the extent that the emitted value is exactly the interval between the two
// instants the caller supplied. A stronger test would need a clock injection seam
// that can fake a clock jump, which is a larger change than the property warrants -
// so the guarantee rests on the code reading `Sub`, and this test catches a
// regression that swaps it for a wall-clock computation with different units.
func TestDetectionLatencyTracksTheMonotonicInterval(t *testing.T) {
	// A real time.Now() value, so the monotonic reading is actually present -
	// unlike fixedDetection, which time.Date builds without one.
	firstSeen := time.Now().Add(-640 * time.Millisecond)
	detectedAt := time.Now()

	incident := goldenIncident(t)
	incident.Record.FirstSeen = firstSeen

	payload, err := Build(incident, BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return detectedAt },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Some slack for the microseconds the test itself consumed.
	if payload.DetectionLatency < 640 || payload.DetectionLatency > 700 {
		t.Errorf("detection_latency_ms = %d, want the 640ms interval", payload.DetectionLatency)
	}
}

// TestDetectionLatencyNeverGoesNegative is the guard for the case the clamp is
// most likely to be asked about: a clock that moved backwards between detection
// and dispatch, which an NTP step does routinely.
func TestDetectionLatencyNeverGoesNegative(t *testing.T) {
	incident := goldenIncident(t)
	incident.Record.FirstSeen = fixedDetection.Add(time.Hour)

	payload, err := Build(incident, BuildOptions{
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if payload.DetectionLatency < 0 {
		t.Errorf("detection_latency_ms = %d; a negative value fails the agent's ge=0",
			payload.DetectionLatency)
	}
	if payload.DetectionLatency != 0 {
		t.Errorf("detection_latency_ms = %d, want 0 for a backwards clock", payload.DetectionLatency)
	}
}

func TestIncidentIDIsDeterministicAcrossRetries(t *testing.T) {
	// A retry must present the same identity, or a 429 turns one failure into two
	// incidents and the agent triages it twice.
	first := buildGolden(t)
	second := buildGolden(t)
	if first.IncidentID != second.IncidentID {
		t.Errorf("incident_id is not deterministic: %q then %q", first.IncidentID, second.IncidentID)
	}

	// And it must change when the incident changes. The identity is the dedup key,
	// so the mutation has to be to that. Bumping `Restarts` alone is not a different
	// incident - it is the same one described inconsistently, and an ID that tracked
	// the field rather than the key would let one failure own two identities.
	other := goldenIncident(t)
	other.Record.DedupKey = "7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b/checkout-api:5"
	other.Record.Restarts = 5
	other.Restarts = 5
	third, err := Build(other, BuildOptions{SentinelVersion: "0.1.0",
		Now:    func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events: goldenEvents})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if third.IncidentID == first.IncidentID {
		t.Error("a different incident produced the same incident_id")
	}
}

func TestQuantityPatternMatchesThePythonSchema(t *testing.T) {
	// The Go-side Quantity pattern is transcribed from agent/models.py. If the
	// Python one moves, this fails here rather than in production as a 422.
	source, err := os.ReadFile(filepath.Join("..", "..", "agent", "models.py"))
	if err != nil {
		t.Skipf("agent/models.py not readable from here: %v", err)
	}
	text := string(source)
	const marker = "QUANTITY_RE"
	index := strings.Index(text, marker)
	if index < 0 {
		t.Skip("models.py no longer names its quantity pattern; update this test")
	}
	window := text[index:]
	if !strings.Contains(window, QuantityPatternSource[:20]) {
		t.Errorf("the Quantity pattern in models.go no longer matches models.py\n"+
			"go:  %s\npy:  %s", QuantityPatternSource, excerpt(window, 400))
	}

	// Negative control: the pattern must actually reject a value the agent rejects.
	for _, invalid := range []string{"256MB", "1.5GiB", "lots", "", "256 Mi"} {
		if quantityPattern.MatchString(invalid) {
			t.Errorf("quantity pattern accepted %q, which the agent would reject", invalid)
		}
	}
}

func excerpt(text string, n int) string {
	if len(text) > n {
		return text[:n] + "..."
	}
	return text
}

// ---------------------------------------------------------------------------
// Transport and status classification
// ---------------------------------------------------------------------------

// recorder captures what the server actually received.
type recorder struct {
	bodies []string
}

func (r *recorder) handler(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		buf := make([]byte, 0, 4096)
		chunk := make([]byte, 1024)
		for {
			n, err := req.Body.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				break
			}
		}
		r.bodies = append(r.bodies, string(buf))
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

// verdictBody is a Contract B document for the given incident, which is what the
// agent actually answers a 2xx with.
//
// The stubs these tests used to return - `{"verdict":"tier_1"}` - are not a shape
// the agent can produce, and nothing noticed, because until now a 2xx was
// accepted without the body ever being read. Every success case here therefore has
// to look like the real thing, or the check would be testing a fiction.
func verdictBody(incidentID string) string {
	return `{"schema_version":"1.0.0","incident_id":"` + incidentID + `",` +
		`"status":"TRIAGED","classification":"RESOURCE_EXHAUSTION","severity":"HIGH",` +
		`"confidence":0.92,"blast_radius_tier":"TIER_2_ARCHITECTURAL",` +
		`"root_cause":{"summary":"container exceeded its memory limit","evidence":[],"affected_scope":"container"},` +
		`"remediation":{"summary":"No automatic change proposed.","risk_level":"HIGH",` +
		`"target_manifest":"","git_patch":"","patch_validated":false},` +
		`"verification_policy":{"slo_targets":[],"rollback_plan":"none"},` +
		`"rca_markdown":"# RCA: memory","analysis_latency_ms":41,"agent_version":"0.1.0"}`
}

// sentIncidentID reads the incident_id out of a Contract A request body, which is
// what the real agent echoes into its verdict.
func sentIncidentID(body string) string {
	var sent struct {
		IncidentID string `json:"incident_id"`
	}
	if err := json.Unmarshal([]byte(body), &sent); err != nil {
		return ""
	}
	return sent.IncidentID
}

// verdictHandler records the request and answers 200 with a Contract B verdict
// echoing the incident id it was sent - which is what the agent does, and the
// only reason the id can match, since Build mints a fresh one per incident.
func (r *recorder) verdictHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		buf := make([]byte, 0, 4096)
		chunk := make([]byte, 1024)
		for {
			n, err := req.Body.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				break
			}
		}
		r.bodies = append(r.bodies, string(buf))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(verdictBody(sentIncidentID(string(buf)))))
	}
}

// readAll drains a bounded request body.
func readAll(req *http.Request) string {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1024)
	for {
		n, err := req.Body.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if err != nil {
			break
		}
	}
	return string(buf)
}

func newTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	client, err := New(Config{
		BaseURL:         server.URL,
		Timeout:         2 * time.Second,
		MaxAttempts:     3,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return client
}

// TestEmitterTimeoutExceedsAgentWorstCase pins the cross-language HTTP contract.
//
// The Sentinel's deadline must exceed the agent's worst-case service time, or
// every Tier-2 request is abandoned client-side before the agent has finished its
// two sequential LLM calls. This was 5s against a 120s agent and the failure was
// silent: incidents were delivered, verdicts discarded, everything escalated.
func TestEmitterTimeoutExceedsAgentWorstCase(t *testing.T) {
	t.Parallel()
	if DefaultTimeout <= AgentMaxServiceTime {
		t.Fatalf("DefaultTimeout = %v, must exceed AgentMaxServiceTime (%v); "+
			"the agent makes two sequential %v LLM calls on the Tier-2 path",
			DefaultTimeout, AgentMaxServiceTime, AgentMaxServiceTime/2)
	}
}

// TestInjectedClientWithNoTimeoutStillDelivers is a regression test for a latent
// defect: the per-attempt deadline was read back off c.http.Timeout instead of the
// resolved Config.Timeout. An injected client with Timeout == 0 (which
// httptest's client is) made context.WithTimeout(ctx, 0) return an already-
// cancelled context, so every attempt failed instantly and no incident could ever
// be delivered through a caller-supplied client.
func TestInjectedClientWithNoTimeoutStillDelivers(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(verdictBody(sentIncidentID(readAll(req)))))
	}))
	defer server.Close()

	// Deliberately Timeout: 0 on the injected client - the shape that used to
	// produce an already-cancelled context on every attempt.
	client, err := New(Config{
		BaseURL:         server.URL,
		HTTPClient:      server.Client(),
		MaxAttempts:     1,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := client.http.Timeout; got != 0 {
		t.Fatalf("precondition: injected client Timeout = %v, want 0", got)
	}

	err = client.Emit(context.Background(), buildGolden(t))
	if err != nil {
		t.Fatalf("Emit through an injected zero-timeout client: %v", err)
	}
}

func TestEmitPostsToTheCanonicalPath(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.verdictHandler())
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()

	if err := client.Dispatch(context.Background(), goldenIncident(t)); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if len(rec.bodies) != 1 {
		t.Fatalf("got %d requests, want 1", len(rec.bodies))
	}
	if !strings.Contains(rec.bodies[0], "\"schema_version\":\"1.0.0\"") {
		t.Errorf("request body is not the Contract A payload: %s", rec.bodies[0])
	}
}

func TestUnprocessableEntityIsFatalAndNotRetried(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler(http.StatusUnprocessableEntity, `{"detail":"bad"}`))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()

	err := client.Dispatch(context.Background(), goldenIncident(t))
	if err == nil {
		t.Fatal("expected an error for 422")
	}
	emitErr := asEmitError(t, err)
	if emitErr.Outcome != OutcomeRejected {
		t.Errorf("outcome = %s, want %s", emitErr.Outcome, OutcomeRejected)
	}
	if emitErr.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("status = %d, want 422", emitErr.StatusCode)
	}
	if len(rec.bodies) != 1 {
		t.Errorf("made %d attempts for a 422; the contract failure is deterministic "+
			"and retrying it is how a validation bug becomes a denial of service", len(rec.bodies))
	}
}

func TestTooManyRequestsIsRetriedThenEscalates(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler(http.StatusTooManyRequests, `{"error":"sandbox_busy"}`))
	defer server.Close()

	client, err := New(Config{
		BaseURL:         server.URL,
		Timeout:         2 * time.Second,
		MaxAttempts:     3,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	emitErr := asEmitError(t, client.Dispatch(context.Background(), goldenIncident(t)))
	if emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %s, want %s after exhausting retries", emitErr.Outcome, OutcomeEscalate)
	}
	if emitErr.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", emitErr.Attempts)
	}
	if len(rec.bodies) != 3 {
		t.Errorf("made %d requests, want 3", len(rec.bodies))
	}
}

func TestTooManyRequestsRecoversWhenTheAgentAccepts(t *testing.T) {
	// 429 then 200: the load-shedding case the retry exists for.
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"sandbox_busy"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(verdictBody(sentIncidentID(readAll(req)))))
	}))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()

	if err := client.Dispatch(context.Background(), goldenIncident(t)); err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if attempts != 2 {
		t.Errorf("made %d attempts, want 2", attempts)
	}
}

func TestServerErrorEscalatesWithoutRetrying(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler(http.StatusInternalServerError, `{"detail":"boom"}`))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()

	emitErr := asEmitError(t, client.Dispatch(context.Background(), goldenIncident(t)))
	if emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %s, want %s", emitErr.Outcome, OutcomeEscalate)
	}
	if len(rec.bodies) != 1 {
		t.Errorf("made %d attempts for a 500; a Sentinel-side retry loop would pin a "+
			"pool worker on an unbounded outage", len(rec.bodies))
	}
}

// TestEmitIsBoundedByTheAttemptDeadline proves the per-attempt timeout holds.
//
// The server here never answers, which is the point: the client must give up on
// its own schedule rather than inheriting the server's.
//
// Note the handler waits on a test-owned channel rather than on
// `req.Context().Done()`. A server-side request context is cancelled when the
// *server* observes the connection closing, which for a request whose body was
// already consumed can take arbitrarily long - so a handler blocked that way can
// outlive the client and hang `httptest.Server.Close`, which is a test-harness
// hang that reads exactly like a product hang. The bounded channel keeps the
// failure mode inside the assertion.
func TestEmitIsBoundedByTheAttemptDeadline(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		select {
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer server.Close()

	client, err := New(Config{
		BaseURL:         server.URL,
		Timeout:         300 * time.Millisecond,
		MaxAttempts:     2,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer client.Close()

	start := time.Now()
	emitErr := asEmitError(t, client.Emit(context.Background(), buildGolden(t)))
	elapsed := time.Since(start)

	if emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %s, want %s for an unreachable agent", emitErr.Outcome, OutcomeEscalate)
	}
	// Two attempts at 300ms, plus jittered backoff. A generous ceiling that still
	// fails if the deadline were not applied at all - without it, the first attempt
	// would sit for the server's full 10 seconds.
	if elapsed > 5*time.Second {
		t.Errorf("Emit took %s; the 300ms per-attempt deadline did not bound the calls", elapsed)
	}
}

// errRoundTripper is a Transport that always fails, simulating an unreachable
// agent (connection refused, reset) rather than an HTTP error status.
type errRoundTripper struct{ err error }

func (r errRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, r.err
}

// TestATransportFailureBacksOffBetweenAttempts pins the R (reliability) fix: a
// transport failure used to retry with no pause, so a down agent was hit
// MaxAttempts times back-to-back. It is retried with the same capped full-jitter
// backoff the 429 path uses - but "did it pause" cannot be read off a clock,
// because full jitter delays uniformly in [0, ceiling) and can be ~0. So the
// backoff is counted through the injected sleep instead: a pause must be invoked
// once per gap between attempts, deterministically.
//
// Before the fix the transport path never called c.wait, so backoffs was 0 and
// this test failed; after, three attempts space two pauses.
func TestATransportFailureBacksOffBetweenAttempts(t *testing.T) {
	t.Parallel()

	backoffs := 0
	c, err := New(Config{
		BaseURL:         "http://agent.invalid",
		HTTPClient:      &http.Client{Transport: errRoundTripper{err: errors.New("connection refused")}},
		MaxAttempts:     3,
		Timeout:         time.Second,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()
	// Return immediately - no real delay - so the test is fast and deterministic,
	// but record every invocation: that is what distinguishes the fixed path.
	c.sleep = func(ctx context.Context, _ time.Duration) bool {
		backoffs++
		return ctx.Err() == nil
	}

	emitErr := asEmitError(t, c.Dispatch(context.Background(), goldenIncident(t)))

	if emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %s, want %s after exhausting retries", emitErr.Outcome, OutcomeEscalate)
	}
	if emitErr.Attempts != 3 {
		t.Errorf("attempts = %d, want 3", emitErr.Attempts)
	}
	if backoffs != 2 {
		t.Errorf("backed off %d times, want 2: a transport failure must space its "+
			"retries, not fire them back-to-back against an unreachable agent", backoffs)
	}
}

// TestATransportFailureAbortsWhenTheWorkerIsCancelled: the backoff must be
// context-aware, so a worker torn down mid-retry is not held for the full
// backoff. This is what keeps the retry loop from outliving the pool worker that
// started it (AGENTS.md §3.2).
func TestATransportFailureAbortsWhenTheWorkerIsCancelled(t *testing.T) {
	t.Parallel()

	c, err := New(Config{
		BaseURL:         "http://agent.invalid",
		HTTPClient:      &http.Client{Transport: errRoundTripper{err: errors.New("connection refused")}},
		MaxAttempts:     3,
		Timeout:         time.Second,
		SentinelVersion: "0.1.0",
		Now:             func() time.Time { return fixedDetection.Add(412 * time.Millisecond) },
		Events:          goldenEvents,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel while the first backoff is pending. The injected sleep reports the
	// cancellation, exactly as timerSleep does on ctx.Done.
	c.sleep = func(ctx context.Context, _ time.Duration) bool {
		cancel()
		return false
	}

	emitErr := asEmitError(t, c.Emit(ctx, buildGolden(t)))

	if emitErr.Outcome != OutcomeEscalate {
		t.Errorf("outcome = %s, want %s", emitErr.Outcome, OutcomeEscalate)
	}
	if emitErr.Attempts != 1 {
		t.Errorf("attempts = %d, want 1: the worker was cancelled during the first "+
			"backoff, so no second POST may fire", emitErr.Attempts)
	}
}

func TestEmitRefusesAPayloadThatViolatesTheContract(t *testing.T) {
	rec := &recorder{}
	server := httptest.NewServer(rec.handler(http.StatusOK, `{}`))
	defer server.Close()

	client := newTestClient(t, server)
	defer client.Close()

	broken := buildGolden(t)
	broken.Namespace = "Not_A_DNS_Label"

	err := client.Emit(context.Background(), broken)
	if !isError(err, ErrContractViolation) {
		t.Fatalf("err = %v, want a contract violation", err)
	}
	if len(rec.bodies) != 0 {
		t.Errorf("a payload that cannot satisfy the schema was sent anyway (%d requests)", len(rec.bodies))
	}
}

func TestNewRejectsAnUnusableBaseURL(t *testing.T) {
	for _, base := range []string{"", "   ", "srek3s-agent:8000", "ftp://agent"} {
		if _, err := New(Config{BaseURL: base}); err == nil {
			t.Errorf("New(%q) succeeded; a misconfigured endpoint must fail at "+
				"startup, not on the first incident", base)
		}
	}
}

func TestRetryAfterIsHonouredFromTheErrorEnvelope(t *testing.T) {
	// The agent's 429 body carries the hint, not a header, so a header-only parse
	// would silently fall back to jitter.
	if got := retryAfter(`{"error":"sandbox_busy","retry_after_ms":1500}`); got != 1500*time.Millisecond {
		t.Errorf("retryAfter = %s, want 1.5s", got)
	}
	for _, body := range []string{
		`{"error":"sandbox_busy"}`,
		`{"retry_after_ms":0}`,
		`{"retry_after_ms":"soon"}`,
		`{"retry_after_ms":-4}`,
		`not json at all`,
	} {
		if got := retryAfter(body); got != 0 {
			t.Errorf("retryAfter(%q) = %s, want 0 (fall back to jitter)", body, got)
		}
	}
}

func TestRetryDelayIsJitteredNotDeterministic(t *testing.T) {
	seen := map[time.Duration]bool{}
	for range 50 {
		seen[retryDelay(3, 0)] = true
	}
	if len(seen) < 2 {
		t.Errorf("retryDelay produced %d distinct value(s) over 50 draws; three workers "+
			"shed at the same moment would re-collide", len(seen))
	}
	for delay := range seen {
		ceiling := baseRetryDelay << 2
		if delay > ceiling {
			t.Errorf("delay %s exceeds the ceiling %s for attempt 3", delay, ceiling)
		}
	}
	// An explicit Retry-After wins over the jitter entirely.
	if got := retryDelay(1, 3*time.Second); got != 3*time.Second {
		t.Errorf("retryDelay with Retry-After = %s, want 3s", got)
	}
}
