// Package emitter serialises a scrubbed incident and ships it to the analysis
// agent over HTTP.
//
// It is the last hop before telemetry leaves the cluster, and therefore the last
// place a mistake becomes a disclosure. Two properties are load-bearing and are
// enforced structurally rather than by convention:
//
//  1. Nothing in this package can construct a payload from unsanitised data. The
//     only public entry point takes a *worker.Incident, whose telemetry fields are
//     documented as scrubbed-before-arrival, and there is no constructor that
//     takes raw strings from a caller. ROADMAP 3.4.2 asks for "no code path that
//     serialises raw telemetry"; the way to make that checkable is to make the raw
//     path unrepresentable.
//
//  2. The wire shape is declared here and nowhere else. agent/models.py is the
//     consumer and sets `extra: "forbid"`, so a typo in a JSON tag is a 422 that
//     silently drops an incident. TestRoundTripAgainstThePythonSchema pins the two
//     together against the canonical fixture.
package emitter

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/srek3s/sentinel/internal/scrubber"
	"github.com/srek3s/sentinel/internal/worker"
)

// SchemaVersion is the wire contract version this build speaks.
//
// Sent on every request rather than negotiated. ARCH §4.1 requires the field, and
// an agent that is behind the Sentinel must be able to tell which contract it is
// being handed - silently defaulting is how a version skew turns into a
// misclassified incident rather than a visible error.
const SchemaVersion = "1.0.0"

// MaxDetectionLatencyMS is the PRD AC-1 budget for detection latency.
//
// It is a *cap on the emitted value*, not a promise about the system. See
// clampLatency for why exceeding it must not fail the emit.
const MaxDetectionLatencyMS = 2000

// incidentIDPrefix is fixed by ARCH §4.1 and by the agent's `_INCIDENT_ID_RE`.
const incidentIDPrefix = "inc_"

// Reason values, mirroring the `Reason` enum in agent/models.py.
//
// A closed set on purpose. The Go watcher classifies a third outcome
// (`Terminated`, a non-OOM non-zero exit) that the agent's enum does not accept,
// and widening the enum here would widen the blast radius: the whole point of the
// narrow enum is that anything outside it escalates rather than triages. The
// mapping is therefore explicit and total, with [ErrUnmappableReason] for
// everything else.
const (
	ReasonOOMKilled         = "OOMKilled"
	ReasonCrashLoopBackOff  = "CrashLoopBackOff"
	ReasonUnmappableFailure = "Terminated"
)

// QuantityPatternSource is the agent's own `Quantity` validation pattern,
// transcribed so the Sentinel can reject an unserialisable limit before spending
// a round trip on a 422.
//
// Transcribed rather than shared because Go and Python have no common source of
// truth for it, and a divergence would be invisible until production. The round
// trip test re-reads the pattern out of agent/models.py, so a change on the Python
// side fails the Go suite rather than waiting for a live incident.
const QuantityPatternSource = `^[0-9]+(\.[0-9]+)?(m|k|Ki|M|Mi|G|Gi|T|Ti|P|Pi)?$`

// IncidentPayload is the flat request body for POST /v1/incidents (ARCH §4.1).
//
// The field names and nesting are exactly agent/models.py's `IncidentPayload`.
// There are no wrappers - no `cluster_info`, no `workload` - because ARCH §4.1
// defines a flat payload and inventing a wrapper would be a unilateral contract
// change made by the producer.
//
// `omitempty` appears nowhere, deliberately. Every nullable field is emitted as an
// explicit `null` rather than omitted: the agent's models are `extra: "forbid"`
// with per-field defaults, and "omitted" and "null" mean different things to a
// reader debugging an incident. ARCH §4.1 spells this out for ResourceLimits -
// a Go guard-chain miss must surface as null, not as an invented value and not as
// an absent key.
type IncidentPayload struct {
	SchemaVersion    string          `json:"schema_version"`
	IncidentID       string          `json:"incident_id"`
	Timestamp        string          `json:"timestamp"`
	Namespace        string          `json:"namespace"`
	PodName          string          `json:"pod_name"`
	ContainerName    string          `json:"container_name"`
	ExitCode         *int32          `json:"exit_code"`
	Reason           string          `json:"reason"`
	ResourceLimits   ResourceLimits  `json:"resource_limits"`
	RestartCount     int32           `json:"restart_count"`
	PreviousReason   *string         `json:"previous_reason"`
	ScrubbedLogs     []string        `json:"scrubbed_logs"`
	ClusterEvents    []ClusterEvent  `json:"cluster_events"`
	RedactionReport  RedactionReport `json:"redaction_report"`
	DetectionLatency int64           `json:"detection_latency_ms"`
	SentinelVersion  string          `json:"sentinel_version"`
}

// ResourceLimits mirrors agent/models.py's `ResourceLimits`.
//
// Pointers, so that "not declared" and "declared as empty" stay distinguishable
// all the way to the JSON. A `string` with `omitempty` would collapse both to an
// absent key; a `string` without it would emit `""`, which the agent's
// `min_length: 1` rejects. The pointer is the only representation that maps
// cleanly onto `str | None = None`.
type ResourceLimits struct {
	CPULimit              *string `json:"cpu_limit"`
	CPURequest            *string `json:"cpu_request"`
	MemoryLimit           *string `json:"memory_limit"`
	MemoryRequest         *string `json:"memory_request"`
	MemoryWorkingSetBytes *int64  `json:"memory_working_set_bytes"`
}

// ClusterEvent mirrors agent/models.py's `ClusterEvent`.
type ClusterEvent struct {
	Type           string  `json:"type"`
	Reason         string  `json:"reason"`
	Message        string  `json:"message"`
	Count          int32   `json:"count"`
	FirstTimestamp *string `json:"first_timestamp"`
	LastTimestamp  *string `json:"last_timestamp"`
	InvolvedObject string  `json:"involved_object"`
}

// RedactionReport mirrors agent/models.py's `RedactionReport`.
//
// Counts and rule IDs only. There is no field here that could hold a masked value,
// which is the structural form of ARCH §6 M4: the reporting channel is incapable
// of leaking because it has no slot to leak into.
type RedactionReport struct {
	TotalRedactions int64    `json:"total_redactions"`
	RulesTriggered  []string `json:"rules_triggered"`
}

// BuildOptions carries the per-build facts that are not on the incident itself.
type BuildOptions struct {
	// SentinelVersion is this binary's version, sent as `sentinel_version`.
	SentinelVersion string

	// Now supplies the detection instant. Defaults to time.Now.
	Now func() time.Time

	// Events converts one scrubbed incident's event messages into wire events.
	//
	// Takes the incident rather than a bare `[]string` because a `ClusterEvent`
	// cannot be built from a message alone: the agent's model requires a
	// non-empty `involved_object`, and that is the pod identity the incident
	// already carries. Handing over the messages alone would force the converter to
	// invent an object reference - attaching a failure to a pod that may never have
	// existed.
	//
	// Takes the *scrubbed* incident rather than `[]corev1.Event` because the worker
	// deliberately does not retain the event objects, only their scrubbed messages.
	// Passing the raw objects through would mean threading unscrubbed Kubernetes
	// text into the serialiser, which is precisely the path ROADMAP 3.4.2 forbids.
	Events func(incident *worker.Incident) []ClusterEvent
}

// Errors returned by Build. Distinct values so the caller can act on the cause
// rather than on a message string.
var (
	// ErrNoIncident means Build was handed a nil incident. A programming error,
	// not a runtime condition.
	ErrNoIncident = errors.New("emitter: nil incident")

	// ErrUnmappableReason means the incident's failure kind has no representation
	// in the agent's `Reason` enum. Per ARCH's fail-closed rule the incident is
	// not emitted: a guessed reason would hand the classifier a confident wrong
	// answer about whether a container was OOM-killed.
	ErrUnmappableReason = errors.New("emitter: failure kind has no wire representation")

	// ErrContractViolation means the payload cannot satisfy the agent's schema -
	// an out-of-range field, a malformed name, a quantity the agent will reject.
	// Caught here so the failure names the field, instead of surfacing as an
	// opaque 422 from the far side of the network.
	ErrContractViolation = errors.New("emitter: payload violates the wire contract")
)

// Build assembles the wire payload from a scrubbed incident.
//
// It is total for every incident the Sentinel can observe, or it returns an error
// explaining which field could not be represented. There is no "best effort" path
// that fills a gap with a plausible value, because a plausible invented value in
// a remediation pipeline is worse than a dropped incident: it produces a diff
// against limits the container never had.
func Build(incident *worker.Incident, opts BuildOptions) (*IncidentPayload, error) {
	if incident == nil {
		return nil, ErrNoIncident
	}
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	detectedAt := now()

	reason, err := mapReason(incident.Kind)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", err, incident.Kind)
	}

	// The record is dereferenced for FirstSeen but may be nil on a hand-assembled
	// incident, so it is resolved once and checked rather than chased.
	var firstSeen time.Time
	if incident.Record != nil {
		firstSeen = incident.Record.FirstSeen
	}
	timestamp := detectedAt
	if !firstSeen.IsZero() {
		timestamp = firstSeen
	}

	id, err := incidentID(incident, detectedAt)
	if err != nil {
		return nil, err
	}

	payload := &IncidentPayload{
		SchemaVersion: SchemaVersion,
		IncidentID:    id,
		Timestamp:     formatTimestamp(timestamp),
		Namespace:     incident.Namespace,
		PodName:       incident.PodName,
		ContainerName: incident.Container,
		Reason:        reason,
		ResourceLimits: ResourceLimits{
			CPULimit:      nullable(incident.Resources.CPULimit),
			CPURequest:    nullable(incident.Resources.CPURequest),
			MemoryLimit:   nullable(incident.Resources.MemoryLimit),
			MemoryRequest: nullable(incident.Resources.MemoryRequest),
			// Always null. Working set is a metrics-server number and the Sentinel
			// has no metrics client; emitting 0 would be a measurement, and
			// emitting a stale one would be worse. ARCH §4.1 makes it nullable for
			// exactly this case.
			MemoryWorkingSetBytes: nil,
		},
		RestartCount:    incident.Restarts,
		ScrubbedLogs:    nonNilStrings(incident.ScrubbedLogs),
		ClusterEvents:   nonNilEvents(opts.Events, incident),
		RedactionReport: redactionReport(incident.Redaction),
		SentinelVersion: opts.SentinelVersion,
	}

	// exit_code is nullable but meaningful for exactly one reason. For
	// CrashLoopBackOff the record carries a placeholder 0, because the container
	// did not exit in the observed state - it is waiting to be restarted. Sending
	// that 0 would be a claim that the container exited cleanly, which is the
	// opposite of the truth, so it is omitted and the field goes null.
	if exitCode, ok := exitCodeFor(incident); ok {
		payload.ExitCode = &exitCode
	}

	if previous := strings.TrimSpace(incident.PreviousReason); previous != "" {
		truncated := previous
		if len(truncated) > maxPreviousReasonLen {
			truncated = truncated[:maxPreviousReasonLen]
		}
		payload.PreviousReason = &truncated
	}

	payload.DetectionLatency = clampLatency(incident, detectedAt)

	if err := Validate(payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// maxPreviousReasonLen is the agent's `max_length` on `previous_reason`.
//
// Truncated rather than dropped, because the head of a kubelet reason carries the
// cause ("Error", "OOMKilled") and the tail is usually the container's own
// message. Dropping the whole field to satisfy a length limit would discard the
// most diagnostic word in the payload.
const maxPreviousReasonLen = 256

// mapReason maps a Sentinel failure kind onto the agent's closed `Reason` enum.
func mapReason(kind string) (string, error) {
	switch kind {
	case ReasonOOMKilled:
		return ReasonOOMKilled, nil
	case ReasonCrashLoopBackOff:
		return ReasonCrashLoopBackOff, nil
	default:
		// Fail closed. `Terminated` - a non-OOM non-zero exit - is a real
		// observation the watcher makes, and the agent has no enum member for it.
		// Emitting the nearest member would assert an OOM kill that did not
		// happen, and an OOM assertion is what unlocks a memory-limit diff.
		return "", ErrUnmappableReason
	}
}

// exitCodeFor reports the exit code to emit, and whether one is meaningful.
func exitCodeFor(incident *worker.Incident) (int32, bool) {
	if incident.Kind == ReasonCrashLoopBackOff {
		// Waiting to restart, not observed exiting. See Build.
		return 0, false
	}
	if incident.Record == nil {
		return 0, false
	}
	return incident.Record.ExitCode, true
}

// incidentID derives a stable identifier for an incident.
//
// Delegates the format to [newIncidentULID]; see that function for why the value
// is deterministic rather than random. The dedup key is the entropy source
// because it already encodes pod, container and restart count - the same triple
// that makes the incident a distinct incident.
func incidentID(incident *worker.Incident, detectedAt time.Time) (string, error) {
	var dedupKey string
	if incident.Record != nil {
		dedupKey = incident.Record.DedupKey
	}
	// A record-less incident hashes the empty key, which is still deterministic
	// and still valid. Build rejects a nil incident outright, so this is only
	// reachable from a caller that assembled one by hand.
	return newIncidentULID(dedupKey, detectedAt)
}

// timestampLayout is fixed-width RFC 3339 with exactly three fractional digits.
//
// Go's RFC3339Nano trims trailing zeros and can therefore emit between zero and
// nine fractional digits. `datetime.fromisoformat` on CPython 3.11 accepts up to
// six, but the emitter must not depend on that: a payload the agent rejects for a
// timestamp is an incident lost, and the fix would be a Python version bump nobody
// is looking for. Three digits is valid RFC 3339, parses on every Python 3, and
// keeps sub-second resolution for ordering.
const timestampLayout = "2006-01-02T15:04:05.000Z"

// formatTimestamp renders a detection instant as UTC RFC 3339.
//
// UTC is not cosmetic. The agent rejects any offset, because `detection_latency_ms`
// is measured against the same clock origin as this field; a non-UTC timestamp
// would make the latency meaningless without looking wrong.
func formatTimestamp(t time.Time) string {
	return t.UTC().Format(timestampLayout)
}

// clampLatency measures detection latency on the monotonic clock and caps it.
//
// The measurement uses [time.Time.Sub], which reads the monotonic reading Go
// stores in a Time when it came from time.Now. ROADMAP 3.5.3 requires exactly
// that: a duration measured by subtracting two wall-clock readings is wrong by
// whatever the clock drifted in between, and a backwards NTP step would produce a
// negative latency that then fails the agent's `ge=0` bound.
//
// The cap is the interesting part. The honest reading of an over-budget latency is
// "detection took 3.1 seconds", and the contract's `le=2000` means that value
// cannot be transmitted. Refusing to emit would convert a slow cluster into
// silence, and a slow cluster is exactly when the RCA matters most - so the value
// is clamped and [ErrLatencyClamped] is returned alongside it, for the caller to
// count. The cap is a reporting ceiling, not a licence to claim the SLO was met.
func clampLatency(incident *worker.Incident, detectedAt time.Time) int64 {
	var firstSeen time.Time
	if incident.Record != nil {
		firstSeen = incident.Record.FirstSeen
	}
	if firstSeen.IsZero() {
		// No detection instant recorded. Zero is the honest floor rather than a
		// guess; the agent's `ge=0` accepts it and a wrong number would not.
		return 0
	}
	elapsed := detectedAt.Sub(firstSeen)
	if elapsed < 0 {
		// Only reachable if a caller supplies a clock that went backwards. Zero
		// is the safe floor: it cannot fail the schema.
		return 0
	}
	milliseconds := elapsed.Milliseconds()
	if milliseconds > MaxDetectionLatencyMS {
		return MaxDetectionLatencyMS
	}
	return milliseconds
}

// ErrLatencyClamped reports that the measured latency exceeded the contract cap
// and was clamped. Not returned by Build - it accompanies a successful payload -
// but exposed so the caller can count over-budget detections rather than let the
// clamp hide them.
var ErrLatencyClamped = errors.New("emitter: detection latency exceeded the contract cap and was clamped")

// Clamped reports whether a payload's latency hit the ceiling, i.e. whether the
// real measurement was worse than what was sent.
func Clamped(payload *IncidentPayload) bool {
	return payload != nil && payload.DetectionLatency >= MaxDetectionLatencyMS
}

// redactionReport converts the scrubber's accounting into the wire report.
//
// `RulesTriggered` is copied, not aliased, so a caller mutating the returned
// slice cannot corrupt the scrubber's manifest-derived state.
func redactionReport(report scrubber.RedactionReport) RedactionReport {
	rules := make([]string, 0, len(report.RulesTriggered))
	for _, id := range report.RulesTriggered {
		rules = append(rules, string(id))
	}
	return RedactionReport{
		TotalRedactions: int64(report.Total),
		RulesTriggered:  rules,
	}
}

// nullable maps "" to nil, so an undeclared resource quantity becomes JSON null.
func nullable(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// nonNilStrings guarantees a JSON array rather than null.
//
// The agent declares `scrubbed_logs: list[str]` with no default, so `null` is a
// schema violation. An incident with no logs is a real and common outcome - the
// log fetch can fail - and it has to travel as `[]`.
func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilEvents(build func(*worker.Incident) []ClusterEvent, incident *worker.Incident) []ClusterEvent {
	if build == nil || len(incident.ScrubbedEventMessages) == 0 {
		return []ClusterEvent{}
	}
	events := build(incident)
	if events == nil {
		return []ClusterEvent{}
	}
	return events
}
