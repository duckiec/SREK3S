package emitter

import (
	"fmt"
	"regexp"
)

// Client-side enforcement of agent/models.py's bounds.
//
// This file exists so a malformed payload fails at the producer, naming the
// offending field, instead of at the consumer as an HTTP 422 that reads like a
// network fault. The agent's response to a schema violation is fatal by design
// (ROADMAP 3.4.4: 422 is never retried), so a payload that violates the contract
// takes its incident with it. Catching the violation one process earlier, with the
// field name attached, is the difference between a fixable bug report and a
// mystery.
//
// The patterns are transcribed from agent/models.py, not generated from it, and
// TestQuantityPatternMatchesThePythonSchema re-reads them from the Python source
// so a change on that side fails this package's tests. Transcription is a real
// risk and it is the lesser one: a Go/Python schema generator would add a codegen
// step to a codebase that currently has one, and a build dependency is a larger
// supply-chain surface than a regex that a test checks.
var (
	// dns1123Label is the agent's namespace/pod_name/container_name pattern.
	//
	// Note it is a *label* pattern (max 63 by Kubernetes' own rules) applied to
	// fields the agent allows up to 253. Transcribed as-is rather than
	// "corrected": the contract is what the consumer accepts, and a stricter Go
	// check would reject names the agent would have taken.
	dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

	// quantityPattern mirrors the agent's `Quantity` type.
	quantityPattern = regexp.MustCompile(QuantityPatternSource)

	// schemaVersionPattern mirrors `schema_version`'s `^\d+\.\d+\.\d+$`.
	schemaVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// rfc3339UTC accepts what [formatTimestamp] emits, and is deliberately narrow:
	// it is a self-check on this package's own formatter, not a general RFC 3339
	// parser. If it ever rejects a timestamp the formatter produced, the two have
	// diverged and the incident should not be sent.
	rfc3339UTC = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)

	// eventTypePattern mirrors `ClusterEvent.type`, which the agent constrains to
	// the literal set {"Normal", "Warning"}.
	eventTypePattern = regexp.MustCompile(`^(Normal|Warning)$`)

	// incidentIDPattern mirrors agent/models.py's `_INCIDENT_ID_RE`: the `inc_`
	// prefix plus a Crockford base32 body of 20-32 symbols. I, L, O and U are
	// absent from the class because Crockford leaves them unassigned.
	incidentIDPattern = regexp.MustCompile(`^inc_[0-9A-HJKMNP-TV-Z]{20,32}$`)
)

// Bounds copied from agent/models.py.
const (
	maxNameLength         = 253
	maxEventTypeLength    = 32
	maxEventReasonLength  = 128
	maxEventMessageLength = 4096
	maxInvolvedObjectMin  = 3
	maxInvolvedObjectMax  = 512
	maxSentinelVersionLen = 64
	minSchemaVersionLen   = 5
	maxSchemaVersionLen   = 32
)

// Validate checks a payload against the consumer's contract.
//
// Returns an error wrapping [ErrContractViolation] naming the first field that
// cannot be represented. It reports the first failure rather than all of them
// because the build path constructs the fields in a fixed order, so a single
// message is a stable, greppable description of a class of defect.
//
// This is not a replacement for the agent's validation. It is a subset: the
// checks here are the ones a producer can get wrong through a mapping mistake.
// Semantic rules the agent enforces that depend on cross-field agreement -
// `reason == OOMKilled` implying `exit_code == 137` (I-A2) and a non-null memory
// limit - are checked too, because those are exactly the fields Build fills in
// from separate sources and can therefore get out of step.
func Validate(payload *IncidentPayload) error {
	if payload == nil {
		return fmt.Errorf("%w: nil payload", ErrContractViolation)
	}

	if !schemaVersionPattern.MatchString(payload.SchemaVersion) ||
		len(payload.SchemaVersion) < minSchemaVersionLen ||
		len(payload.SchemaVersion) > maxSchemaVersionLen {
		return violation("schema_version", payload.SchemaVersion)
	}

	// The agent's `_INCIDENT_ID_RE` requires the `inc_` prefix followed by a
	// Crockford base32 body. Checked with the same alphabet rather than a
	// `strings.HasPrefix` alone, because the body is where a wrong encoder shows
	// up - and an earlier version of this file used lowercase hex, which passed a
	// prefix-only check and would have been a 422 in production.
	if !incidentIDPattern.MatchString(payload.IncidentID) {
		return violation("incident_id", payload.IncidentID)
	}

	if !rfc3339UTC.MatchString(payload.Timestamp) {
		return violation("timestamp", payload.Timestamp)
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{"namespace", payload.Namespace},
		{"pod_name", payload.PodName},
		{"container_name", payload.ContainerName},
	} {
		if err := validateName(field.name, field.value); err != nil {
			return err
		}
	}

	switch payload.Reason {
	case ReasonOOMKilled, ReasonCrashLoopBackOff:
	default:
		return violation("reason", payload.Reason)
	}

	if payload.RestartCount < 0 {
		return violation("restart_count", payload.RestartCount)
	}

	if payload.DetectionLatency < 0 || payload.DetectionLatency > MaxDetectionLatencyMS {
		return violation("detection_latency_ms", payload.DetectionLatency)
	}

	if payload.SentinelVersion == "" || len(payload.SentinelVersion) > maxSentinelVersionLen {
		return violation("sentinel_version", payload.SentinelVersion)
	}

	if payload.PreviousReason != nil && len(*payload.PreviousReason) > maxPreviousReasonLen {
		return violation("previous_reason", *payload.PreviousReason)
	}

	if err := validateResourceLimits(payload.ResourceLimits); err != nil {
		return err
	}

	if err := validateEvents(payload.ClusterEvents); err != nil {
		return err
	}

	if payload.RedactionReport.TotalRedactions < 0 {
		return violation("redaction_report.total_redactions", payload.RedactionReport.TotalRedactions)
	}

	// I-A2, the agent's cross-field invariant. Checked here because Build fills
	// `exit_code` and `resource_limits.memory_limit` from two independent sources -
	// the terminated state and the pod spec - and nothing else in the pipeline
	// would notice if they disagreed.
	//
	// The OOM case is the one that matters: `reason == OOMKilled` is what unlocks a
	// memory-limit diff, so a payload claiming an OOM kill with no memory limit
	// declared is asking the agent to reason about a limit it was never told.
	if payload.Reason == ReasonOOMKilled {
		if payload.ExitCode == nil {
			return violation("exit_code", "required when reason is OOMKilled")
		}
		if *payload.ExitCode != 137 {
			return violation("exit_code", *payload.ExitCode)
		}
		if payload.ResourceLimits.MemoryLimit == nil {
			return violation("resource_limits.memory_limit", "required when reason is OOMKilled")
		}
	}

	// I-A3, the CrashLoop invariant.
	if payload.Reason == ReasonCrashLoopBackOff && payload.RestartCount < 1 {
		return violation("restart_count", payload.RestartCount)
	}

	return nil
}

func validateName(field, value string) error {
	if value == "" {
		return violation(field, "must not be empty")
	}
	if len(value) > maxNameLength {
		return violation(field, "exceeds max_length")
	}
	if !dns1123Label.MatchString(value) {
		return violation(field, value)
	}
	return nil
}

func validateResourceLimits(limits ResourceLimits) error {
	for _, field := range []struct {
		name  string
		value *string
	}{
		{"resource_limits.cpu_limit", limits.CPULimit},
		{"resource_limits.cpu_request", limits.CPURequest},
		{"resource_limits.memory_limit", limits.MemoryLimit},
		{"resource_limits.memory_request", limits.MemoryRequest},
	} {
		if field.value == nil {
			continue
		}
		if !quantityPattern.MatchString(*field.value) {
			return violation(field.name, *field.value)
		}
	}
	if limits.MemoryWorkingSetBytes != nil && *limits.MemoryWorkingSetBytes < 0 {
		return violation("resource_limits.memory_working_set_bytes", *limits.MemoryWorkingSetBytes)
	}
	return nil
}

func validateEvents(events []ClusterEvent) error {
	for i, event := range events {
		prefix := fmt.Sprintf("cluster_events[%d]", i)
		if !eventTypePattern.MatchString(event.Type) || len(event.Type) > maxEventTypeLength {
			return violation(prefix+".type", event.Type)
		}
		if event.Reason == "" || len(event.Reason) > maxEventReasonLength {
			return violation(prefix+".reason", event.Reason)
		}
		if event.Message == "" || len(event.Message) > maxEventMessageLength {
			return violation(prefix+".message", event.Message)
		}
		if event.Count < 0 {
			return violation(prefix+".count", event.Count)
		}
		if len(event.InvolvedObject) < maxInvolvedObjectMin ||
			len(event.InvolvedObject) > maxInvolvedObjectMax {
			return violation(prefix+".involved_object", event.InvolvedObject)
		}
		for _, field := range []struct {
			name  string
			value *string
		}{
			{prefix + ".first_timestamp", event.FirstTimestamp},
			{prefix + ".last_timestamp", event.LastTimestamp},
		} {
			if field.value != nil && !rfc3339UTC.MatchString(*field.value) {
				return violation(field.name, *field.value)
			}
		}
	}
	return nil
}

func violation(field string, value any) error {
	return fmt.Errorf("%w: %s = %v", ErrContractViolation, field, value)
}
