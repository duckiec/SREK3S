package scrubber

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

const sentinel = RedactionSentinel

// TestManifestMatchesSpecification pins the manifest against ARCHITECTURE.md §6.
// ROADMAP 1.1.3 requires the rules verbatim and 1.1.6 requires the order to be
// unchanged, so both are asserted rather than assumed.
func TestManifestMatchesSpecification(t *testing.T) {
	t.Parallel()

	if len(Manifest) != 11 {
		t.Fatalf("manifest has %d rules, ARCHITECTURE.md §6 defines 11", len(Manifest))
	}

	wantOrder := []RuleID{
		RulePEMPrivateKey, RuleAWSAccessKeyID, RuleAWSSecretKey, RuleJWT,
		RuleBearerToken, RuleBasicAuthURL, RuleGenericSecretKV, RuleUUID,
		RuleIPv4Address, RuleK8sSecretMount, RulePrivateKeyPEMBody,
	}
	for i, want := range wantOrder {
		if Manifest[i].ID != want {
			t.Errorf("rule %d is %q, want %q (order is normative, ARCH §6)", i, Manifest[i].ID, want)
		}
		if Manifest[i].RE == nil {
			t.Errorf("rule %q has a nil compiled pattern", Manifest[i].ID)
			continue
		}
		if _, err := regexp.Compile(Manifest[i].RE.String()); err != nil {
			t.Errorf("rule %q does not recompile cleanly: %v", Manifest[i].ID, err)
		}
	}

	// Rules 6 and 7 carry capture-group templates per the §6.3/§6.4 amendments.
	r, ok := ruleByID(RuleBasicAuthURL)
	if !ok {
		t.Fatal("basic_auth_url missing from manifest")
	}
	if got, want := r.templateFor(), "${1}"+sentinel+"${3}"; got != want {
		t.Errorf("basic_auth_url template = %q, want %q (ARCH §6.3 amendment)", got, want)
	}
	g, ok := ruleByID(RuleGenericSecretKV)
	if !ok {
		t.Fatal("generic_secret_kv missing from manifest")
	}
	if got, want := g.templateFor(), "${1}"+sentinel+"${3}"; got != want {
		t.Errorf("generic_secret_kv template = %q, want %q (ARCH §6.4 amendment, D-1)", got, want)
	}
}

// TestMultiLineFlagMatchesCapability is the proof obligation behind defect D-5.
//
// Each compiled rule is probed with newline-bearing inputs whose only
// distinguishing feature is an embedded newline. The observed capability must
// equal the declared MultiLine flag, in both directions: a false negative puts
// the rule outside the M3 cross-line pass and can reintroduce D-3, and a false
// positive costs throughput for nothing.
func TestMultiLineFlagMatchesCapability(t *testing.T) {
	t.Parallel()

	// Probes chosen so a match implies the match itself contains a newline.
	probes := map[RuleID][]string{
		RulePEMPrivateKey: {
			"-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
		},
		RuleAWSAccessKeyID: {"AKIAIOSFODNN7EXAM\nPLE"},
		RuleAWSSecretKey:   {"aws secret \"AAAA\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\""},
		RuleJWT:            {"eyJhbGci.eyJzdWIi\n.SflKxwRJ"},
		RuleBearerToken:    {"Bearer abc12345\n67890"},
		RuleBasicAuthURL:   {"a://b:c\nd@e"},
		RuleGenericSecretKV: {
			"password=AA\nBB",
			`{"password":"AA` + "\n" + `BB"}`,
			"api_key=sk-live-\n9f8a7b6c5d4e3f2a1b",
		},
		RuleUUID:              {"7f3a1b2c-4d5e-4f6\n0-8a9b-0c1d2e3f4a5b"},
		RuleIPv4Address:       {"10.4.2.9\n:5432"},
		RuleK8sSecretMount:    {"token for\nkube-system"},
		RulePrivateKeyPEMBody: {"-----BEGIN RSA PRIVATE\nKEY-----"},
	}

	for _, r := range Manifest {
		observed := false
		for _, probe := range probes[r.ID] {
			loc := r.RE.FindStringIndex(probe)
			if loc == nil {
				continue
			}
			if strings.ContainsRune(probe[loc[0]:loc[1]], '\n') {
				observed = true
				break
			}
		}
		if observed != r.MultiLine {
			t.Errorf("rule %q: MultiLine flag is %v but the compiled pattern is multi-line-capable=%v; "+
				"the M3 cross-line pass would %s", r.ID, r.MultiLine, observed,
				map[bool]string{true: "omit a rule that can match across lines", false: "scan for a rule that cannot"}[r.MultiLine])
		}
	}
}

// TestCrossLinePassRestrictedToMultiLineRules is the D-5 cost control: the
// cross-line pass must not fall back to the full manifest.
func TestCrossLinePassRestrictedToMultiLineRules(t *testing.T) {
	t.Parallel()

	ml := multiLineManifest()
	if len(ml) == 0 {
		t.Fatal("no rules marked MultiLine; the M3 pass would be a no-op")
	}
	if len(ml) >= len(Manifest) {
		t.Errorf("cross-line pass runs %d of %d rules; the D-5 restriction is not in effect",
			len(ml), len(Manifest))
	}
	for _, r := range ml {
		if !r.MultiLine {
			t.Errorf("multiLineManifest returned %q, which is not marked MultiLine", r.ID)
		}
	}
	t.Logf("cross-line pass runs %d of %d rules: %v", len(ml), len(Manifest), ruleIDs(ml))
}

func ruleIDs(rules []Rule) []RuleID {
	out := make([]RuleID, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.ID)
	}
	return out
}

// TestRuleByRule exercises each of the eleven rules with a canonical trigger,
// and asserts the secret is gone. Each case is run against the full pipeline,
// which is how the manifest is actually used.
func TestRuleByRule(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		// mustNotContain are the literal secrets that must not survive.
		mustNotContain []string
		// mustContain is text that must survive for the RCA to remain useful
		// (ARCH §6.1 M5, and the §6.3 rationale).
		mustContain []string
		wantRule    RuleID
	}{
		{
			name:           "pem_private_key whole block",
			in:             "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8Dbv8prpJ\n-----END RSA PRIVATE KEY-----",
			mustNotContain: []string{"BEGIN RSA PRIVATE KEY", "MIIEowIBAAKCAQEAy8Dbv8prpJ", "END RSA PRIVATE KEY"},
			wantRule:       RulePEMPrivateKey,
		},
		{
			name:           "pem_private_key pkcs8 without algorithm",
			in:             "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqh\n-----END PRIVATE KEY-----",
			mustNotContain: []string{"MIIEvQIBADANBgkqh"},
			wantRule:       RulePEMPrivateKey,
		},
		{
			name:           "pem_private_key openssh",
			in:             "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
			mustNotContain: []string{"b3BlbnNzaC1rZXktdjEAAAAA"},
			wantRule:       RulePEMPrivateKey,
		},
		{
			name:           "aws_access_key_id AKIA",
			in:             "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			mustNotContain: []string{"AKIAIOSFODNN7EXAMPLE"},
			mustContain:    []string{"aws_access_key_id="},
			wantRule:       RuleAWSAccessKeyID,
		},
		{
			name:           "aws_access_key_id AROA inline",
			in:             "assume-role AROAI44QH8DHBEXAMPLE proceeding",
			mustNotContain: []string{"AROAI44QH8DHBEXAMPLE"},
			mustContain:    []string{"assume-role", "proceeding"},
			wantRule:       RuleAWSAccessKeyID,
		},
		{
			name:           "aws_secret_access_key quoted 40 char",
			in:             `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
			mustNotContain: []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
			wantRule:       RuleAWSSecretKey,
		},
		{
			name:           "jwt three segment",
			in:             "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			mustNotContain: []string{"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
			mustContain:    []string{"token "},
			wantRule:       RuleJWT,
		},
		{
			name:           "bearer_token",
			in:             "Authorization: Bearer abc123def456ghi789jkl",
			mustNotContain: []string{"abc123def456ghi789jkl"},
			wantRule:       RuleBearerToken,
		},
		{
			// Rule 6, ARCH §6.3. The password goes; scheme, user, host and port
			// stay. Host and port are the topology an RCA reasons over.
			name:           "basic_auth_url postgres preserves topology",
			in:             "postgres://payments:hunter2@10.4.2.9:5432/payments",
			mustNotContain: []string{"hunter2"},
			mustContain:    []string{"postgres://payments:" + sentinel, "@", ":5432", "/payments"},
			wantRule:       RuleBasicAuthURL,
		},
		{
			name:           "basic_auth_url mysql preserves topology",
			in:             "mysql://root:s3cr3tP4ss@db.internal:3306/checkout",
			mustNotContain: []string{"s3cr3tP4ss"},
			mustContain:    []string{"mysql://root:" + sentinel, "@db.internal:3306", "/checkout"},
			wantRule:       RuleBasicAuthURL,
		},
		{
			name:           "basic_auth_url redis preserves topology",
			in:             "redis://cache-user:authToken99@redis.internal:6379/0",
			mustNotContain: []string{"authToken99"},
			mustContain:    []string{"redis://cache-user:" + sentinel, "@redis.internal:6379"},
			wantRule:       RuleBasicAuthURL,
		},
		{
			name:           "generic_secret_kv equals form",
			in:             "password=hunter2",
			mustNotContain: []string{"hunter2"},
			wantRule:       RuleGenericSecretKV,
		},
		{
			name:           "generic_secret_kv yaml colon form",
			in:             "password: hunter2",
			mustNotContain: []string{"hunter2"},
			wantRule:       RuleGenericSecretKV,
		},
		{
			name:           "uuid",
			in:             "trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b done",
			mustNotContain: []string{"7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b"},
			mustContain:    []string{"trace", "done"},
			wantRule:       RuleUUID,
		},
		{
			name:           "ipv4_address",
			in:             "dialing 10.4.2.9:5432",
			mustNotContain: []string{"10.4.2.9"},
			mustContain:    []string{":5432"},
			wantRule:       RuleIPv4Address,
		},
		{
			name:           "k8s_secret_mount namespace then token",
			in:             "kube-system reading ca.crt for the apiserver",
			mustNotContain: []string{"kube-system"},
			wantRule:       RuleK8sSecretMount,
		},
		{
			name:           "private_key_pem_body orphaned begin marker",
			in:             "truncated log: -----BEGIN RSA PRIVATE KEY----- <eof>",
			mustNotContain: []string{"-----BEGIN RSA PRIVATE KEY-----"},
			mustContain:    []string{"truncated log:", "<eof>"},
			wantRule:       RulePrivateKeyPEMBody,
		},
	}

	// Coverage guard, checked statically against the case list. It cannot be
	// derived from the subtests: they run in parallel, so a map they populate
	// would still be empty when this runs.
	covered := map[RuleID]bool{}
	for _, tc := range cases {
		covered[tc.wantRule] = true
	}
	for _, r := range Manifest {
		if !covered[r.ID] {
			t.Errorf("rule %q has no direct coverage in TestRuleByRule", r.ID)
		}
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := ScrubString(context.Background(), tc.in)

			for _, leak := range tc.mustNotContain {
				if strings.Contains(out, leak) {
					t.Errorf("SECRET LEAK: %q survived\n  in:  %q\n  out: %q", leak, tc.in, out)
				}
			}
			for _, keep := range tc.mustContain {
				if !strings.Contains(out, keep) {
					t.Errorf("diagnostic text lost: %q\n  in:  %q\n  out: %q", keep, tc.in, out)
				}
			}
		})
	}
}

// TestBasicAuthURLPreservesEndpointTopology is the explicit ARCH §6.3
// assertion requested for the postgres URI.
//
// It is checked twice, because the full pipeline additionally applies rule 9
// `ipv4_address` to an IP-literal host. Topology preservation and IP masking
// are separate concerns and both are correct.
func TestBasicAuthURLPreservesEndpointTopology(t *testing.T) {
	t.Parallel()

	const uri = "postgres://payments:hunter2@10.4.2.9:5432/payments"

	t.Run("rule 6 in isolation preserves host and port verbatim", func(t *testing.T) {
		t.Parallel()
		rule, ok := ruleByID(RuleBasicAuthURL)
		if !ok {
			t.Fatal("basic_auth_url missing")
		}
		out := rule.RE.ReplaceAllString(uri, rule.templateFor())
		if out != "postgres://payments:"+sentinel+"@10.4.2.9:5432/payments" {
			t.Errorf("rule 6 output = %q\nwant %q", out,
				"postgres://payments:"+sentinel+"@10.4.2.9:5432/payments")
		}
		if !strings.Contains(out, "10.4.2.9:5432") {
			t.Errorf("rule 6 destroyed the endpoint: %q", out)
		}
		if strings.Contains(out, "hunter2") {
			t.Errorf("rule 6 leaked the password: %q", out)
		}
	})

	t.Run("full pipeline preserves shape and port, masks IP by design", func(t *testing.T) {
		t.Parallel()
		out := ScrubString(context.Background(), uri)

		if strings.Contains(out, "hunter2") {
			t.Fatalf("password leaked: %q", out)
		}
		// The structural shape an RCA depends on must survive.
		for _, want := range []string{"postgres://payments:" + sentinel + "@", ":5432", "/payments"} {
			if !strings.Contains(out, want) {
				t.Errorf("lost %q from %q", want, out)
			}
		}
		// Rule 9 legitimately masks the IP-literal host.
		if !strings.Contains(out, "[REDACTED]:5432") {
			t.Errorf("expected the IP host to be masked by ipv4_address, got %q", out)
		}
	})
}

// TestNegativeControls asserts the manifest is not so broad that it destroys
// ordinary operational log content. Over-masking is acceptable (ARCH §6.1 M5),
// destroying every diagnostic is not.
func TestNegativeControls(t *testing.T) {
	t.Parallel()

	clean := []string{
		"2026-09-28T14:03:11.001Z INFO checkout started tenant=acme-corp latency_ms=42",
		"2026-09-28T14:03:11.233Z DEBUG pool checkout acquired conn id=1284 wait_ms=3",
		"2026-09-28T14:03:11.455Z INFO db query ok table=orders rows=17 duration_ms=8",
		"the AKIA prefix is used by AWS",
		"version 999.1.1.1 is not a valid address",
		"client 10.4.2",
		"retrying upstream call attempt=2 backoff_ms=100",
		"health probe /readyz status=200 duration_ms=2",
	}

	for _, in := range clean {
		if out := ScrubString(context.Background(), in); out != in {
			t.Errorf("clean line was modified\n  in:  %q\n  out: %q", in, out)
		}
	}
}

// TestIdempotence asserts invariant I-A5 across a broad corpus, including
// already-masked input. ROADMAP 1.2.5.
func TestIdempotence(t *testing.T) {
	t.Parallel()

	corpus := []string{
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAy8Dbv8prpJ\n-----END RSA PRIVATE KEY-----",
		"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		"token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"Authorization: Bearer abc123def456ghi789jkl",
		"postgres://payments:hunter2@10.4.2.9:5432/payments",
		"password=hunter2",
		"password: hunter2",
		"trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
		"dialing 10.4.2.9:5432",
		"kube-system reading ca.crt",
		sentinel,
		sentinel + sentinel,
		"password=" + sentinel,
		"postgres://payments:" + sentinel + "@10.4.2.9:5432/payments",
		"",
		"   ",
	}

	for _, in := range corpus {
		once := ScrubString(context.Background(), in)
		twice := ScrubString(context.Background(), once)
		if once != twice {
			t.Errorf("not idempotent\n  in:   %q\n  once: %q\n  twice:%q", in, once, twice)
		}
		// Third pass guards against slow drift.
		if third := ScrubString(context.Background(), twice); third != twice {
			t.Errorf("drifted on the third pass\n  2nd: %q\n  3rd: %q", twice, third)
		}
	}
}

// TestRedactionReportContainsNoPlaintext is rule M4 / ROADMAP 1.3.3: the report
// must carry no matched value, no fragment of one, and no reversible encoding.
func TestRedactionReportContainsNoPlaintext(t *testing.T) {
	t.Parallel()

	secrets := []string{
		"AKIAIOSFODNN7EXAMPLE",
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"hunter2",
		"s3cr3tP4ss",
		"authToken99",
		"abc123def456ghi789jkl",
		"7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
		"10.4.2.9",
	}
	lines := []string{
		"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		`aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		"postgres://payments:hunter2@10.4.2.9:5432/payments",
		"mysql://root:s3cr3tP4ss@db.internal:3306/checkout",
		"redis://cache-user:authToken99@redis.internal:6379/0",
		"Authorization: Bearer abc123def456ghi789jkl",
		"trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
	}

	_, rep := ScrubLines(context.Background(), lines)
	rendered := fmt.Sprintf("%+v", rep)

	for _, secret := range secrets {
		if strings.Contains(rendered, secret) {
			t.Errorf("report leaked %q: %s", secret, rendered)
		}
		// Assert a substantial prefix is absent too. The window is 8 characters
		// rather than something tiny: rule IDs are legitimate report content
		// and collide with short prefixes (basic_auth_url contains "auth").
		prefix := secret
		if len(prefix) > 8 {
			prefix = prefix[:8]
		}
		if strings.Contains(rendered, prefix) {
			t.Errorf("report leaked a prefix of %q (%q): %s", secret, prefix, rendered)
		}
	}
	if rep.Total == 0 {
		t.Error("report recorded zero redactions for a payload full of secrets")
	}
}

// TestReportTotalEqualsPerRuleCounts is ROADMAP 1.3.4. It asserts against the
// internal per-rule tallies, because RedactionReport deliberately exposes only
// a deduplicated rule list.
func TestReportTotalEqualsPerRuleCounts(t *testing.T) {
	t.Parallel()

	r := newRedactor()
	r.record(RuleAWSAccessKeyID, 2)
	r.record(RuleIPv4Address, 3)
	r.record(RuleUUID, 1)

	rep := r.report()
	if rep.Total != 6 {
		t.Errorf("Total = %d, want 6", rep.Total)
	}

	sum := 0
	for _, c := range r.counts {
		sum += c
	}
	if sum != rep.Total {
		t.Errorf("sum of per-rule counts = %d, Total = %d", sum, rep.Total)
	}
	if len(rep.RulesTriggered) != 3 {
		t.Errorf("RulesTriggered has %d entries, want 3: %v", len(rep.RulesTriggered), rep.RulesTriggered)
	}
}

// TestReportOrderingIsManifestOrder is ROADMAP 1.3.2: byte-stable output.
func TestReportOrderingIsManifestOrder(t *testing.T) {
	t.Parallel()

	// Fire rules out of manifest order to prove the sort, not the input order,
	// determines the result.
	r := newRedactor()
	r.record(RulePrivateKeyPEMBody, 1)
	r.record(RuleUUID, 1)
	r.record(RuleAWSAccessKeyID, 1)
	r.record(RuleBearerToken, 1)

	want := []RuleID{RuleAWSAccessKeyID, RuleBearerToken, RuleUUID, RulePrivateKeyPEMBody}
	got := r.report().RulesTriggered
	if len(got) != len(want) {
		t.Fatalf("RulesTriggered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("RulesTriggered = %v, want %v", got, want)
			break
		}
	}

	// Determinism: the same input must produce the same report bytes.
	_, a := ScrubLines(context.Background(), []string{"password=hunter2", "dialing 10.4.2.9"})
	_, b := ScrubLines(context.Background(), []string{"password=hunter2", "dialing 10.4.2.9"})
	if fmt.Sprint(a) != fmt.Sprint(b) {
		t.Errorf("report is not deterministic: %v vs %v", a, b)
	}
}

// TestNilContextIsSafe is ROADMAP 1.2.6.
func TestNilContextIsSafe(t *testing.T) {
	t.Parallel()

	//nolint:staticcheck // deliberately passing nil to prove it is handled
	if out := ScrubString(nil, "password=hunter2"); strings.Contains(out, "hunter2") {
		t.Errorf("nil ctx produced a leak: %q", out)
	}
	//nolint:staticcheck
	if out, _ := ScrubLines(nil, []string{"password=hunter2"}); strings.Contains(out[0], "hunter2") {
		t.Errorf("nil ctx produced a leak: %q", out[0])
	}
}

// TestContextCancellation is ROADMAP 1.2.7.
//
// The ratified wording of 1.2.7 asks for a "partially-masked buffer ... never
// raw", which is self-contradictory for an ordered manifest: aborting after
// rule 6 leaves every rule 7 secret in the buffer. See the scrub doc comment
// for the resolution. These tests assert the contract that is actually safe:
// every returned line has been through the complete manifest.
func TestContextCancellation(t *testing.T) {
	t.Parallel()

	t.Run("pre-cancelled context returns masked output, never raw", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		lines := []string{
			"password=leakedOne",
			"api_key=sk-live-leakedTwo",
			"dialing 10.4.2.999",
			"trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4afff",
		}
		out, rep := ScrubLines(ctx, lines)

		// A pre-cancelled context may legitimately return zero lines. Whatever
		// it returns must be fully masked.
		secrets := []string{"leakedOne", "sk-live-leakedTwo", "10.4.2.999", "0c1d2e3f4afff"}
		for i, line := range out {
			for _, secret := range secrets {
				if strings.Contains(line, secret) {
					t.Errorf("line %d leaked %q after cancellation: %q", i, secret, line)
				}
			}
		}
		t.Logf("pre-cancelled: returned %d of %d lines, total=%d", len(out), len(lines), rep.Total)
	})

	t.Run("cancellation mid-batch never yields a partially masked line", func(t *testing.T) {
		t.Parallel()
		// Each line carries a secret unique to its index, so any unmasked line
		// is detected unambiguously. The deadline is short enough to land
		// mid-batch, and the assertion holds whether or not it fires.
		//
		// Scaled down under -race: 4000 lines x 11 patterns is heavy, and
		// ROADMAP 1.5.3 budgets 30s for the entire binary. The assertion is
		// identical, only the batch is smaller.
		n := 4000
		if raceEnabled {
			n = 600
		}
		lines := make([]string, n)
		for i := range lines {
			lines[i] = fmt.Sprintf(
				"2026-09-28T14:03:11.001Z INFO request %d password=secretNumber%d db=postgres://u:pw%d@10.4.2.%d:5432/x",
				i, i, i, i%250)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
		defer cancel()

		out, _ := ScrubLines(ctx, lines)

		for i, line := range out {
			for _, leak := range []string{
				fmt.Sprintf("secretNumber%d ", i),
				fmt.Sprintf("pw%d@", i),
			} {
				if strings.Contains(line, leak) {
					t.Fatalf("line %d leaked %q after mid-batch cancellation: %q", i, leak, line)
				}
			}
		}
		t.Logf("returned %d of %d lines after mid-batch cancellation, all fully masked", len(out), n)
	})

	t.Run("uncancelled context scrubs everything", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		lines := []string{"password=hunter2", "dialing 10.4.2.9"}
		out, rep := ScrubLines(ctx, lines)
		if len(out) != 2 {
			t.Fatalf("got %d lines, want 2", len(out))
		}
		if strings.Contains(out[0], "hunter2") {
			t.Errorf("leak: %q", out[0])
		}
		if rep.Total == 0 {
			t.Error("no redactions recorded")
		}
	})
}

// TestCrossLineSecret is ROADMAP 1.4.6, the M3 safety pass.
func TestCrossLineSecret(t *testing.T) {
	t.Parallel()

	t.Run("secret split across a line boundary is caught", func(t *testing.T) {
		t.Parallel()
		// The value straddles two lines, so no single line matches rule 7.
		lines := []string{
			"db password=hunter",
			"2 tail",
		}
		out, _ := ScrubLines(context.Background(), lines)
		joined := strings.Join(out, "\n")
		if strings.Contains(joined, "hunter\n2") {
			t.Errorf("cross-line secret survived: %q", joined)
		}
	})
}

// TestD3_CrossLinePEMBlockIsRemovedAsOneSpan is the ratified fix for defect
// D-3, asserted as a live conformance test.
//
// Before the fix, the per-line pass ran rule 11 private_key_pem_body first,
// which redacted only the BEGIN marker. By the time the cross-line pass joined
// the lines, rule 1 pem_private_key had no BEGIN...END pair left to match, so
// the base64 key body and the END marker survived verbatim. The fix runs the
// multi-line pass first, so rule 1 sees an intact block.
func TestD3_CrossLinePEMBlockIsRemovedAsOneSpan(t *testing.T) {
	t.Parallel()

	const body = "MIIEowIBAAKCAQEAy8Dbv8prpJ0kKhlGeJYozo2t60EG8L0561g13R29LvMR5hy"

	lines := []string{
		"loading key material",
		"-----BEGIN RSA PRIVATE KEY-----",
		body,
		"-----END RSA PRIVATE KEY-----",
		"key material loaded",
	}
	out, rep := ScrubLines(context.Background(), lines)
	joined := strings.Join(out, "\n")

	if strings.Contains(joined, body) {
		t.Errorf("D-3 REGRESSION: PEM body survived the cross-line pass\n%s", joined)
	}
	if strings.Contains(joined, "-----END RSA PRIVATE KEY-----") {
		t.Errorf("D-3 REGRESSION: END marker survived\n%s", joined)
	}
	// Surrounding diagnostics must survive: masking must not eat the log.
	if !strings.Contains(joined, "loading key material") || !strings.Contains(joined, "key material loaded") {
		t.Errorf("diagnostic text around the block was destroyed\n%s", joined)
	}
	// RedactionReport exposes only {Total, RulesTriggered} by design (ARCH §6.1
	// M4: counts only, no per-rule tallies), so the assertion is membership.
	if !slices.Contains(rep.RulesTriggered, RulePEMPrivateKey) {
		t.Errorf("expected rule pem_private_key to fire; report was %+v", rep)
	}

	// The single-string path never sees a newline, so it relies on rule 1
	// matching an embedded one.
	if one := ScrubString(context.Background(), strings.Join(lines, "\n")); strings.Contains(one, body) {
		t.Errorf("D-3 REGRESSION: PEM body survived ScrubString\n%s", one)
	}
}

// TestEmptyAndEdgeInputs is ROADMAP 1.4.8.
func TestEmptyAndEdgeInputs(t *testing.T) {
	t.Parallel()

	t.Run("nil slice", func(t *testing.T) {
		t.Parallel()
		out, rep := ScrubLines(context.Background(), nil)
		if out != nil {
			t.Errorf("got %v, want nil", out)
		}
		if rep.Total != 0 {
			t.Errorf("nil input produced a report: %+v", rep)
		}
	})

	t.Run("empty and whitespace strings", func(t *testing.T) {
		t.Parallel()
		for _, in := range []string{"", " ", "\t\n  ", "\x00\x01\x02"} {
			if out := ScrubString(context.Background(), in); out != in {
				t.Errorf("input %q became %q", in, out)
			}
		}
	})

	t.Run("one megabyte single line", func(t *testing.T) {
		t.Parallel()
		if testing.Short() {
			t.Skip("1 MiB single line skipped in -short mode")
		}
		// Halved under -race. Eleven patterns over 1 MiB of attacker-shaped text
		// is the most expensive test in the package, and ROADMAP 1.5.3 gives the
		// whole binary 30s. The behaviour under test (no panic, secret removed)
		// is identical at half the size; only the volume differs.
		shift := uint(16)
		if raceEnabled {
			shift = 15
		}
		big := strings.Repeat("password=hunter2 ", 1<<shift)
		out := ScrubString(context.Background(), big)
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret survived in a %d KiB line", len(big)>>10)
		}
	})

	t.Run("invalid utf8 does not panic", func(t *testing.T) {
		t.Parallel()
		bad := string([]byte{0xff, 0xfe, 0x00, 0x80, 0x81}) + " password=hunter2"
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("panicked on invalid UTF-8: %v", r)
			}
		}()
		out := ScrubString(context.Background(), bad)
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret survived alongside invalid UTF-8: %q", out)
		}
	})

	t.Run("multi-byte text is preserved", func(t *testing.T) {
		t.Parallel()
		// Note on the expectation: rule 7's value class is [^"',;}]{4,}, which
		// includes spaces and multibyte runes, so a trailing token after the
		// secret on the same line is consumed too. That over-masking is a known
		// property of the ratified pattern, tolerated by ARCH §6.1 M5
		// (over-masking beats under-masking). What matters here is that the
		// secret is gone and the text is still valid UTF-8.
		in := "2026-09-28T14:03:11.204Z 日本語のログ password=hunter2"
		out := ScrubString(context.Background(), in)
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret survived: %q", out)
		}
		if !utf8.ValidString(out) {
			t.Errorf("scrubbing produced invalid UTF-8: %q", out)
		}
		if !strings.Contains(out, "日本語") {
			t.Errorf("leading multi-byte diagnostic text was destroyed: %q", out)
		}
	})
}

// TestScrubLinesDoesNotAliasInput guards the same class of bug as ARCHITECTURE
// §10 INV-4: the caller's slice must not keep holding unsanitized text.
func TestScrubLinesDoesNotAliasInput(t *testing.T) {
	t.Parallel()

	in := []string{"password=hunter2", "dialing 10.4.2.9"}
	out, _ := ScrubLines(context.Background(), in)

	for i := range in {
		if in[i] == out[i] {
			t.Errorf("line %d was aliased, not sanitized: %q", i, in[i])
		}
	}
}

// TestNoDiskArtifacts is ROADMAP 1.4.10: the shipped code must not touch the
// disk. The audit covers non-test files only, because the test suite reads the
// corpus fixture from disk legitimately.
func TestNoDiskArtifacts(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"os", "io", "io/ioutil", "io/fs", "net", "net/http",
		"os/exec", "path/filepath", "database/sql",
	}
	got := packageImports()
	for _, imp := range forbidden {
		if got[imp] {
			t.Errorf("shipped code imports %q; ARCH §6.1 M2 requires in-memory only", imp)
		}
	}
	t.Logf("shipped imports: %v", keysOf(got))
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestConcurrency is the -race target for ROADMAP 1.5.3.
func TestConcurrency(t *testing.T) {
	t.Parallel()

	const goroutines = 32
	const iterations = 200

	lines := []string{
		"password=hunter2",
		"aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
		"Authorization: Bearer abc123def456ghi789jkl",
		"postgres://payments:hunter2@10.4.2.9:5432/payments",
		"trace 7f3a1b2c-4d5e-4f60-8a9b-0c1d2e3f4a5b",
		"clean operational line",
	}

	done := make(chan struct{}, goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < iterations; i++ {
				line := lines[(g+i)%len(lines)]
				out := ScrubString(context.Background(), line)
				if strings.Contains(out, "hunter2") && !strings.Contains(line, "10.4.2.9") {
					t.Errorf("concurrent scrub leaked: %q", out)
				}
			}
		}(g)
	}
	for g := 0; g < goroutines; g++ {
		<-done
	}
}
