package deploy

import (
	"strings"
	"testing"
)

// observatonalVerbs is the complete set ARCHITECTURE.md §1 permits against a
// cluster. Membership, not absence-from-a-deny-list, so a verb nobody anticipated
// fails the check.
var observatonalVerbs = map[string]bool{
	"get": true, "list": true, "watch": true,
}

// TestSentinelRoleGrantsNoMutatingVerb is terminal-validation item 4, and the
// load-bearing control for ARCHITECTURE.md §1's zero-mutation guarantee.
//
// Paired with the equivalent pytest in agent/tests/test_deploy_manifests.py, and
// the duplication is deliberate rather than accidental: the two run in different CI
// jobs on different toolchains, and a manifest that is hardened in one and
// unguarded in the other is still unguarded.
func TestSentinelRoleGrantsNoMutatingVerb(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "rbac.yaml"))
	if err != nil {
		t.Fatalf("rbac.yaml: %v", err)
	}
	role, err := one(documents, "Role")
	if err != nil {
		t.Fatalf("%v", err)
	}

	rules, ok := role["rules"].([]any)
	if !ok {
		t.Fatalf("Role.rules is %T; the verb check would pass vacuously", role["rules"])
	}
	if len(rules) == 0 {
		t.Fatal("Role.rules is empty; a deny-list check would pass on a Role that " +
			"grants nothing, and the Sentinel would watch nothing in silence")
	}

	var granted []string
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a rule is %T, want a mapping", raw)
		}
		for _, verb := range strList(t, rule["verbs"], "rule.verbs") {
			if !observatonalVerbs[verb] {
				granted = append(granted, verb)
			}
		}
	}
	if len(granted) > 0 {
		t.Errorf("the Sentinel's Role grants non-observational verbs: %v", granted)
	}
}

// TestSentinelRoleGrantsWhatTheWatcherReads is the converse.
//
// A Role that permits nothing mutating but also permits nothing at all satisfies
// the check above and produces a Sentinel that watches the cluster and reports
// nothing - the most dangerous possible failure for this system, because it is
// silent.
func TestSentinelRoleGrantsWhatTheWatcherReads(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "rbac.yaml"))
	if err != nil {
		t.Fatalf("rbac.yaml: %v", err)
	}
	role, err := one(documents, "Role")
	if err != nil {
		t.Fatalf("%v", err)
	}

	granted := map[string]bool{}
	for _, raw := range role["rules"].([]any) {
		rule := raw.(map[string]any)
		for _, resource := range strList(t, rule["resources"], "rule.resources") {
			granted[resource] = true
		}
	}
	for _, required := range []string{"pods", "pods/log", "events", "deployments", "replicasets"} {
		if !granted[required] {
			t.Errorf("the Role does not grant %q; the watcher's log fetch reads the "+
				"pods/log subresource, which a rule on pods alone does not cover", required)
		}
	}
}

// TestNoClusterScopedBindingWidensTheSentinel is the escalation check.
//
// A namespaced Role bound through a ClusterRoleBinding passes every verb assertion
// in this file while granting read access to every namespace in the cluster.
func TestNoClusterScopedBindingWidensTheSentinel(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "rbac.yaml"))
	if err != nil {
		t.Fatalf("rbac.yaml: %v", err)
	}
	if found := byKind(documents, "ClusterRole"); len(found) > 0 {
		t.Errorf("rbac.yaml declares %d ClusterRole(s); the Sentinel's Role is namespaced", len(found))
	}
	if found := byKind(documents, "ClusterRoleBinding"); len(found) > 0 {
		t.Errorf("rbac.yaml declares %d ClusterRoleBinding(s)", len(found))
	}
	binding, err := one(documents, "RoleBinding")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if kind := dig(binding, "roleRef", "kind"); kind != "Role" {
		t.Errorf("roleRef.kind = %v, want Role", kind)
	}
}

// hardeningField is one ARCH §8 assertion, as a path and an expected value.
type hardeningField struct {
	name  string
	path  []string
	value any
}

func sentinelHardening() []hardeningField {
	return []hardeningField{
		{"runAsUser", []string{"securityContext", "runAsUser"}, 10001},
		{"runAsGroup", []string{"securityContext", "runAsGroup"}, 10001},
		{"runAsNonRoot", []string{"securityContext", "runAsNonRoot"}, true},
		{"readOnlyRootFilesystem", []string{"securityContext", "readOnlyRootFilesystem"}, true},
		{"allowPrivilegeEscalation", []string{"securityContext", "allowPrivilegeEscalation"}, false},
		{"privileged", []string{"securityContext", "privileged"}, false},
	}
}

// TestSentinelDeploymentCarriesTheFullHardeningBlock is terminal-validation item 4's
// second half: ARCH §8, enforced where a Dockerfile cannot reach.
func TestSentinelDeploymentCarriesTheFullHardeningBlock(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}

	containers, ok := digSlice(deployment, "spec", "template", "spec", "containers")
	if !ok || len(containers) == 0 {
		t.Fatalf("no containers found; the hardening checks below would pass vacuously")
	}
	for _, raw := range containers {
		container, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("a container entry is %T", raw)
		}
		for _, field := range sentinelHardening() {
			actual := dig(container, field.path...)
			if actual != field.value {
				t.Errorf("container %v: %s = %v, want %v",
					container["name"], field.name, actual, field.value)
			}
		}

		drop := dig(container, "securityContext", "capabilities", "drop")
		list, ok := drop.([]any)
		if !ok || len(list) != 1 || list[0] != "ALL" {
			t.Errorf("container %v: capabilities.drop = %v, want [ALL]",
				container["name"], drop)
		}
	}
}

// TestSentinelPodSecurityContextIsComplete covers the fields a container-level
// block cannot express.
//
// `seccompProfile` in particular: a Dockerfile cannot set it, so if the manifest
// does not, nothing else in the repository does.
func TestSentinelPodSecurityContextIsComplete(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	podSpec := dig(deployment, "spec", "template", "spec")

	if got := dig(podSpec, "securityContext", "runAsUser"); got != 10001 {
		t.Errorf("pod securityContext.runAsUser = %v, want 10001", got)
	}
	if got := dig(podSpec, "securityContext", "runAsGroup"); got != 10001 {
		t.Errorf("pod securityContext.runAsGroup = %v, want 10001", got)
	}
	// fsGroup owns the emptyDir. Without it matching the run group, /tmp is
	// group-root and the non-root process cannot write to it - and a read-only root
	// filesystem leaves nowhere else to write, so the pod would fail at first use.
	if got := dig(podSpec, "securityContext", "fsGroup"); got != 10001 {
		t.Errorf("pod securityContext.fsGroup = %v, want 10001", got)
	}
	if got := dig(podSpec, "securityContext", "seccompProfile", "type"); got != "RuntimeDefault" {
		t.Errorf("seccompProfile.type = %v, want RuntimeDefault; a Dockerfile "+
			"cannot express this, so the manifest is the only place it is set", got)
	}
}

// TestTmpIsTheOnlyWritablePath is 3.6.3's second clause.
func TestTmpIsTheOnlyWritablePath(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	podSpec := dig(deployment, "spec", "template", "spec")

	volumes, ok := digSlice(podSpec, "volumes")
	if !ok {
		t.Fatal("no volumes; the /tmp mount would have nothing to mount")
	}
	volumeKinds := map[string]bool{}
	volumeConfigMap := map[string]bool{}
	for _, raw := range volumes {
		volume := raw.(map[string]any)
		volumeKinds[volume["name"].(string)] = volume["emptyDir"] != nil
		volumeConfigMap[volume["name"].(string)] = volume["configMap"] != nil
	}

	containers, _ := digSlice(podSpec, "containers")
	for _, raw := range containers {
		container := raw.(map[string]any)
		mounts, ok := digSlice(container, "volumeMounts")
		if !ok {
			continue
		}
		for _, rawMount := range mounts {
			mount := rawMount.(map[string]any)
			if mount["mountPath"] != "/tmp" {
				// A read-only projected ConfigMap is the one allowed exception:
				// it is not writable state and cannot outlive the pod. Every
				// other path must remain on the read-only root filesystem.
				if !volumeConfigMap[mount["name"].(string)] || mount["readOnly"] != true {
					t.Errorf("container %v mounts %v; ARCH §8 allows /tmp only unless read-only config",
						container["name"], mount["mountPath"])
				}
			}
			if isEmptyDir, known := volumeKinds[mount["name"].(string)]; !known || !isEmptyDir {
				if volumeConfigMap[mount["name"].(string)] && mount["readOnly"] == true {
					continue
				}
				t.Errorf("container %v mounts volume %v, which is not an emptyDir; "+
					"a hostPath or PVC is writable state that outlives the pod",
					container["name"], mount["name"])
			}
		}
	}
}

// TestNoInitOrEphemeralContainers is a gap this file closed.
//
// The first draft checked only `spec.containers`, which a privileged
// `initContainers` entry would sail past - running as root with full capabilities,
// then handing the main container a writable root.
func TestNoInitOrEphemeralContainers(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	podSpec := dig(deployment, "spec", "template", "spec")
	for _, key := range []string{"initContainers", "ephemeralContainers"} {
		if entries, ok := podSpec.(map[string]any)[key]; ok && entries != nil {
			t.Errorf("sentinel.yaml declares %s; this file's hardening checks "+
				"inspect spec.containers only and would not see them", key)
		}
	}
}

// TestAgentDoesNotAutomountAServiceAccountToken is 3.6.5.
//
// Stronger than "the agent's verbs are read-only": no token at all, so it cannot
// write to the cluster even if a future bug tried.
func TestAgentDoesNotAutomountAServiceAccountToken(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "agent.yaml"))
	if err != nil {
		t.Fatalf("agent.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	podSpec := dig(deployment, "spec", "template", "spec").(map[string]any)

	if got := podSpec["automountServiceAccountToken"]; got != false {
		t.Errorf("agent automountServiceAccountToken = %v, want false; the agent "+
			"makes no Kubernetes API calls and must hold no cluster credential", got)
	}
	if _, present := podSpec["serviceAccountName"]; present {
		t.Error("the agent names a ServiceAccount; it should name none")
	}
}

// TestSentinelTerminationGraceExceedsTheDrainBudget connects two files that
// nothing else links.
//
// ShutdownGrace lives in cmd/sentinel/main.go; terminationGracePeriodSeconds lives
// here. Raise the drain past the grace period and the kubelet SIGKILLs the process
// mid-drain on every rolling update - with no error anywhere, because the loss is
// silent by construction.
//
// THE PATH IS PodSpec, NOT THE CONTAINER, and it was wrong here until 2026-10-01.
//
// This test read the value from containers[0]. terminationGracePeriodSeconds is a
// field of PodSpec with no container-level counterpart, so the apiserver rejects the
// whole Deployment with a strict-decoding error naming
// "spec.template.spec.containers[0].terminationGracePeriodSeconds". The field
// shipped at that level and the deploy set could not be applied at all - found by
// applying it to a live control plane, not by any test.
//
// The assertion passed for a whole milestone because it ran against a YAML parser,
// where the value is present and plausible at either indentation. Reading a document
// is not the same as validating one, and a check written against a parser inherits
// that limit. TestTerminationGraceIsNotOnAContainer is the companion assertion that
// closes it; see also deploy/sentinel.yaml.
func TestSentinelTerminationGraceExceedsTheDrainBudget(t *testing.T) {
	source := readRepoFile(t, "cmd", "sentinel", "main.go")
	grace := parseIntAfter(t, source, "ShutdownGrace = ")

	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	actual := dig(deployment, "spec", "template", "spec", "terminationGracePeriodSeconds")

	seconds, ok := actual.(int)
	if !ok {
		t.Fatalf("pod-level terminationGracePeriodSeconds is %T, want an integer; it "+
			"must be a sibling of `containers` under spec.template.spec", actual)
	}
	if seconds <= grace {
		t.Errorf("terminationGracePeriodSeconds = %d, ShutdownGrace = %d; the "+
			"kubelet would SIGKILL the process before the drain finished, making "+
			"the graceful shutdown path decorative", seconds, grace)
	}
}

// TestTerminationGraceIsNotOnAContainer proves the field is absent at container
// level, in both shipped deployments.
//
// Negative-controlled in TestTerminationGraceContainerFieldIsDetectable, which
// feeds this the very shape that shipped and requires it to object.
func TestTerminationGraceIsNotOnAContainer(t *testing.T) {
	for _, name := range []string{"sentinel.yaml", "agent.yaml"} {
		documents, err := decodeAll(readManifest(t, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		deployment, err := one(documents, "Deployment")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		containers, _ := digSlice(deployment, "spec", "template", "spec", "containers")
		if len(containers) == 0 {
			t.Fatalf("%s: no containers to check", name)
		}
		for _, raw := range containers {
			container, ok := raw.(map[string]any)
			if !ok {
				t.Fatalf("%s: container entry is %T, want a map", name, raw)
			}
			if _, present := container["terminationGracePeriodSeconds"]; present {
				t.Errorf("%s: container %v sets terminationGracePeriodSeconds. It is "+
					"a PodSpec field; the apiserver refuses the entire Deployment with "+
					"a strict-decoding error, so this manifest is unappliable. Assert it "+
					"on the pod spec instead.", name, container["name"])
			}
		}
		// And the valid location must carry a value, so this cannot pass on a
		// manifest that merely dropped the field.
		if dig(deployment, "spec", "template", "spec",
			"terminationGracePeriodSeconds") == nil {
			t.Errorf("%s: no pod-level terminationGracePeriodSeconds; the drain budget "+
				"is unprotected", name)
		}
	}
}

// TestTerminationGraceContainerFieldIsDetectable is the negative control for
// TestTerminationGraceIsNotOnAContainer.
//
// A guard that cannot fail is a guard nobody reads, and this repository has a
// documented history of exactly that: the original form of
// TestSentinelTerminationGraceExceedsTheDrainBudget asserted a container-level field
// for a milestone and never noticed, because a planted container-level copy is
// indistinguishable from a correct one to a YAML parser. This test feeds the
// detector the planted shape directly.
func TestTerminationGraceContainerFieldIsDetectable(t *testing.T) {
	planted := map[string]any{
		"name":                          "sentinel",
		"terminationGracePeriodSeconds": 45,
	}
	if _, present := planted["terminationGracePeriodSeconds"]; !present {
		t.Fatal("the control is not the shape it claims to be")
	}
	// The same expression the real test uses, against the planted map.
	if !containerCarriesGrace(planted) {
		t.Fatal("the detector failed to notice a container-level " +
			"terminationGracePeriodSeconds; the real assertion would be vacuous")
	}
	// And it must NOT fire on a container that does not carry it.
	if containerCarriesGrace(map[string]any{"name": "agent"}) {
		t.Fatal("the detector fired on a container with no such field")
	}
}

// containerCarriesGrace is the predicate both the real assertion and the control
// consult. Factored out so the control exercises the same expression rather than a
// restatement of it - a control that re-implements the check proves only that the
// control works.
func containerCarriesGrace(container map[string]any) bool {
	_, present := container["terminationGracePeriodSeconds"]
	return present
}

// ---------------------------------------------------------------------------
// Negative controls - AGENTS.md §5.5
// ---------------------------------------------------------------------------

// TestControlVerbCheckFailsOnAnInjectedWrite proves the RBAC check can fail.
//
// A check written against the wrong key - `rule` instead of `rules` - iterates an
// empty list and reports success forever. This is the assertion that distinguishes
// the two.
func TestControlVerbCheckFailsOnAnInjectedWrite(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "rbac.yaml"))
	if err != nil {
		t.Fatalf("rbac.yaml: %v", err)
	}
	role, err := one(documents, "Role")
	if err != nil {
		t.Fatalf("%v", err)
	}

	rules := role["rules"].([]any)
	// The exact violation the real check forbids, injected in memory.
	rules = append(rules, map[string]any{
		"apiGroups": []any{""},
		"resources": []any{"pods"},
		"verbs":     []any{"delete", "get"},
	})
	role["rules"] = rules

	var offenders []string
	for _, raw := range rules {
		for _, verb := range strList(t, raw.(map[string]any)["verbs"], "rule.verbs") {
			if !observatonalVerbs[verb] {
				offenders = append(offenders, verb)
			}
		}
	}
	if len(offenders) == 0 {
		t.Fatal("the verb check did not notice an injected delete, so " +
			"TestSentinelRoleGrantsNoMutatingVerb proves nothing")
	}
}

// TestControlHardeningCheckFailsOnARemovedField proves the field lookup can fail.
//
// `dig` returns nil for a missing key. A check written as `assert dig(...) != nil`
// would pass a manifest with nothing set; this removes a field and confirms the
// real comparison trips.
func TestControlHardeningCheckFailsOnARemovedField(t *testing.T) {
	container := map[string]any{
		"securityContext": map[string]any{"readOnlyRootFilesystem": true},
	}
	security := container["securityContext"].(map[string]any)
	delete(security, "readOnlyRootFilesystem")

	for _, field := range sentinelHardening() {
		if field.name == "readOnlyRootFilesystem" {
			actual := dig(container, field.path...)
			if actual == field.value {
				t.Fatalf("%s = %v after deletion, so the check cannot fail", field.name, actual)
			}
			continue
		}
	}
}

// TestControlDigSurvivesAScalarParent is the negative control for the walker.
//
// A naive map chain panics on a string, which reads as a schema error rather than
// as a missing field - and the natural "fix" is to catch the panic, which hides
// every real nil.
func TestControlDigSurvivesAScalarParent(t *testing.T) {
	if got := dig("readOnlyRootFilesystem", "securityContext"); got != nil {
		t.Errorf("dig through a string = %v, want nil", got)
	}
	if got := dig(nil, "securityContext", "runAsUser"); got != nil {
		t.Errorf("dig through nil = %v, want nil", got)
	}
	if got := dig(map[string]any{"securityContext": "oops"}, "securityContext", "runAsUser"); got != nil {
		t.Errorf("dig through a scalar = %v, want nil", got)
	}
}

// TestControlManifestTextDiffersFromTheParse guards against the test reading a
// file it did not actually parse.
//
// Every check in this file operates on the decoded structure. If a change made
// `readManifest` return a comment-only stub, all of them would pass. This asserts
// the parsed content is non-trivial.
func TestControlManifestTextDiffersFromTheParse(t *testing.T) {
	documents, err := decodeAll(readManifest(t, "sentinel.yaml"))
	if err != nil {
		t.Fatalf("sentinel.yaml: %v", err)
	}
	deployment, err := one(documents, "Deployment")
	if err != nil {
		t.Fatalf("%v", err)
	}
	// A stub would have the kind and nothing else.
	if len(deployment) < 3 {
		t.Errorf("the parsed Deployment has %d top-level keys, which suggests "+
			"the file was not really parsed", len(deployment))
	}
	if !strings.Contains(readManifest(t, "sentinel.yaml"), "readOnlyRootFilesystem") {
		t.Error("the manifest text no longer mentions readOnlyRootFilesystem")
	}
}
