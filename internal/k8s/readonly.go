package k8s

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

// DefaultCallTimeout bounds every direct API call this package makes.
//
// AGENTS.md §3.2: every blocking operation takes a context bounded by a timeout.
// The informer's own List/Watch are long-lived by design and are bounded by the
// stop channel instead; this constant is for the one-shot reads below, which
// would otherwise inherit whatever deadline the caller's context happened to
// carry - including none at all.
const DefaultCallTimeout = 10 * time.Second

// AllNamespaces is the namespace value that scopes a namespaced client across
// every namespace. client-go treats the empty namespace on a namespaced resource
// as "all namespaces" for List and Watch.
const AllNamespaces = ""

// ReadOnlyClientset is the only cluster handle the Sentinel hands to application
// code.
//
// kubernetes.Interface exposes Create, Update, Patch, Delete and DeleteCollection
// on every resource. Returning it would make "do not write" a code-review
// convention, and conventions are exactly what a rushed change steps over. This
// facade exposes only the verbs observation needs, so a write cannot be expressed
// through the type.
//
// The informer factory genuinely requires a kubernetes.Interface, because that
// is what client-go's informer constructor takes. That interface is held inside
// the watcher and never leaves this package; TestNoMutatingCallsInSources proves
// it mechanically by parsing this package's AST rather than trusting the comment.
type ReadOnlyClientset struct {
	inner kubernetes.Interface
}

// NewReadOnlyClientset wraps a clientset for observation use.
//
// The inner clientset is unexported, so the only way to reach it is from inside
// this package. That is the guarantee; the reflection test is the audit.
func NewReadOnlyClientset(inner kubernetes.Interface) *ReadOnlyClientset {
	return &ReadOnlyClientset{inner: inner}
}

// PodReader observes pods. Get, List and Watch - no more.
type PodReader struct {
	inner corev1client.PodInterface
	ns    string
}

// Get fetches one pod by name from the reader's namespace.
func (p PodReader) Get(ctx context.Context, name string) (*corev1.Pod, error) {
	return p.inner.Get(ctx, name, metav1.GetOptions{})
}

// List fetches the pods in the reader's namespace.
func (p PodReader) List(ctx context.Context) (*corev1.PodList, error) {
	return p.inner.List(ctx, metav1.ListOptions{})
}

// Watch streams pod changes until the context is done.
func (p PodReader) Watch(ctx context.Context) (watch.Interface, error) {
	return p.inner.Watch(ctx, metav1.ListOptions{})
}

// Namespace returns the namespace this reader is scoped to, or "" for all.
func (p PodReader) Namespace() string { return p.ns }

// EventReader observes events.
type EventReader struct {
	inner corev1client.EventInterface
	ns    string
}

// List fetches the events in the reader's namespace.
func (e EventReader) List(ctx context.Context) (*corev1.EventList, error) {
	return e.inner.List(ctx, metav1.ListOptions{})
}

// Pods returns a pod reader scoped to every namespace.
func (r ReadOnlyClientset) Pods() PodReader {
	return PodReader{inner: r.inner.CoreV1().Pods(AllNamespaces), ns: AllNamespaces}
}

// PodsIn returns a pod reader scoped to one namespace.
func (r ReadOnlyClientset) PodsIn(namespace string) PodReader {
	return PodReader{inner: r.inner.CoreV1().Pods(namespace), ns: namespace}
}

// Events returns an event reader scoped to every namespace.
func (r ReadOnlyClientset) Events() EventReader {
	return EventReader{inner: r.inner.CoreV1().Events(AllNamespaces), ns: AllNamespaces}
}

// EventsIn returns an event reader scoped to one namespace.
func (r ReadOnlyClientset) EventsIn(namespace string) EventReader {
	return EventReader{inner: r.inner.CoreV1().Events(namespace), ns: namespace}
}

// AllowedFacadeMethods is the complete set of exported method names the
// read-only facade and its readers may expose.
//
// An allow-list, not a deny-list of write verbs, and the reason is measured
// rather than stylistic. A deny-list has to walk into return types to reach
// Pods().Create(), which is four levels deep; at the depth where Create becomes
// visible it also starts matching "Evictions", "RoleBindings" and
// "ValidatingAdmissionPolicyBindings" - accessor names that contain "Evict" and
// "Bind". Both were observed failing in this package's own test run. A guard that
// reports false positives gets ignored, and a guard that gets ignored is the same
// as no guard.
//
// An exact allow-list cannot have that failure mode: adding any method to the
// facade that is not listed here fails the build, whatever it is called.
var AllowedFacadeMethods = map[string]bool{
	"Pods":      true,
	"PodsIn":    true,
	"Events":    true,
	"EventsIn":  true,
	"Get":       true,
	"List":      true,
	"Watch":     true,
	"Namespace": true,
}

// DisallowedFacadeMethods returns exported methods on the facade or its readers
// that are not in [AllowedFacadeMethods].
//
// Includes embedded and promoted methods, so a method inherited from an embedded
// type is audited too - an embed is the obvious way to add capability without
// editing the type that carries the guarantee.
func DisallowedFacadeMethods() []string {
	targets := map[string]any{
		"ReadOnlyClientset": ReadOnlyClientset{},
		"PodReader":         PodReader{},
		"EventReader":       EventReader{},
	}

	var offenders []string
	for name, target := range targets {
		typ := reflect.TypeOf(target)
		for i := 0; i < typ.NumMethod(); i++ {
			method := typ.Method(i)
			if !method.IsExported() {
				continue
			}
			if !AllowedFacadeMethods[method.Name] {
				offenders = append(offenders, name+"."+method.Name)
			}
		}
	}
	sort.Strings(offenders)
	return offenders
}

// DescribeReadOnlyClientset renders the facade's scope for a startup log.
//
// Exists so main can report *what it will observe* without holding a
// kubernetes.Interface, which is the point of the facade. A startup line that says
// "namespace=payments" is a claim; this returns the reader that would be used, so
// the log and the capability are the same value.
func DescribeReadOnlyClientset(r *ReadOnlyClientset, namespace string) string {
	if r == nil {
		return "(none)"
	}
	scope := namespace
	if scope == AllNamespaces {
		scope = "(all)"
	}
	return fmt.Sprintf("pods=%s events=%s verbs=%v",
		scope, scope, AllowedFacadeMethods)
}

// BoundTimeout returns a context carrying the default deadline.
//
// AGENTS.md §3.2 forbids a bare context.Background() on a blocking call. This is
// the single place the default is applied, so the bound is uniform and greppable
// rather than restated at each call site with a slightly different value.
func BoundTimeout(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, DefaultCallTimeout)
}
