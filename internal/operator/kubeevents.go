package operator

import (
	"context"
	"log/slog"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// EventEmitter writes Kubernetes Events for things Rampart does on its own, such as a feed sync, next to the
// notification the tenants get, so `kubectl get events -n <namespace>` tells the same story. It needs the
// `events: create` the chart's ClusterRole already grants. A failure to write an Event is logged, never returned:
// an Event is a report, not part of the work.
type EventEmitter struct {
	client    kubernetes.Interface
	namespace string
	object    string // the pod the Event is about
	log       *slog.Logger
}

// NewEventEmitter builds an emitter for the cluster the operator runs in.
func NewEventEmitter(rc *rest.Config, namespace string, log *slog.Logger) (*EventEmitter, error) {
	c, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, err
	}
	return NewEventEmitterFor(c, namespace, log), nil
}

// NewEventEmitterFor is NewEventEmitter with a client given (tests).
func NewEventEmitterFor(c kubernetes.Interface, namespace string, log *slog.Logger) *EventEmitter {
	if namespace == "" {
		namespace = "default"
	}
	obj := os.Getenv("POD_NAME")
	if obj == "" {
		obj, _ = os.Hostname() // a pod's hostname is its name
	}
	if obj == "" {
		obj = "rampart"
	}
	return &EventEmitter{client: c, namespace: namespace, object: obj, log: log}
}

// Emit records an Event in the namespace. A core/v1 Event is refused unless its involved object is in the same
// namespace (a cluster-scoped object, such as ClusterFeed, only lets it live in "default"), so the Event is about this
// pod, which is what runs the sync: `kubectl get events -n <namespace>` and `kubectl describe pod` show it. eventType
// is Normal or Warning.
func (e *EventEmitter) Emit(ctx context.Context, eventType, reason, message string) {
	now := metav1.NewTime(time.Now())
	ev := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "rampart-", Namespace: e.namespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1", Kind: "Pod", Namespace: e.namespace, Name: e.object,
		},
		Type: eventType, Reason: reason, Message: truncate(message, 1000),
		FirstTimestamp: now, LastTimestamp: now, Count: 1,
		Source: corev1.EventSource{Component: "rampart"}, ReportingController: "rampart.aspm.dev/rampart", ReportingInstance: "rampart",
		Action: "Sync",
	}
	if _, err := e.client.CoreV1().Events(e.namespace).Create(ctx, ev, metav1.CreateOptions{}); err != nil {
		e.log.Warn("could not record a Kubernetes Event", "reason", reason, "err", err)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
