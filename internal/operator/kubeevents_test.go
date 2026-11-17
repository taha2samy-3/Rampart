package operator

import (
	"context"
	"log/slog"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestEventEmitter_RecordsAnEventInTheNamespace(t *testing.T) {
	c := fake.NewSimpleClientset()
	e := NewEventEmitterFor(c, "rampart", slog.Default())
	e.Emit(context.Background(), "Warning", "FeedSyncFailed", "NVD: failed: 429")
	list, err := c.CoreV1().Events("rampart").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(list.Items) != 1 {
		t.Fatalf("events: %v %v", list, err)
	}
	ev := list.Items[0]
	if ev.InvolvedObject.Namespace != ev.Namespace || ev.InvolvedObject.Kind != "Pod" { // the API server refuses an Event whose object is in another namespace
		t.Fatalf("the involved object lives in the Event's namespace: %+v", ev)
	}
	if ev.Type != "Warning" || ev.Reason != "FeedSyncFailed" || ev.Message != "NVD: failed: 429" {
		t.Fatalf("event: %+v", ev)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 4); len([]rune(got)) != 4 {
		t.Fatalf("truncate: %q", got)
	}
}
