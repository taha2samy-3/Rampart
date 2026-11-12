package store_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/workflow"
)

type notificationList struct {
	Items  []domain.Notification `json:"items"`
	Unread int                   `json:"unread"`
}

func TestNotifications_DeadlinesAndExpiry(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	ingestRules(t, h, map[string]string{"rule.a": "9.5", "rule.b": "7.5"}, "main")
	ids := findingIDs(t, h)
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	omar := h.tokenFor(auth.RoleViewer, "omar@acme.example")
	list := func(token string) notificationList {
		code, out := getJSON[notificationList](t, h, token, "/api/v1/notifications")
		if code != http.StatusOK {
			t.Fatalf("list notifications: %d", code)
		}
		return out
	}
	if l := list(sara); len(l.Items) != 0 || l.Unread != 0 {
		t.Fatalf("a new tenant has no notifications: %+v", l)
	}
	if code, _ := h.callAs("", "GET", "/api/v1/notifications", nil, nil); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}

	// Finding a is due in 10 hours, b in 40 hours: only a is announced, and only once.
	setDue := func(rule string, d time.Duration) {
		f := h.finding(ids[rule])
		due := time.Now().UTC().Add(d)
		f.SLADue = &due
		if err := h.store.UpdateFindingRisk(ctx, h.tenant, []*domain.Finding{f}); err != nil {
			t.Fatal(err)
		}
	}
	setDue("rule.a", 10*time.Hour)
	setDue("rule.b", 40*time.Hour)
	now := time.Now().UTC()
	if n, err := h.scorer.WarnDueSoon(ctx, h.tenant, now); err != nil || n != 1 {
		t.Fatalf("due soon: %d %v", n, err)
	}
	if n, _ := h.scorer.WarnDueSoon(ctx, h.tenant, now); n != 0 {
		t.Fatalf("a finding is announced once, got %d the second time", n)
	}
	l := list(sara)
	if len(l.Items) != 1 || l.Unread != 1 || l.Items[0].Kind != domain.NotifySLADueSoon || !l.Items[0].Unread {
		t.Fatalf("after the warning: %+v", l)
	}
	// The link the message carries must find the finding it is about.
	link := l.Items[0].Link
	code, found := getJSON[struct {
		Items []struct {
			Finding struct {
				RuleID string `json:"rule_id"`
			}
		}
	}](t, h, sara, "/api/v1/findings?"+strings.TrimPrefix(strings.Replace(link, "/findings?", "", 1), "?"))
	if code != http.StatusOK || len(found.Items) != 1 || found.Items[0].Finding.RuleID != "rule.a" {
		t.Fatalf("the link %q finds %d %+v", link, code, found)
	}

	// Reading is per user.
	if code, _ := h.callAs(sara, "POST", "/api/v1/notifications/read", nil, nil); code != http.StatusNoContent {
		t.Fatalf("mark read: %d", code)
	}
	if l := list(sara); l.Unread != 0 || l.Items[0].Unread {
		t.Fatalf("after reading: %+v", l)
	}
	if l := list(omar); l.Unread != 1 {
		t.Fatalf("another user still has it unread: %+v", l)
	}

	// A breach is announced once as well; a restarted deadline is announced again.
	setDue("rule.a", -time.Hour)
	if n, err := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC()); err != nil || n != 1 {
		t.Fatalf("breach: %d %v", n, err)
	}
	if l := list(sara); l.Unread != 1 || l.Items[0].Kind != domain.NotifySLABreached {
		t.Fatalf("after the breach: %+v", l)
	}
	if n, _ := h.scorer.MarkBreaches(ctx, h.tenant, time.Now().UTC()); n != 0 || list(sara).Unread != 1 {
		t.Fatalf("a breach must not be announced twice")
	}

	// A risk acceptance: announced 14 days before, again 1 day before, and when it ends.
	svc := workflow.New(h.store)
	out, err := svc.Request(ctx, h.tenant, "user:boss@acme.example", domain.RiskAcceptanceRequest{
		FindingIDs: []uuid.UUID{ids["rule.b"]}, Justification: "behind the VPN", ExpiresAt: now.Add(10 * 24 * time.Hour),
	})
	if err != nil || out.Acceptance.Status != domain.AcceptanceApproved {
		t.Fatalf("request: %+v %v", out, err)
	}
	if n, err := h.scorer.WarnExpiringAcceptances(ctx, h.tenant, now); err != nil || n != 1 {
		t.Fatalf("14 days: %d %v", n, err)
	}
	if n, _ := h.scorer.WarnExpiringAcceptances(ctx, h.tenant, now.Add(time.Hour)); n != 0 {
		t.Fatalf("14 days is announced once, got %d", n)
	}
	if n, _ := h.scorer.WarnExpiringAcceptances(ctx, h.tenant, now.Add(9*24*time.Hour+time.Hour)); n != 1 {
		t.Fatalf("1 day: want one more announcement, got %d", n)
	}
	if n, _ := h.scorer.WarnExpiringAcceptances(ctx, h.tenant, now.Add(9*24*time.Hour+2*time.Hour)); n != 0 {
		t.Fatalf("1 day is announced once, got %d", n)
	}
	if n, err := svc.ExpireDue(ctx, h.tenant, now.Add(11*24*time.Hour)); err != nil || n != 1 {
		t.Fatalf("expiry: %d %v", n, err)
	}
	kinds := map[string]int{}
	for _, it := range list(sara).Items {
		kinds[it.Kind]++
	}
	if kinds[domain.NotifyAcceptanceEnding] != 2 || kinds[domain.NotifyAcceptanceEnded] != 1 || kinds[domain.NotifySLABreached] != 1 || kinds[domain.NotifySLADueSoon] != 1 {
		t.Fatalf("kinds: %v", kinds)
	}
}
