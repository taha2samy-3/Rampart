package scoring

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/domain"
	"rampart/internal/store"
)

func factor(t *testing.T, f *domain.Finding, app *domain.Application, name string) int {
	t.Helper()
	b, _ := Breakdown(f, app, nil, nil)
	for _, x := range b.Factors {
		if x.Name == name {
			return x.Points
		}
	}
	return 0
}

// The application's context reaches the score (D55): sensitive data adds, a WAF subtracts only from a finding a
// dynamic scan made.
func TestBreakdown_ApplicationContext(t *testing.T) {
	app := &domain.Application{BusinessCriticality: "critical", DataClassification: []string{"pii"}, CompensatingControls: []string{"waf"}}
	dast := &domain.Finding{Severity: domain.SeverityHigh, Category: domain.CategoryDAST}
	sast := &domain.Finding{Severity: domain.SeverityHigh, Category: domain.CategorySAST}
	if p := factor(t, dast, app, "COMPENSATING_CONTROL"); p != -80 {
		t.Fatalf("a WAF on a DAST finding: %d", p)
	}
	if p := factor(t, sast, app, "COMPENSATING_CONTROL"); p != 0 {
		t.Fatalf("a WAF must not lower a SAST finding: %d", p)
	}
	withData, _ := Breakdown(sast, app, nil, nil)
	without, _ := Breakdown(sast, &domain.Application{BusinessCriticality: "critical"}, nil, nil)
	if withData.TotalScore-without.TotalScore != 80 {
		t.Fatalf("sensitive data should add 80: %d vs %d", withData.TotalScore, without.TotalScore)
	}
}

type mockNotifStore struct {
	store.Store
	created  []domain.Notification
	dueSoon  []domain.DueSoon
	expiring []domain.ExpiringAcceptance
}

func (m *mockNotifStore) CreateNotification(_ context.Context, _ uuid.UUID, n *domain.Notification) error {
	m.created = append(m.created, *n)
	return nil
}
func (m *mockNotifStore) ListNotifications(_ context.Context, _ uuid.UUID, _ string, _ int) ([]domain.Notification, int, error) {
	return m.created, len(m.created), nil
}
func (m *mockNotifStore) MarkNotificationsRead(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
	return nil
}
func (m *mockNotifStore) WarnSLADueSoon(_ context.Context, _ uuid.UUID, _ time.Time, _ time.Duration) ([]domain.DueSoon, error) {
	return m.dueSoon, nil
}
func (m *mockNotifStore) WarnExpiringAcceptances(_ context.Context, _ uuid.UUID, _ time.Time) ([]domain.ExpiringAcceptance, error) {
	return m.expiring, nil
}

type mockRouter struct {
	routed []*domain.Notification
}

func (m *mockRouter) RouteInAppNotification(_ context.Context, _ uuid.UUID, n *domain.Notification) []error {
	m.routed = append(m.routed, n)
	return nil
}

func TestScorer_InAppNotificationRouting(t *testing.T) {
	ctx := context.Background()
	tenantID := domain.NewID()
	now := time.Now().UTC()

	st := &mockNotifStore{
		dueSoon: []domain.DueSoon{
			{ID: domain.NewID(), Title: "Critical SQL Injection", Band: "critical", Due: now.Add(12 * time.Hour)},
		},
		expiring: []domain.ExpiringAcceptance{
			{ID: domain.NewID(), Justification: "Legacy system upgrade", Owner: "user:alice", DaysLeft: 14, Findings: 3},
		},
	}
	r := &mockRouter{}
	scorer := New(nil, nil, nil)
	scorer.store = st
	scorer.SetNotificationRouter(r)

	// 1. notifyBreaches
	scorer.notifyBreaches(ctx, tenantID, 2, now)
	if len(r.routed) != 1 || r.routed[0].Kind != domain.NotifySLABreached {
		t.Fatalf("expected 1 sla_breached notification routed, got %+v", r.routed)
	}

	// 2. WarnDueSoon
	n, err := scorer.WarnDueSoon(ctx, tenantID, now)
	if err != nil || n != 1 {
		t.Fatalf("WarnDueSoon returned n=%d, err=%v", n, err)
	}
	if len(r.routed) != 2 || r.routed[1].Kind != domain.NotifySLADueSoon {
		t.Fatalf("expected sla_due_soon notification routed, got %+v", r.routed)
	}

	// 3. WarnExpiringAcceptances
	nExp, err := scorer.WarnExpiringAcceptances(ctx, tenantID, now)
	if err != nil || nExp != 1 {
		t.Fatalf("WarnExpiringAcceptances returned n=%d, err=%v", nExp, err)
	}
	if len(r.routed) != 3 || r.routed[2].Kind != domain.NotifyAcceptanceEnding {
		t.Fatalf("expected acceptance_expiring notification routed, got %+v", r.routed)
	}
}
