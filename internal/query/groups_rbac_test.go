package query_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/query"
)

// D90 (docs/23 C8): a group belongs to an application; who may create it, fill it and ticket it follows the
// caller's role on each application involved.
func TestFindingGroups_ScopedByApplication(t *testing.T) {
	ctx := context.Background()
	st := newMockGroupViewStore()
	tenantID := uuid.New()
	authn := auth.NewAuthenticatorWithStore(st)
	admin := authn.DefaultAdminToken(tenantID)
	api := query.NewAPIWithAuth(st, nil, authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	appA, appB := uuid.New(), uuid.New()
	_ = st.CreateApplication(ctx, &domain.Application{ID: appA, TenantID: tenantID, Name: "payments", Slug: "payments"})
	_ = st.CreateApplication(ctx, &domain.Application{ID: appB, TenantID: tenantID, Name: "search", Slug: "search"})
	fA1, fA2, fB := uuid.New(), uuid.New(), uuid.New()
	_ = st.UpsertFindings(ctx, tenantID, []*domain.Finding{
		{ID: fA1, TenantID: tenantID, FindingKey: "a1", ApplicationID: appA, Title: "a1", Severity: domain.SeverityHigh, State: domain.StateOpen},
		{ID: fA2, TenantID: tenantID, FindingKey: "a2", ApplicationID: appA, Title: "a2", Severity: domain.SeverityCritical, State: domain.StateOpen},
		{ID: fB, TenantID: tenantID, FindingKey: "b", ApplicationID: appB, Title: "b", Severity: domain.SeverityLow, State: domain.StateOpen},
	})

	// A tenant viewer who is maintainer on payments only.
	raw, rec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "pay-maint", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, rec)
	_ = st.UpsertAccessBinding(ctx, tenantID, &domain.AccessBinding{ID: uuid.New(), Subject: "pay-maint", Role: "maintainer", ApplicationID: appA})
	// A tenant viewer who is triager on payments only.
	triRaw, triRec, _ := auth.GenerateToken(tenantID, auth.RoleViewer, "pay-tri", []string{"*"}, time.Hour)
	_ = st.SaveToken(ctx, triRec)
	_ = st.UpsertAccessBinding(ctx, tenantID, &domain.AccessBinding{ID: uuid.New(), Subject: "pay-tri", Role: "triager", ApplicationID: appA})

	do := func(token, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		return w
	}
	create := func(token, body string) (int, domain.FindingGroup) {
		w := do(token, "POST", "/api/v1/groups", body)
		var g domain.FindingGroup
		_ = json.Unmarshal(w.Body.Bytes(), &g)
		return w.Code, g
	}

	if code, _ := create(raw, `{"name":"tenant-wide"}`); code != http.StatusForbidden {
		t.Fatalf("a tenant-wide group needs admin: %d", code)
	}
	if code, _ := create(raw, `{"name":"search","application_id":"`+appB.String()+`"}`); code != http.StatusForbidden {
		t.Fatalf("a group on an application where the caller is a viewer: %d", code)
	}
	if code, _ := create(triRaw, `{"name":"x","application_id":"`+appA.String()+`"}`); code != http.StatusForbidden {
		t.Fatalf("a triager may not create a group: %d", code)
	}
	if code, _ := create(raw, `{"name":"ghost","application_id":"`+uuid.NewString()+`"}`); code != http.StatusForbidden && code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown application is refused: %d", code)
	}
	code, grp := create(raw, `{"name":"payments sprint","application_id":"`+appA.String()+`"}`)
	if code != http.StatusCreated || grp.ApplicationID == nil || *grp.ApplicationID != appA {
		t.Fatalf("maintainer on payments creates a payments group: %d %+v", code, grp)
	}
	members := "/api/v1/groups/" + grp.ID.String() + "/members"

	if w := do(triRaw, "POST", members, `{"finding_ids":["`+fB.String()+`"]}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a finding of another application does not join an application's group: %d", w.Code)
	}
	if w := do(triRaw, "POST", members, `{"finding_ids":["`+uuid.NewString()+`"]}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unknown finding is refused: %d", w.Code)
	}
	if w := do(triRaw, "POST", members, `{"finding_ids":["`+fA1.String()+`","`+fA2.String()+`"]}`); w.Code != http.StatusNoContent {
		t.Fatalf("a triager on payments adds payments findings: %d %s", w.Code, w.Body.String())
	}

	ticket := "/api/v1/groups/" + grp.ID.String() + "/ticket"
	if w := do(triRaw, "POST", ticket, ``); w.Code != http.StatusForbidden {
		t.Fatalf("a triager may not open the group's ticket: %d", w.Code)
	}
	if w := do(raw, "POST", ticket, ``); w.Code != http.StatusAccepted {
		t.Fatalf("maintainer reserves the ticket: %d %s", w.Code, w.Body.String())
	}
	if w := do(raw, "POST", ticket, ``); w.Code != http.StatusConflict {
		t.Fatalf("a second request while one is reserved: %d", w.Code)
	}

	// A tenant-wide group (admin) holding both applications: the payments maintainer may not ticket it.
	_, wide := create(admin, `{"name":"log4j everywhere"}`)
	if w := do(admin, "POST", "/api/v1/groups/"+wide.ID.String()+"/members", `{"finding_ids":["`+fA1.String()+`","`+fB.String()+`"]}`); w.Code != http.StatusNoContent {
		t.Fatalf("admin fills a tenant-wide group: %d", w.Code)
	}
	if w := do(raw, "POST", "/api/v1/groups/"+wide.ID.String()+"/ticket", ``); w.Code != http.StatusForbidden {
		t.Fatalf("maintainer on one of the two applications: %d", w.Code)
	}
	if w := do(raw, "DELETE", "/api/v1/groups/"+wide.ID.String(), ``); w.Code != http.StatusForbidden {
		t.Fatalf("only an admin deletes a tenant-wide group: %d", w.Code)
	}
	empty := func() string { _, g := create(admin, `{"name":"empty"}`); return g.ID.String() }()
	if w := do(admin, "POST", "/api/v1/groups/"+empty+"/ticket", ``); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an empty group has nothing to ticket: %d", w.Code)
	}
}
