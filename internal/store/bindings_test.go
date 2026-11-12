package store_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"rampart/internal/auth"
	"rampart/internal/domain"
	"rampart/internal/enrich"
	"rampart/internal/query"
)

func TestAccessBindings_RoleOnOneApplication(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	seedFindings(t, ctx, h.store, h.tenant, 0)
	shop, _ := h.store.LookupApplication(ctx, h.tenant, "shop")
	shopAsset, _ := h.store.LookupAsset(ctx, h.tenant, domain.AssetRepository, "github.com/acme/shop")
	now := time.Now().UTC()
	billing := &domain.Application{ID: uuid.New(), TenantID: h.tenant, Slug: "billing", Name: "Billing", BusinessCriticality: "high", Lifecycle: "production", CreatedAt: now}
	if err := h.store.CreateApplication(ctx, billing); err != nil {
		t.Fatal(err)
	}
	billAsset := &domain.Asset{ID: uuid.New(), TenantID: h.tenant, ApplicationID: &billing.ID, Type: domain.AssetRepository, Key: "github.com/acme/billing", DisplayName: "billing", Active: true, FirstSeen: now, LastSeen: now}
	if err := h.store.CreateAsset(ctx, billAsset); err != nil {
		t.Fatal(err)
	}
	mk := func(i int, app *domain.Application, asset *domain.Asset) *domain.Finding {
		return &domain.Finding{ID: uuid.New(), TenantID: h.tenant, FindingKey: fmt.Sprintf("bind-%d", i), DedupScope: app.Slug + ":main", AssetID: asset.ID, ApplicationID: app.ID,
			Track: "main", RuleScannerFamily: "semgrep", RuleID: fmt.Sprintf("rule.%d", i), Title: fmt.Sprintf("Finding %d", i), Category: domain.CategorySAST,
			Severity: domain.SeverityHigh, ToolSeverity: "high", State: domain.StateOpen, FirstSeen: now, LastSeen: now, OccurrenceCount: 1, Version: 1, CreatedAt: now, UpdatedAt: now}
	}
	s1, s2, s3, b1 := mk(1, shop, shopAsset), mk(2, shop, shopAsset), mk(3, shop, shopAsset), mk(4, billing, billAsset)
	if err := h.store.UpsertFindings(ctx, h.tenant, []*domain.Finding{s1, s2, s3, b1}); err != nil {
		t.Fatal(err)
	}

	authn := auth.NewAuthenticatorWithStore(h.store)
	api := query.NewAPIWithAuth(h.store, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(api.Audited(mux))
	defer srv.Close()
	ann := h.tokenFor(auth.RoleViewer, "Ann@acme.example") // a viewer of the tenant
	bob := h.tokenFor(auth.RoleViewer, "bob@acme.example")
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	do := func(token, method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	triage := func(token string, f *domain.Finding, state string) int {
		code, _ := do(token, "PATCH", "/api/v1/findings/"+f.ID.String(), `{"state":"`+state+`"}`)
		return code
	}
	bind := func(token, subject, role string, app uuid.UUID) (int, []byte) {
		return do(token, "POST", "/api/v1/access-bindings", fmt.Sprintf(`{"subject":%q,"role":%q,"applicationId":%q}`, subject, role, app))
	}

	// A viewer decides nothing, anywhere.
	if c := triage(ann, s1, "under_investigation"); c != http.StatusForbidden {
		t.Fatalf("viewer: %d", c)
	}
	// A binding makes her a triager of the shop, and only of the shop. The subject is matched without case.
	if code, body := bind(boss, "ann@acme.example", "triager", shop.ID); code != http.StatusCreated {
		t.Fatalf("bind: %d %s", code, body)
	}
	if c := triage(ann, s1, "under_investigation"); c != http.StatusOK {
		t.Fatalf("triager on the shop: %d", c)
	}
	if c := triage(ann, b1, "under_investigation"); c != http.StatusForbidden {
		t.Fatalf("the same person on billing: %d", c)
	}
	// Bulk: the shop finding goes through, the billing one is refused by name, the rest still happens.
	code, body := do(ann, "POST", "/api/v1/findings/bulk", fmt.Sprintf(`{"ids":[%q,%q],"patch":{"state":"under_investigation","note":"x"}}`, s2.ID, b1.ID))
	var bulk query.BulkResponse
	_ = json.Unmarshal(body, &bulk)
	if code != http.StatusOK || bulk.Updated != 1 || len(bulk.Failed) != 1 || bulk.Failed[0].ID != b1.ID.String() || !strings.Contains(bulk.Failed[0].Error, "role") {
		t.Fatalf("bulk: %d %+v", code, bulk)
	}
	if h.finding(b1.ID).State != domain.StateOpen {
		t.Fatal("billing was changed")
	}
	// A triager does not manage access; an owner does, of her application only, and never gives admin.
	if code, _ := bind(ann, "bob@acme.example", "viewer", shop.ID); code != http.StatusForbidden {
		t.Fatalf("a triager gave access: %d", code)
	}
	if code, _ := bind(boss, "ann@acme.example", "owner", shop.ID); code != http.StatusCreated { // replaces her role: one row per person and application
		t.Fatal("upgrade")
	}
	_, lb := do(boss, "GET", "/api/v1/access-bindings?application="+shop.ID.String(), "")
	if strings.Count(string(lb), `"subject"`) != 1 {
		t.Fatalf("one binding per person and application: %s", lb)
	}
	if code, _ := bind(ann, "bob@acme.example", "triager", shop.ID); code != http.StatusCreated {
		t.Fatalf("an owner giving triager on her application: %d", code)
	}
	if code, _ := bind(ann, "bob@acme.example", "triager", billing.ID); code != http.StatusForbidden {
		t.Fatalf("an owner of the shop giving access to billing: %d", code)
	}
	if code, _ := bind(ann, "bob@acme.example", "admin", shop.ID); code != http.StatusBadRequest {
		t.Fatalf("admin is not scoped: %d", code)
	}
	if code, _ := bind(boss, "bob@acme.example", "triager", uuid.New()); code != http.StatusNotFound {
		t.Fatalf("an application that is not there: %d", code)
	}
	if code, _ := bind(boss, "bad subject", "viewer", shop.ID); code != http.StatusBadRequest {
		t.Fatalf("a subject with a space: %d", code)
	}
	if code, _ := bind(boss, "carl@acme.example", "viewer", billing.ID); code != http.StatusCreated {
		t.Fatal("billing binding")
	}
	// What she cannot manage she cannot see.
	_, annList := do(ann, "GET", "/api/v1/access-bindings", "")
	if strings.Contains(string(annList), "carl@acme.example") || !strings.Contains(string(annList), "bob@acme.example") {
		t.Fatalf("an owner lists the bindings of her applications only: %s", annList)
	}
	var bobBinding struct {
		Items []struct{ ID, Subject string }
	}
	_ = json.Unmarshal(annList, &bobBinding)
	var carlID string
	_, all := do(boss, "GET", "/api/v1/access-bindings", "")
	var allL struct {
		Items []struct{ ID, Subject string }
	}
	_ = json.Unmarshal(all, &allL)
	for _, it := range allL.Items {
		if it.Subject == "carl@acme.example" {
			carlID = it.ID
		}
	}
	if code, _ := do(ann, "DELETE", "/api/v1/access-bindings/"+carlID, ""); code != http.StatusNotFound {
		t.Fatalf("deleting a binding she cannot see: %d", code)
	}
	if code, _ := do(bob, "GET", "/api/v1/access-bindings", ""); code != http.StatusForbidden {
		t.Fatalf("a triager listing bindings: %d", code)
	}

	// Risk acceptance: a triager of the shop asks for it there and not on billing; approving needs a maintainer.
	if code, _ := do(boss, "PATCH", "/api/v1/settings", `{"riskAcceptanceApproval":true}`); code != http.StatusOK {
		t.Fatalf("settings: %d", code)
	}
	ask := func(token string, f *domain.Finding) (int, []byte) {
		return do(token, "POST", "/api/v1/risk-acceptances", fmt.Sprintf(`{"findingIds":[%q],"justification":"behind the VPN","expiresAt":%q}`, f.ID, now.Add(30*24*time.Hour).Format(time.RFC3339)))
	}
	if code, _ := ask(bob, b1); code != http.StatusForbidden {
		t.Fatalf("a triager of the shop asking about billing: %d", code)
	}
	code, req := ask(bob, s3)
	if code != http.StatusCreated {
		t.Fatalf("asking on the shop: %d %s", code, req)
	}
	var o struct{ Acceptance struct{ ID string } }
	_ = json.Unmarshal(req, &o)
	if code, _ := do(bob, "POST", "/api/v1/risk-acceptances/"+o.Acceptance.ID+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("a triager approving: %d", code)
	}
	if code, b := do(ann, "POST", "/api/v1/risk-acceptances/"+o.Acceptance.ID+"/approve", `{}`); code != http.StatusOK {
		t.Fatalf("an owner of the shop approving: %d %s", code, b)
	}
	if h.finding(s3.ID).State != domain.StateRiskAccepted {
		t.Fatalf("s3: %s", h.finding(s3.ID).State)
	}

	// The UI asks what the caller may do where.
	_, me := do(ann, "GET", "/api/v1/me/access", "")
	if !strings.Contains(string(me), shop.ID.String()) || !strings.Contains(string(me), `"owner"`) || !strings.Contains(string(me), `"role":"viewer"`) {
		t.Fatalf("me/access: %s", me)
	}

	// Taking the binding away takes the right away, at once.
	_, annL := do(boss, "GET", "/api/v1/access-bindings?application="+shop.ID.String(), "")
	var sl struct {
		Items []struct{ ID, Subject string }
	}
	_ = json.Unmarshal(annL, &sl)
	for _, it := range sl.Items {
		if strings.EqualFold(it.Subject, "ann@acme.example") {
			if code, _ := do(boss, "DELETE", "/api/v1/access-bindings/"+it.ID, ""); code != http.StatusNoContent {
				t.Fatalf("delete: %d", code)
			}
		}
	}
	if c := triage(ann, s1, "affected"); c != http.StatusForbidden {
		t.Fatalf("after the binding is gone: %d", c)
	}
	// Every change of access is in the audit log.
	_, au := do(boss, "GET", "/api/v1/audit?action=POST%20/api/v1/access-bindings", "")
	if !strings.Contains(string(au), "access-bindings") {
		t.Fatalf("audit: %s", au)
	}
}

func TestAccessBindings_HierarchyAndTenantScopes(t *testing.T) {
	h := newUploadHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Create applications under different hierarchy subtrees
	checkout := &domain.Application{
		ID:                  uuid.New(),
		TenantID:            h.tenant,
		Slug:                "checkout",
		Name:                "Checkout",
		HierarchyPath:       "fintech.payments.checkout",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		CreatedAt:           now,
	}
	if err := h.store.CreateApplication(ctx, checkout); err != nil {
		t.Fatal(err)
	}
	chkAsset := &domain.Asset{
		ID:            uuid.New(),
		TenantID:      h.tenant,
		ApplicationID: &checkout.ID,
		Type:          domain.AssetRepository,
		Key:           "github.com/acme/checkout",
		DisplayName:   "checkout",
		Active:        true,
		FirstSeen:     now,
		LastSeen:      now,
	}
	if err := h.store.CreateAsset(ctx, chkAsset); err != nil {
		t.Fatal(err)
	}

	wallet := &domain.Application{
		ID:                  uuid.New(),
		TenantID:            h.tenant,
		Slug:                "wallet",
		Name:                "Wallet",
		HierarchyPath:       "fintech.payments.wallet",
		BusinessCriticality: "high",
		Lifecycle:           "production",
		CreatedAt:           now,
	}
	if err := h.store.CreateApplication(ctx, wallet); err != nil {
		t.Fatal(err)
	}
	walAsset := &domain.Asset{
		ID:            uuid.New(),
		TenantID:      h.tenant,
		ApplicationID: &wallet.ID,
		Type:          domain.AssetRepository,
		Key:           "github.com/acme/wallet",
		DisplayName:   "wallet",
		Active:        true,
		FirstSeen:     now,
		LastSeen:      now,
	}
	if err := h.store.CreateAsset(ctx, walAsset); err != nil {
		t.Fatal(err)
	}

	logistics := &domain.Application{
		ID:                  uuid.New(),
		TenantID:            h.tenant,
		Slug:                "logistics",
		Name:                "Logistics",
		HierarchyPath:       "ops.logistics",
		BusinessCriticality: "medium",
		Lifecycle:           "production",
		CreatedAt:           now,
	}
	if err := h.store.CreateApplication(ctx, logistics); err != nil {
		t.Fatal(err)
	}
	logAsset := &domain.Asset{
		ID:            uuid.New(),
		TenantID:      h.tenant,
		ApplicationID: &logistics.ID,
		Type:          domain.AssetRepository,
		Key:           "github.com/acme/logistics",
		DisplayName:   "logistics",
		Active:        true,
		FirstSeen:     now,
		LastSeen:      now,
	}
	if err := h.store.CreateAsset(ctx, logAsset); err != nil {
		t.Fatal(err)
	}

	mk := func(key string, app *domain.Application, asset *domain.Asset) *domain.Finding {
		return &domain.Finding{
			ID:                uuid.New(),
			TenantID:          h.tenant,
			FindingKey:        key,
			DedupScope:        app.Slug + ":main",
			AssetID:           asset.ID,
			ApplicationID:     app.ID,
			Track:             "main",
			RuleScannerFamily: "semgrep",
			RuleID:            "rule.test",
			Title:             key,
			Category:          domain.CategorySAST,
			Severity:          domain.SeverityHigh,
			ToolSeverity:      "high",
			State:             domain.StateOpen,
			FirstSeen:         now,
			LastSeen:          now,
			OccurrenceCount:   1,
			Version:           1,
			CreatedAt:         now,
			UpdatedAt:         now,
		}
	}
	fChk := mk("h-find-1", checkout, chkAsset)
	fWal := mk("h-find-2", wallet, walAsset)
	fLog := mk("h-find-3", logistics, logAsset)
	if err := h.store.UpsertFindings(ctx, h.tenant, []*domain.Finding{fChk, fWal, fLog}); err != nil {
		t.Fatal(err)
	}

	authn := auth.NewAuthenticatorWithStore(h.store)
	api := query.NewAPIWithAuth(h.store, enrich.NewFeedStore(), authn)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	srv := httptest.NewServer(api.Audited(mux))
	defer srv.Close()

	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	claire := h.tokenFor(auth.RoleViewer, "claire@acme.example")
	dave := h.tokenFor(auth.RoleViewer, "dave@acme.example")

	do := func(token, method, path, body string) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, b
	}
	triage := func(token string, f *domain.Finding, state string) int {
		code, _ := do(token, "PATCH", "/api/v1/findings/"+f.ID.String(), `{"state":"`+state+`"}`)
		return code
	}

	// 2. Grant hierarchy scope on "fintech.payments" to claire
	code, body := do(boss, "POST", "/api/v1/access-bindings", `{"subject":"claire@acme.example","role":"triager","hierarchyPath":"fintech.payments"}`)
	if code != http.StatusCreated {
		t.Fatalf("bind hierarchy: %d %s", code, body)
	}

	// Claire can triage checkout and wallet (under fintech.payments)
	if c := triage(claire, fChk, "under_investigation"); c != http.StatusOK {
		t.Fatalf("claire on checkout: expected 200, got %d", c)
	}
	if c := triage(claire, fWal, "under_investigation"); c != http.StatusOK {
		t.Fatalf("claire on wallet: expected 200, got %d", c)
	}

	// Claire cannot triage logistics (under ops.logistics)
	if c := triage(claire, fLog, "under_investigation"); c != http.StatusForbidden {
		t.Fatalf("claire on logistics: expected 403, got %d", c)
	}

	// Verify me/access exposes hierarchy bindings
	_, meClaire := do(claire, "GET", "/api/v1/me/access", "")
	if !strings.Contains(string(meClaire), "fintech.payments") || !strings.Contains(string(meClaire), `"triager"`) {
		t.Fatalf("me/access for claire missing hierarchy info: %s", meClaire)
	}

	// 3. Grant tenant scope to dave
	code, body = do(boss, "POST", "/api/v1/access-bindings", `{"subject":"dave@acme.example","role":"triager","tenantScope":true}`)
	if code != http.StatusCreated {
		t.Fatalf("bind tenant scope: %d %s", code, body)
	}

	// Dave has tenant-wide triager role: can triage checkout, wallet, and logistics
	if c := triage(dave, fChk, "out_of_scope"); c != http.StatusOK {
		t.Fatalf("dave on checkout: expected 200, got %d", c)
	}
	if c := triage(dave, fWal, "out_of_scope"); c != http.StatusOK {
		t.Fatalf("dave on wallet: expected 200, got %d", c)
	}
	if c := triage(dave, fLog, "under_investigation"); c != http.StatusOK {
		t.Fatalf("dave on logistics: expected 200, got %d", c)
	}
}
