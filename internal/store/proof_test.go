package store_test

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"

	"rampart/internal/auth"
	"rampart/internal/domain"
)

func (h *uploadHarness) uploadProof(token, acceptanceID, name string, data []byte) (int, []byte) {
	h.t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", name)
	_, _ = fw.Write(data)
	_ = mw.Close()
	req, _ := http.NewRequest("POST", h.server.URL+"/api/v1/risk-acceptances/"+acceptanceID+"/proofs", &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, out
}

// Proof files on a risk acceptance (01 C5, D60): the requester attaches a PDF and an e-mail; a file whose bytes
// do not match its extension, an office document and someone unrelated are refused; anyone who reads the
// acceptance can download, always as an attachment with the type the server chose, and the download is audited;
// at most ten; nothing more once the acceptance is closed.
func TestRiskAcceptanceProofs(t *testing.T) {
	h := newUploadHarness(t)
	ingestRules(t, h, map[string]string{"rule.a": "9.5"}, "main")
	a := findingIDs(t, h)["rule.a"]
	sara := h.tokenFor(auth.RoleTriager, "sara@acme.example")
	omar := h.tokenFor(auth.RoleTriager, "omar@acme.example")
	viewer := h.tokenFor(auth.RoleViewer, "viewer@acme.example")
	boss := h.tokenFor(auth.RoleAdmin, "boss@acme.example")
	code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances", map[string]any{
		"findingIds": []string{a.String()}, "justification": "internal service behind the VPN", "expiresAt": days(30)}, nil)
	if code != http.StatusCreated {
		t.Fatalf("request: %d %s", code, body)
	}
	var out struct{ Acceptance domain.RiskAcceptance }
	_ = json.Unmarshal(body, &out)
	id := out.Acceptance.ID.String()

	pdf := []byte("%PDF-1.7\n1 0 obj << >> endobj\n%%EOF\n")
	if code, body := h.uploadProof(sara, id, "CISO approval.pdf", pdf); code != http.StatusCreated {
		t.Fatalf("pdf: %d %s", code, body)
	}
	if code, body := h.uploadProof(sara, id, "RE- risk.eml", []byte("From: ciso@acme.example\r\n\r\nApproved until the migration.")); code != http.StatusCreated {
		t.Fatalf("eml: %d %s", code, body)
	}
	for name, data := range map[string][]byte{"fake.pdf": []byte("<html>hi</html>"), "minutes.docx": []byte("PK\x03\x04....")} {
		if code, body := h.uploadProof(sara, id, name, data); code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: %d %s", name, code, body)
		}
	}
	if code, _ := h.uploadProof(omar, id, "x.pdf", pdf); code != http.StatusForbidden {
		t.Fatalf("an unrelated triager added proof: %d", code)
	}
	if code, _ := h.uploadProof(viewer, id, "x.pdf", pdf); code != http.StatusForbidden {
		t.Fatalf("a viewer added proof: %d", code)
	}

	code, body = h.callAs(viewer, "GET", "/api/v1/risk-acceptances/"+id+"/proofs", nil, nil)
	var list struct{ Items []domain.RiskAcceptanceProof }
	_ = json.Unmarshal(body, &list)
	if code != http.StatusOK || len(list.Items) != 2 || list.Items[0].Name != "CISO approval.pdf" || list.Items[0].UploadedBy != "user:sara@acme.example" {
		t.Fatalf("list: %d %s", code, body)
	}
	req, _ := http.NewRequest("GET", h.server.URL+"/api/v1/risk-acceptances/"+id+"/proofs/"+list.Items[0].ID.String(), nil)
	req.Header.Set("Authorization", "Bearer "+viewer)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || !bytes.Equal(got, pdf) || res.Header.Get("Content-Type") != "application/pdf" ||
		!strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment") || res.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download: %d %v", res.StatusCode, res.Header)
	}
	_, audit := h.callAs(boss, "GET", "/api/v1/audit?action=GET%20/api/v1/risk-acceptances/%7Bid%7D/proofs/%7Bproof%7D", nil, nil)
	if !strings.Contains(string(audit), "user:viewer@acme.example") {
		t.Fatalf("the download is not in the audit log: %s", audit)
	}

	// At most ten.
	for i := 0; i < domain.MaxProofs-2; i++ {
		if code, body := h.uploadProof(sara, id, "page.png", []byte("\x89PNG\r\n\x1a\n....")); code != http.StatusCreated {
			t.Fatalf("proof %d: %d %s", i+3, code, body)
		}
	}
	if code, _ := h.uploadProof(sara, id, "one-more.png", []byte("\x89PNG\r\n\x1a\n....")); code != http.StatusConflict {
		t.Fatalf("an eleventh proof: %d", code)
	}

	// A closed acceptance is a record: no more proof.
	if code, body := h.callAs(sara, "POST", "/api/v1/risk-acceptances/"+id+"/revoke", map[string]any{"note": "fixed instead"}, nil); code != http.StatusOK {
		t.Fatalf("revoke: %d %s", code, body)
	}
	if code, _ := h.uploadProof(boss, id, "late.pdf", pdf); code != http.StatusConflict {
		t.Fatalf("proof on a revoked acceptance: %d", code)
	}
}
