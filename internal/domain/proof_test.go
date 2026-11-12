package domain

import (
	"errors"
	"strings"
	"testing"
)

// The proof allow-list (D60): the extension and the first bytes must agree, text must be UTF-8, archives and
// office documents are refused, names cannot hide a path or an extension.
func TestCheckProof(t *testing.T) {
	pdf := []byte("%PDF-1.7\n...")
	png := []byte("\x89PNG\r\n\x1a\n....")
	ok := []struct {
		name, ctype string
		head        []byte
	}{
		{"approval.pdf", "application/pdf", pdf},
		{"Screenshot 2026-11-12.PNG", "image/png", png},
		{"call notes.md", "text/plain; charset=utf-8", []byte("# Call with the owner\nAgreed: internal only. ✓")},
		{"RE approval.eml", "text/plain; charset=utf-8", []byte("From: mona@acme.example\r\nSubject: ok\r\n\r\nAccepted.")},
		{`C:\Users\mona\evidence.txt`, "text/plain; charset=utf-8", []byte("ok")},
	}
	for _, c := range ok {
		name, ctype, err := CheckProof(c.name, c.head, int64(len(c.head)))
		if err != nil || ctype != c.ctype || strings.ContainsAny(name, `\/:`) {
			t.Fatalf("%s: %q %q %v", c.name, name, ctype, err)
		}
	}
	bad := map[string]struct {
		name string
		head []byte
		size int64
	}{
		"a text file named .pdf":      {"approval.pdf", []byte("not a pdf"), 9},
		"a docx (a zip archive)":      {"approval.docx", []byte("PK\x03\x04"), 4},
		"an executable":               {"tool.exe", []byte("MZ"), 2},
		"binary in a .txt":            {"x.txt", []byte("a\x00b"), 3},
		"too large":                   {"big.pdf", pdf, MaxProofBytes + 1},
		"empty":                       {"e.pdf", nil, 0},
		"no extension":                {"README", []byte("x"), 1},
		"hidden file":                 {".env", []byte("x"), 1},
		"double dots":                 {"a..pdf", pdf, int64(len(pdf))},
		"alternate data stream colon": {"a.txt:evil.exe", []byte("x"), 1},
	}
	for why, c := range bad {
		if _, _, err := CheckProof(c.name, c.head, c.size); !errors.Is(err, ErrProof) {
			t.Fatalf("%s: accepted (%v)", why, err)
		}
	}
	long := strings.Repeat("a", 400) + ".pdf"
	if name, _, err := CheckProof(long, pdf, int64(len(pdf))); err != nil || len(name) != MaxProofNameLen || !strings.HasSuffix(name, ".pdf") {
		t.Fatalf("a long name is shortened keeping its extension: %d %v", len(name), err)
	}
}
