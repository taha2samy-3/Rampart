package domain

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// RiskAcceptanceProof is a file that supports a risk acceptance: an e-mail acknowledging the risk, meeting notes,
// a written justification (docs/01 C5, docs/03, D60). Proofs are evidence, so they are never changed or removed.
type RiskAcceptanceProof struct {
	ID               uuid.UUID `json:"id"`
	RiskAcceptanceID uuid.UUID `json:"risk_acceptance_id"`
	Name             string    `json:"name"`
	ContentType      string    `json:"content_type"`
	SizeBytes        int64     `json:"size_bytes"`
	SHA256           string    `json:"sha256"`
	ObjectRef        string    `json:"-"`
	UploadedBy       string    `json:"uploaded_by"`
	UploadedAt       time.Time `json:"uploaded_at"`
}

// Limits on proofs (D60).
const (
	MaxProofBytes   = 10 << 20 // 10 MiB: documents and screenshots, not archives
	MaxProofs       = 10       // per acceptance
	MaxProofNameLen = 200
)

// proofKinds is the allow-list: extension, the bytes such a file starts with, and the type it is served as.
// Office documents are not on it: a .docx is a ZIP archive, which the OWASP file upload guidance advises against
// accepting; export them to PDF. Text kinds (.txt, .md, .eml) must be UTF-8 without NUL bytes.
var proofKinds = map[string]struct {
	magic       []byte
	contentType string
}{
	".pdf":  {[]byte("%PDF-"), "application/pdf"},
	".png":  {[]byte("\x89PNG\r\n\x1a\n"), "image/png"},
	".jpg":  {[]byte{0xFF, 0xD8, 0xFF}, "image/jpeg"},
	".jpeg": {[]byte{0xFF, 0xD8, 0xFF}, "image/jpeg"},
	".txt":  {nil, "text/plain; charset=utf-8"},
	".md":   {nil, "text/plain; charset=utf-8"},
	".eml":  {nil, "text/plain; charset=utf-8"},
}

// ErrProof is a proof file refused, with the reason in its message.
var ErrProof = errors.New("proof refused")

// CheckProof validates an uploaded proof by its name and its first bytes, never by the Content-Type the client
// sent (OWASP: it "cannot be trusted"). It returns the name to show and the type to serve it as.
func CheckProof(name string, head []byte, size int64) (string, string, error) {
	if size <= 0 {
		return "", "", fmt.Errorf("%w: the file is empty", ErrProof)
	}
	if size > MaxProofBytes {
		return "", "", fmt.Errorf("%w: the file is larger than %d MiB", ErrProof, MaxProofBytes>>20)
	}
	clean := cleanProofName(name)
	if clean == "" {
		return "", "", fmt.Errorf("%w: the file needs a name with an extension", ErrProof)
	}
	ext := strings.ToLower(path.Ext(clean))
	kind, ok := proofKinds[ext]
	if !ok {
		return "", "", fmt.Errorf("%w: %s files are not accepted; use PDF, PNG, JPEG, plain text, Markdown or a saved e-mail (.eml)", ErrProof, ext)
	}
	if kind.magic != nil {
		if !bytes.HasPrefix(head, kind.magic) {
			return "", "", fmt.Errorf("%w: the content is not a %s file", ErrProof, strings.TrimPrefix(ext, "."))
		}
	} else if bytes.IndexByte(head, 0) >= 0 || !utf8.Valid(trimPartialRune(head)) {
		return "", "", fmt.Errorf("%w: a %s file must be UTF-8 text", ErrProof, ext)
	}
	return clean, kind.contentType, nil
}

// cleanProofName keeps the base name, drops control characters, and refuses what can hide an extension or a
// path (OWASP: colons, leading and repeated dots). The name is only shown; files are stored under a new id.
func cleanProofName(name string) string {
	name = path.Base(strings.ReplaceAll(name, `\`, "/"))
	var b strings.Builder
	for _, r := range name {
		if unicode.IsControl(r) || r == ':' || r == '/' {
			continue
		}
		b.WriteRune(r)
	}
	out := strings.TrimSpace(b.String())
	if out == "." || strings.HasPrefix(out, ".") || strings.Contains(out, "..") || !strings.Contains(out, ".") {
		return ""
	}
	if len(out) > MaxProofNameLen {
		ext := path.Ext(out)
		if len(ext) > 16 { // no allowed extension is this long; refuse instead of cutting (found by FuzzCheckProof)
			return ""
		}
		base := out[:MaxProofNameLen-len(ext)]
		for !utf8.ValidString(base) { // never cut a character in half
			base = base[:len(base)-1]
		}
		out = base + ext
	}
	return out
}

// trimPartialRune drops a rune cut in half at the end of the sniffed head.
func trimPartialRune(b []byte) []byte {
	for i := 0; i < utf8.UTFMax && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}
