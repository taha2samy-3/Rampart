package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"rampart/internal/domain"
)

// CorrelationKey is the second key of D24: computed from category-level fields only, so findings that
// different tools report for the same issue on the same asset share it. It is stored and indexed and groups
// findings for display ("also reported by Grype"); it never merges them. canonVuln is the CVE when the
// identifier is an alias of one (D11, D19).
//
//	SCA:  canonical vulnerability id + purl_base + asset + track
//	SAST: CWE + file path + function (the logical location) + asset + track (docs/05); a CWE and a file are
//	      required, and a report without a logical location correlates on the file alone
//
// It returns "" when the record has not got the fields to correlate on.
func CorrelationKey(rec StagedRecord, canonVuln string, assetID uuid.UUID, track string) string {
	var parts []string
	switch rec.Category {
	case domain.CategorySCA:
		purl := ""
		if rec.Location.Package != nil {
			purl = rec.Location.Package.PurlBase
		}
		id := strings.ToUpper(strings.TrimSpace(canonVuln))
		if id == "" || purl == "" {
			return ""
		}
		parts = []string{"sca", id, purl}
	case domain.CategorySAST:
		file, function := "", ""
		if rec.Location.Code != nil {
			file, function = rec.Location.Code.FilePath, rec.Location.Code.LogicalLocation
		}
		if len(rec.CWEs) == 0 || rec.CWEs[0] <= 0 || file == "" {
			return ""
		}
		parts = []string{"sast", strconv.Itoa(rec.CWEs[0]), file, function}
	default:
		return ""
	}
	parts = append(parts, assetID.String(), track)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}
