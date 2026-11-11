// Package web embeds the built single-page application (doc 13 section 2).
//
// `pnpm build` in this directory writes dist/. The directory always exists in git (a .keep file) so
// the Go build works before the first UI build; the server then explains that the UI is not built.
package web

import "embed"

// Dist is the contents of dist/ (hashed assets and index.html).
//
//go:embed all:dist
var Dist embed.FS
