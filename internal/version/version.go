// Package version holds the build version. Release builds set it with
// -ldflags "-X rampart/internal/version.Version=1.2.3" (ko does this through .ko.yaml).
package version

// Version is the product version reported by the CLI and by GET /api/v1/ui-config.
var Version = "0.1.0"
