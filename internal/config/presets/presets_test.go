package presets_test

import (
	"testing"

	"rampart/internal/config/presets"
)

func TestGetPreset(t *testing.T) {
	for _, name := range []string{
		"clusterslapolicy-pci-dss",
		"clusterslapolicy-fedramp-rev5",
		"clusterslapolicy-fedramp-vdr",
		"clusterslapolicy-cisa-bod",
		"clusterriskpolicy-default",
	} {
		data, err := presets.GetPreset(name)
		if err != nil {
			t.Fatalf("failed to get preset %q: %v", name, err)
		}
		if len(data) == 0 {
			t.Fatalf("preset %q returned empty data", name)
		}
	}
}
