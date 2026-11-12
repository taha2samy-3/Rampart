package presets

import (
	"embed"
	"fmt"
)

//go:embed *.yaml
var PresetsFS embed.FS

// GetPreset returns the raw YAML of a named preset.
func GetPreset(name string) ([]byte, error) {
	filename := name + ".yaml"
	data, err := PresetsFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("presets: preset %q not found: %w", name, err)
	}
	return data, nil
}
