package sbomparsers

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var DefaultSBOMParsersFS embed.FS

// SBOMParserManifest represents the parsed YAML of a ClusterSBOMParser or SBOMParser resource.
type SBOMParserManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec map[string]any `yaml:"spec"`
}

// DefaultSBOMParser represents an embedded default ClusterSBOMParser.
type DefaultSBOMParser struct {
	Name string
	Spec []byte
}

// ParseManifest unmarshals raw YAML into an SBOMParserManifest.
func ParseManifest(data []byte) (*SBOMParserManifest, error) {
	var m SBOMParserManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetDefaultSBOMParser returns the raw YAML of a named default ClusterSBOMParser.
func GetDefaultSBOMParser(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".yaml")
	filename := name + ".yaml"
	data, err := DefaultSBOMParsersFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("sbomparsers: default parser %q not found: %w", name, err)
	}
	return data, nil
}

// ListDefaultSBOMParsers returns all embedded default ClusterSBOMParser objects.
func ListDefaultSBOMParsers() ([]DefaultSBOMParser, error) {
	entries, err := DefaultSBOMParsersFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []DefaultSBOMParser
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := DefaultSBOMParsersFS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		out = append(out, DefaultSBOMParser{
			Name: name,
			Spec: data,
		})
	}
	return out, nil
}
