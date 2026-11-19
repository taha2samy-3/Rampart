package parsers

import (
	"embed"
	"fmt"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var DefaultParsersFS embed.FS

// ParserManifest represents the parsed YAML of a ClusterParser resource.
type ParserManifest struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name string `yaml:"name"`
	} `yaml:"metadata"`
	Spec map[string]any `yaml:"spec"`
}

// DefaultParser represents an embedded default parser.
type DefaultParser struct {
	Name string
	Spec []byte
}

// ParseManifest unmarshals a raw YAML into a ParserManifest.
func ParseManifest(data []byte) (*ParserManifest, error) {
	var m ParserManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// GetDefaultParser returns the raw YAML of a named default ClusterParser.
func GetDefaultParser(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".yaml")
	filename := name + ".yaml"
	data, err := DefaultParsersFS.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("parsers: default parser %q not found: %w", name, err)
	}
	return data, nil
}

// ListDefaultParsers returns all embedded default ClusterParser objects.
func ListDefaultParsers() ([]DefaultParser, error) {
	entries, err := DefaultParsersFS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	var out []DefaultParser
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := DefaultParsersFS.ReadFile(e.Name())
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		out = append(out, DefaultParser{
			Name: name,
			Spec: data,
		})
	}
	return out, nil
}
