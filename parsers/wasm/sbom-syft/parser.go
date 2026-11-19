package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"rampart/internal/normalize"
)

// Options is reserved for options of the reader. An SBOM is assets: Syft lists what is in a source and makes no
// finding (docs/34 section 0b), so the reader has nothing to switch on.
type Options struct{}

// Event types emitted as JSONL to stdout. The host (internal/sbom/host.go) reads them.
const (
	EventMetadata  = "metadata"
	EventComponent = "component"
	EventEdge      = "edge"
)

// MetadataEvent describes top-level SBOM information.
type MetadataEvent struct {
	Type        string `json:"type"`
	Format      string `json:"format"`
	SpecVersion string `json:"spec_version"`
	ToolName    string `json:"tool_name,omitempty"`
	RootRef     string `json:"root_ref,omitempty"`
}

// ComponentEvent describes an extracted package.
type ComponentEvent struct {
	Type     string   `json:"type"`
	Ref      string   `json:"ref"`
	Name     string   `json:"name"`
	Version  string   `json:"version,omitempty"`
	Purl     string   `json:"purl,omitempty"`
	PurlBase string   `json:"purl_base,omitempty"`
	CompType string   `json:"component_type,omitempty"`
	Licenses []string `json:"licenses,omitempty"`
}

// EdgeEvent describes a dependency relationship.
type EdgeEvent struct {
	Type   string `json:"type"`
	From   string `json:"from"`
	To     string `json:"to"`
	Direct bool   `json:"direct"`
}

type syftArtifact struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Version  string `json:"version"`
	Type     string `json:"type"`
	Purl     string `json:"purl"`
	Licenses []struct {
		Value          string `json:"value"`
		SPDXExpression string `json:"spdxExpression"`
	} `json:"licenses"`
}

type syftRelationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

type syftSource struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftSchema struct {
	Version string `json:"version"`
}

// ParseSyftStream reads an Anchore Syft JSON document and writes line-delimited JSON events: the packages as
// components, the relationships as edges and one metadata line. The document is read as a stream: the `artifacts`
// array is emitted one element at a time and every other large section (`files`, `distro`, ...) is skipped, so memory
// holds the id of each package and the relationships, not the document.
//
// It fails, writing nothing it cannot stand behind, when the input is not a Syft document: a document that has no
// `artifacts` array is not one, and an SBOM that says nothing is not an SBOM with no packages.
func ParseSyftStream(r io.Reader, w io.Writer, _ Options) error {
	out := bufio.NewWriter(w)
	defer func() { _ = out.Flush() }()
	emit := func(v any) error {
		data, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := out.Write(data); err != nil {
			return err
		}
		return out.WriteByte('\n')
	}

	dec := json.NewDecoder(bufio.NewReaderSize(r, 256<<10))
	tok, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("not a Syft document: it is empty")
		}
		return fmt.Errorf("not a Syft document: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return errors.New("not a Syft document: it is not a JSON object")
	}

	var (
		sawArtifacts bool
		source       *syftSource
		descriptor   *syftDescriptor
		schema       *syftSchema
		relations    []syftRelationship
		refOf        = map[string]string{} // artifact id -> the ref its component carries
		refOfNameVer = map[string]string{} // name@version -> the ref of the first artifact with it
		skipped      int
	)

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		switch key {
		case "artifacts":
			if err := expectDelim(dec, '['); err != nil {
				return fmt.Errorf("artifacts: %w", err)
			}
			sawArtifacts = true
			for dec.More() {
				var a syftArtifact
				if err := dec.Decode(&a); err != nil {
					return fmt.Errorf("decoding an artifact: %w", err)
				}
				ref := a.ID
				if a.Purl != "" {
					ref = a.Purl
				}
				if ref == "" && a.Name == "" {
					skipped++ // an artifact that names nothing cannot be told apart from another
					continue
				}
				if a.ID != "" {
					refOf[a.ID] = ref
				}
				if a.Name != "" {
					if _, seen := refOfNameVer[a.Name+"@"+a.Version]; !seen {
						refOfNameVer[a.Name+"@"+a.Version] = ref
					}
				}
				purlBase := ""
				if a.Purl != "" {
					_, purlBase, _ = normalize.CanonicalPURL(a.Purl)
				}
				var licenses []string
				for _, l := range a.Licenses {
					if l.Value != "" {
						licenses = append(licenses, l.Value)
					} else if l.SPDXExpression != "" {
						licenses = append(licenses, l.SPDXExpression)
					}
				}
				if err := emit(ComponentEvent{
					Type: EventComponent, Ref: ref, Name: a.Name, Version: a.Version, Purl: a.Purl, PurlBase: purlBase,
					CompType: a.Type, Licenses: licenses,
				}); err != nil {
					return err
				}
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}
		case "artifactRelationships":
			if err := expectDelim(dec, '['); err != nil {
				return fmt.Errorf("artifactRelationships: %w", err)
			}
			for dec.More() {
				var rel syftRelationship
				if err := dec.Decode(&rel); err != nil {
					return fmt.Errorf("decoding a relationship: %w", err)
				}
				relations = append(relations, rel)
			}
			if err := expectDelim(dec, ']'); err != nil {
				return err
			}
		case "source":
			source = &syftSource{}
			if err := dec.Decode(source); err != nil {
				source = nil // Syft 0.x wrote a string here: the source is only a name for the root, not required
			}
		case "descriptor":
			descriptor = &syftDescriptor{}
			if err := dec.Decode(descriptor); err != nil {
				descriptor = nil
			}
		case "schema":
			schema = &syftSchema{}
			if err := dec.Decode(schema); err != nil {
				schema = nil
			}
		default:
			if err := skipValue(dec); err != nil {
				return err
			}
		}
	}
	if !sawArtifacts {
		return errors.New("not a Syft document: it has no artifacts array")
	}

	specVersion := "1.0"
	switch {
	case schema != nil && schema.Version != "":
		specVersion = schema.Version
	case descriptor != nil && descriptor.Version != "":
		specVersion = descriptor.Version
	}
	// The root is the source Syft scanned. When a package of that name and version is in the list (a directory or a
	// repository that is itself a package), the root is that component, so the edges leaving it are direct and a path
	// from the root can be found. A source that is no package (an image) stays a name.
	rootRef := ""
	if source != nil && source.Name != "" {
		rootRef = source.Name
		if source.Version != "" {
			rootRef += "@" + source.Version
		}
		if ref, ok := refOfNameVer[rootRef]; ok {
			rootRef = ref
		}
	}
	tool := ""
	if descriptor != nil {
		tool = descriptor.Name
	}
	if err := emit(MetadataEvent{Type: EventMetadata, Format: "Syft", SpecVersion: specVersion, ToolName: tool, RootRef: rootRef}); err != nil {
		return err
	}

	// Syft names a relationship by artifact id; the components carry the purl when there is one.
	resolve := func(id string) string {
		if ref, ok := refOf[id]; ok {
			return ref
		}
		return id
	}
	for _, rel := range relations {
		parent, child := resolve(rel.Parent), resolve(rel.Child)
		if parent == "" || child == "" {
			continue
		}
		switch strings.ToLower(rel.Type) {
		case "depends-on", "contains":
			if err := emit(EdgeEvent{Type: EventEdge, From: parent, To: child, Direct: rootRef != "" && parent == rootRef}); err != nil {
				return err
			}
		case "dependency-of":
			if err := emit(EdgeEvent{Type: EventEdge, From: child, To: parent, Direct: rootRef != "" && child == rootRef}); err != nil {
				return err
			}
		}
	}
	if skipped > 0 {
		_, _ = fmt.Fprintf(errWriter, "syft: %d artifact(s) with no id, purl or name were skipped\n", skipped)
	}
	return nil
}

func expectDelim(dec *json.Decoder, d json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if got, ok := tok.(json.Delim); !ok || got != d {
		return fmt.Errorf("expected %q, got %v", string(d), tok)
	}
	return nil
}

// skipValue reads past one JSON value token by token, so a section the reader does not use (`files` can be hundreds
// of megabytes for an image) is never held in memory.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
