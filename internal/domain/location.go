package domain

import (
	"strings"
)

// CodeLocation defines source-code coordinates for SAST, Secrets, and IaC.
type CodeLocation struct {
	FilePath        string `json:"file_path,omitempty"`
	StartLine       int    `json:"start_line,omitempty"`
	EndLine         int    `json:"end_line,omitempty"`
	StartColumn     int    `json:"start_column,omitempty"`
	EndColumn       int    `json:"end_column,omitempty"`
	LogicalLocation string `json:"logical_location,omitempty"` // function, class, or module
	Snippet         string `json:"snippet,omitempty"`
	SnippetHash     string `json:"snippet_hash,omitempty"` // SHA-256 of normalized whitespace snippet
}

// PackageLocation defines package and dependency coordinates for SCA.
type PackageLocation struct {
	Purl             string   `json:"purl,omitempty"`
	PurlBase         string   `json:"purl_base,omitempty"` // purl without version or qualifiers
	ComponentName    string   `json:"component_name,omitempty"`
	InstalledVersion string   `json:"installed_version,omitempty"`
	FixedVersion     string   `json:"fixed_version,omitempty"`
	ManifestPath     string   `json:"manifest_path,omitempty"`
	DependencyPath   []string `json:"dependency_path,omitempty"`
}

// WebLocation defines endpoint coordinates for DAST.
type WebLocation struct {
	NormalizedURL string `json:"normalized_url,omitempty"`
	Method        string `json:"method,omitempty"`
	Parameter     string `json:"param,omitempty"`
}

// ResourceLocation defines infrastructure and cloud resource coordinates.
type ResourceLocation struct {
	Address string `json:"resource_address,omitempty"` // terraform resource address, e.g. aws_s3_bucket.data
	Key     string `json:"resource_key,omitempty"`     // cluster/namespace/kind/name or ARN
	Type    string `json:"resource_type,omitempty"`
}

// Location represents the typed union of all finding physical coordinates (normative D11).
type Location struct {
	Code     *CodeLocation     `json:"code,omitempty"`
	Package  *PackageLocation  `json:"package,omitempty"`
	Web      *WebLocation      `json:"web,omitempty"`
	Resource *ResourceLocation `json:"resource,omitempty"`
	Image    string            `json:"image,omitempty"` // container image reference/layer
}

// PrimaryPath extracts the most relevant human-readable target path.
func (l Location) PrimaryPath() string {
	if l.Code != nil && l.Code.FilePath != "" {
		return l.Code.FilePath
	}
	if l.Package != nil {
		if l.Package.ManifestPath != "" {
			return l.Package.ManifestPath
		}
		if l.Package.PurlBase != "" {
			return l.Package.PurlBase
		}
		if l.Package.ComponentName != "" {
			return l.Package.ComponentName
		}
	}
	if l.Web != nil && l.Web.NormalizedURL != "" {
		return l.Web.NormalizedURL
	}
	if l.Resource != nil {
		if l.Resource.Address != "" {
			return l.Resource.Address
		}
		if l.Resource.Key != "" {
			return l.Resource.Key
		}
	}
	if l.Image != "" {
		return l.Image
	}
	return ""
}

// IsEmpty returns true if no sub-location coordinate is populated.
func (l Location) IsEmpty() bool {
	return (l.Code == nil || strings.TrimSpace(l.Code.FilePath) == "") &&
		(l.Package == nil || (l.Package.Purl == "" && l.Package.ComponentName == "")) &&
		(l.Web == nil || l.Web.NormalizedURL == "") &&
		(l.Resource == nil || (l.Resource.Address == "" && l.Resource.Key == "")) &&
		l.Image == ""
}
