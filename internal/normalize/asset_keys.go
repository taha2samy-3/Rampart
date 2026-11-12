package normalize

import (
	"net/url"
	"path"
	"strings"
)

// RepositoryURL normalizes a Git repository URL (stripping credentials, trailing .git, and lowercasing host).
func RepositoryURL(raw string) string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimSuffix(raw, "/")
	// Handle scp-like syntax: git@github.com:org/repo.git
	if strings.HasPrefix(raw, "git@") {
		parts := strings.SplitN(raw[4:], ":", 2)
		if len(parts) == 2 {
			host := strings.ToLower(parts[0])
			repoPath := strings.TrimSuffix(strings.TrimSuffix(parts[1], "/"), ".git")
			repoPath = strings.TrimPrefix(repoPath, "/")
			return "https://" + host + "/" + strings.ToLower(repoPath)
		}
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		// Treat as plain path or slug
		clean := strings.TrimSuffix(strings.TrimPrefix(raw, "/"), ".git")
		return strings.ToLower(clean)
	}

	host := strings.ToLower(u.Host)
	cleanPath := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), ".git")
	cleanPath = path.Clean(cleanPath)
	if cleanPath == "." || cleanPath == "/" {
		cleanPath = ""
	} else if !strings.HasPrefix(cleanPath, "/") {
		cleanPath = "/" + cleanPath
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "https"
	}

	return scheme + "://" + host + strings.ToLower(cleanPath)
}

// ImageRef strips tags and digests from container image references per D10 (registry/repository).
func ImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	// Strip digest (@sha256:...)
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}

	// Strip tag (:latest, :v1.0), accounting for registry port (e.g. localhost:5000/repo:tag)
	lastSlash := strings.LastIndex(ref, "/")
	if lastSlash != -1 {
		repoPart := ref[lastSlash+1:]
		if colonIdx := strings.Index(repoPart, ":"); colonIdx != -1 {
			ref = ref[:lastSlash+1] + repoPart[:colonIdx]
		}
	} else {
		if colonIdx := strings.Index(ref, ":"); colonIdx != -1 {
			ref = ref[:colonIdx]
		}
	}

	return strings.ToLower(ref)
}
