// Package client provides a hardened, SSRF-safe REST client for Dependency-Track 4.x/5.x (docs/10, docs/21 §4.2).
package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"rampart/internal/domain"
)

// ErrNotFound is returned when a Dependency-Track resource (e.g. project) does not exist (404).
var ErrNotFound = errors.New("dependencytrack: resource not found")

// RequiredPermissions defines the minimum permissions Rampart needs for flows B and C (pull findings & portfolio).
var RequiredPermissions = []string{
	"VIEW_PORTFOLIO",
	"VIEW_VULNERABILITY",
}

// HTTPDoer executes an HTTP request and returns response body, status code, response headers, and error.
// connectors.SafeClient satisfies this interface.
type HTTPDoer interface {
	Do(req *http.Request) ([]byte, int, http.Header, error)
}

type defaultDoer struct {
	client *http.Client
}

func (d *defaultDoer) Do(req *http.Request) ([]byte, int, http.Header, error) {
	resp, err := d.client.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	return body, resp.StatusCode, resp.Header, err
}

// Config configures the Dependency-Track client.
type Config struct {
	BaseURL   string
	APIKey    string
	Client    HTTPDoer
	Allowlist *domain.PlatformSSRFAllowlist
	Timeout   time.Duration
}

// Client interacts with the Dependency-Track REST API.
type Client struct {
	baseURL   string
	apiKey    string
	doer      HTTPDoer
	allowlist *domain.PlatformSSRFAllowlist
}

// NewClient returns an initialized Dependency-Track client.
func NewClient(cfg Config) *Client {
	baseURL := strings.TrimRight(cfg.BaseURL, "/")
	doer := cfg.Client
	if doer == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		doer = &defaultDoer{
			client: &http.Client{Timeout: timeout},
		}
	}
	return &Client{
		baseURL:   baseURL,
		apiKey:    strings.TrimSpace(cfg.APIKey),
		doer:      doer,
		allowlist: cfg.Allowlist,
	}
}

// Project represents a Dependency-Track project.
type Project struct {
	UUID          string     `json:"uuid"`
	Name          string     `json:"name"`
	Version       string     `json:"version,omitempty"`
	Classifier    string     `json:"classifier,omitempty"`
	Active        bool       `json:"active"`
	Purl          string     `json:"purl,omitempty"`
	LastBomImport int64      `json:"lastBomImport,omitempty"` // epoch ms
	Parent        *ParentRef `json:"parent,omitempty"`
	Tags          []Tag      `json:"tags,omitempty"`
	Properties    []Property `json:"properties,omitempty"`
}

type ParentRef struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type Tag struct {
	Name string `json:"name"`
}

type Property struct {
	Group string `json:"group"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

// ProjectMetrics contains summary counts and last occurrence timestamp for a project.
type ProjectMetrics struct {
	Critical        int   `json:"critical"`
	High            int   `json:"high"`
	Medium          int   `json:"medium"`
	Low             int   `json:"low"`
	Unassigned      int   `json:"unassigned"`
	Vulnerabilities int   `json:"vulnerabilities"`
	LastOccurrence  int64 `json:"lastOccurrence"` // epoch ms
}

type permissionItem struct {
	Name string `json:"name"`
}

type teamSelfResponse struct {
	UUID        string           `json:"uuid"`
	Name        string           `json:"name"`
	Permissions []permissionItem `json:"permissions"`
}

type versionResponse struct {
	Version string `json:"version"`
}

// GetVersion returns the Dependency-Track server version from /api/version.
func (c *Client) GetVersion(ctx context.Context) (string, error) {
	endpoint := c.baseURL + "/api/version"
	body, code, err := c.doGet(ctx, endpoint)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s", code, endpoint)
	}

	var res versionResponse
	if err := json.Unmarshal(body, &res); err != nil {
		// Some DT versions return raw plain text version
		v := strings.TrimSpace(string(body))
		if v != "" {
			return v, nil
		}
		return "", fmt.Errorf("decoding version response: %w", err)
	}
	return res.Version, nil
}

// ProbePermissions checks whether the API key has the required permissions (docs/21 §4.2).
// First probes /api/v1/team/self; falls back to testing capability endpoints if permissions are omitted.
func (c *Client) ProbePermissions(ctx context.Context) (granted []string, missing []string, err error) {
	// 1. Try /api/v1/team/self
	endpoint := c.baseURL + "/api/v1/team/self"
	body, code, getErr := c.doGet(ctx, endpoint)
	if getErr == nil && code == http.StatusOK {
		var team teamSelfResponse
		if err := json.Unmarshal(body, &team); err == nil && len(team.Permissions) > 0 {
			permSet := make(map[string]bool)
			for _, p := range team.Permissions {
				permSet[p.Name] = true
				granted = append(granted, p.Name)
			}
			for _, req := range RequiredPermissions {
				if !permSet[req] {
					missing = append(missing, req)
				}
			}
			return granted, missing, nil
		}
	}

	// 2. Fallback: probe capability endpoints directly
	// A. Probe VIEW_PORTFOLIO via /api/v1/project?pageSize=1
	projURL := c.baseURL + "/api/v1/project?pageSize=1&pageNumber=1"
	_, projCode, projErr := c.doGet(ctx, projURL)
	if projErr != nil {
		return nil, nil, fmt.Errorf("probing VIEW_PORTFOLIO: %w", projErr)
	}
	switch projCode {
	case http.StatusOK:
		granted = append(granted, "VIEW_PORTFOLIO")
	case http.StatusForbidden, http.StatusUnauthorized:
		missing = append(missing, "VIEW_PORTFOLIO")
	default:
		return nil, nil, fmt.Errorf("unexpected status %d probing VIEW_PORTFOLIO", projCode)
	}

	// B. Probe VIEW_VULNERABILITY via /api/v1/vulnerability?pageSize=1
	vulnURL := c.baseURL + "/api/v1/vulnerability?pageSize=1&pageNumber=1"
	_, vulnCode, vulnErr := c.doGet(ctx, vulnURL)
	if vulnErr != nil {
		return granted, missing, fmt.Errorf("probing VIEW_VULNERABILITY: %w", vulnErr)
	}
	switch vulnCode {
	case http.StatusOK:
		granted = append(granted, "VIEW_VULNERABILITY")
	case http.StatusForbidden, http.StatusUnauthorized:
		missing = append(missing, "VIEW_VULNERABILITY")
	}

	return granted, missing, nil
}

// ListProjects retrieves a paged list of projects from /api/v1/project.
// Returns the list of projects, total count from X-Total-Count, and any error.
func (c *Client) ListProjects(ctx context.Context, pageNumber, pageSize int, onlyActive bool) ([]Project, int, error) {
	if pageNumber < 1 {
		pageNumber = 1
	}
	if pageSize <= 0 {
		pageSize = 100
	}

	q := url.Values{}
	q.Set("pageNumber", strconv.Itoa(pageNumber))
	q.Set("pageSize", strconv.Itoa(pageSize))
	if onlyActive {
		q.Set("excludeInactive", "true")
	}

	endpoint := fmt.Sprintf("%s/api/v1/project?%s", c.baseURL, q.Encode())
	req, err := c.newRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}

	body, code, header, err := c.doer.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetching projects: %w", sanitizeError(err))
	}
	if code != http.StatusOK {
		return nil, 0, fmt.Errorf("unexpected status %d from %s", code, endpoint)
	}

	var projects []Project
	if err := json.Unmarshal(body, &projects); err != nil {
		return nil, 0, fmt.Errorf("decoding projects list: %w", err)
	}

	total := len(projects)
	if totalHeader := header.Get("X-Total-Count"); totalHeader != "" {
		if parsed, err := strconv.Atoi(totalHeader); err == nil {
			total = parsed
		}
	}

	return projects, total, nil
}

// GetProject retrieves a single project's details by UUID from /api/v1/project/{uuid}.
func (c *Client) GetProject(ctx context.Context, uuid string) (*Project, error) {
	endpoint := fmt.Sprintf("%s/api/v1/project/%s", c.baseURL, url.PathEscape(uuid))
	body, code, err := c.doGet(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s", code, endpoint)
	}

	var p Project
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decoding project %s: %w", uuid, err)
	}
	return &p, nil
}

// GetProjectProperties retrieves project properties from /api/v1/project/{uuid}/property.
func (c *Client) GetProjectProperties(ctx context.Context, uuid string) ([]Property, error) {
	endpoint := fmt.Sprintf("%s/api/v1/project/%s/property", c.baseURL, url.PathEscape(uuid))
	body, code, err := c.doGet(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, nil
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching project properties for %s", code, uuid)
	}

	var props []Property
	if err := json.Unmarshal(body, &props); err != nil {
		return nil, fmt.Errorf("decoding project properties for %s: %w", uuid, err)
	}
	return props, nil
}

// GetFindings retrieves all findings for a project as raw bytes ready for streaming parse.
// Calls GET /api/v1/finding/project/{uuid}?suppressed=true.
func (c *Client) GetFindings(ctx context.Context, projectUUID string, includeSuppressed bool) ([]byte, error) {
	endpoint := fmt.Sprintf("%s/api/v1/finding/project/%s?suppressed=%t", c.baseURL, url.PathEscape(projectUUID), includeSuppressed)
	body, code, err := c.doGet(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching findings for %s", code, projectUUID)
	}
	return body, nil
}

// GetProjectMetrics retrieves the current metrics for a project from /api/v1/metrics/project/{uuid}/current.
func (c *Client) GetProjectMetrics(ctx context.Context, projectUUID string) (*ProjectMetrics, error) {
	endpoint := fmt.Sprintf("%s/api/v1/metrics/project/%s/current", c.baseURL, url.PathEscape(projectUUID))
	body, code, err := c.doGet(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if code == http.StatusNotFound {
		return nil, ErrNotFound
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching metrics for %s", code, endpoint)
	}

	var m ProjectMetrics
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("decoding metrics for %s: %w", projectUUID, err)
	}
	return &m, nil
}

func (c *Client) newRequest(ctx context.Context, method, endpoint string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *Client) doGet(ctx context.Context, endpoint string) ([]byte, int, error) {
	req, err := c.newRequest(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, 0, err
	}
	body, code, _, err := c.doer.Do(req)
	if err != nil {
		return nil, 0, sanitizeError(err)
	}
	return body, code, nil
}

func sanitizeError(err error) error {
	if err == nil {
		return nil
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		u := urlErr.URL
		if parsed, perr := url.Parse(u); perr == nil {
			parsed.User = nil
			parsed.RawQuery = ""
			u = parsed.String()
		}
		return fmt.Errorf("%s %s: %w", urlErr.Op, u, urlErr.Err)
	}
	return err
}
