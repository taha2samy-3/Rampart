package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"rampart/internal/domain"
	trackerclient "rampart/internal/tracker/client"
)

// CheckInfo is what a Check learns besides "it works" (D87); defined in domain so the operator can read it.
type CheckInfo = domain.ConnectorCheckInfo

// DetailedChecker is a Checker that also returns what it learned. The operator stores it in the connector status.
type DetailedChecker interface {
	CheckDetailed(ctx context.Context, conn domain.Connector, secret []byte) (CheckInfo, error)
}

// SetGitHubAPI overrides the GitHub API base (tests).
func (c *DefaultChecker) SetGitHubAPI(u string) { c.githubAPI = u }

// CheckDetailed runs the connector's Check and returns what it learned.
func (c *DefaultChecker) CheckDetailed(ctx context.Context, conn domain.Connector, secret []byte) (CheckInfo, error) {
	s := c.forConnector(conn)
	switch conn.Type {
	case domain.ConnectorTypeJira:
		return s.checkJiraDetailed(ctx, conn, secret)
	case domain.ConnectorTypeGitHub:
		return CheckInfo{}, s.checkGitHub(ctx, conn, secret)
	case domain.ConnectorTypeExternalTracker:
		return s.checkExternalTrackerDetailed(ctx, conn, secret)
	default:
		return CheckInfo{}, s.check(ctx, conn, secret)
	}
}

func (c *DefaultChecker) checkExternalTrackerDetailed(ctx context.Context, conn domain.Connector, secret []byte) (CheckInfo, error) {
	if conn.Spec.ExternalTracker == nil {
		return CheckInfo{}, errors.New("externalTracker config is nil")
	}
	if c.trackerStore == nil {
		return CheckInfo{}, errors.New("externalTracker check requires tracker store wiring")
	}
	cfg := *conn.Spec.ExternalTracker
	scope := strings.ToLower(strings.TrimSpace(cfg.TrackerRef.Scope))
	if scope == "" {
		scope = "cluster"
	}
	obj, found, err := c.trackerStore.GetTracker(ctx, conn.TenantID, scope, cfg.TrackerRef.Namespace, cfg.TrackerRef.Name)
	if err != nil {
		return CheckInfo{}, err
	}
	if !found {
		return CheckInfo{}, fmt.Errorf("referenced external tracker %q (%s) not found", cfg.TrackerRef.Name, scope)
	}
	if obj.Error != "" {
		return CheckInfo{}, fmt.Errorf("external tracker %q refused: %s", cfg.TrackerRef.Name, obj.Error)
	}
	spec, err := parseStoredTracker(obj)
	if err != nil {
		return CheckInfo{}, err
	}
	if !spec.IsEnabled() {
		return CheckInfo{}, fmt.Errorf("external tracker %q is disabled", cfg.TrackerRef.Name)
	}

	secrets := map[string]string{}
	if len(secret) > 0 {
		// Support either JSON map of named secrets or single default "token" key.
		if err := json.Unmarshal(secret, &secrets); err != nil {
			secrets = map[string]string{"token": strings.TrimSpace(string(secret))}
		}
	}
	dialFn := c.dialTracker
	if dialFn == nil {
		dialFn = trackerclient.Dial
	}
	cli, err := dialFn(trackerclient.DialConfig{
		Target:  spec.Target(obj.Namespace),
		Secure:  spec.UseTLS(),
		Timeout: spec.Timeout(),
	})
	if err != nil {
		return CheckInfo{}, err
	}

	tr, err := NewGrpcTracker(cfg, cli, secrets, "")
	if err != nil {
		_ = cli.Close()
		return CheckInfo{}, err
	}
	// A check is rare and asked for by a person: it dials its own connection and closes it when done.
	defer func() { _ = tr.CloseClient() }()
	tr.SetConnectorName(conn.Name)
	return tr.CheckDetailed(ctx)
}

// jiraAuthHeader is the header the tracker sends: Basic for "email:apiToken", Bearer for a personal access token.
func jiraAuthHeader(secret []byte) string {
	s := strings.TrimSpace(string(secret))
	if strings.Contains(s, ":") {
		return "Basic " + basicAuthToken(s)
	}
	return "Bearer " + s
}

func (c *DefaultChecker) getJSON(ctx context.Context, u, auth string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/json")
	body, status, _, err := c.client.Do(req)
	if err != nil {
		return 0, SanitizeError(err)
	}
	if status >= 300 {
		return status, fmt.Errorf("HTTP %d", status) // never the body: it may echo what was sent
	}
	return status, json.Unmarshal(body, out)
}

// checkJiraDetailed verifies the credentials and learns the account and the accepted create fields (D87).
//
//  1. GET /rest/api/3/myself: the credentials work; accountId is the account Rampart acts as (D70 B6). A change made
//     by it is Rampart's own and never read as a decision.
//  2. GET /rest/api/3/issue/createmeta/{project}/issuetypes: the configured issue type exists in the project.
//  3. GET /rest/api/3/issue/createmeta/{project}/issuetypes/{id}: the fields that screen accepts; priority and labels
//     are sent only when accepted (D70 B10), because one field the screen lacks makes Jira refuse the whole issue.
func (c *DefaultChecker) checkJiraDetailed(ctx context.Context, conn domain.Connector, secret []byte) (CheckInfo, error) {
	if err := c.checkJira(ctx, conn, secret); err != nil { // the URL and the SSRF policy
		return CheckInfo{}, err
	}
	if len(strings.TrimSpace(string(secret))) == 0 {
		return CheckInfo{}, errors.New("jira credentials are empty")
	}
	cfg := conn.Spec.Jira
	base := strings.TrimRight(cfg.URL, "/")
	auth := jiraAuthHeader(secret)

	var me struct {
		AccountID string `json:"accountId"`
	}
	if status, err := c.getJSON(ctx, base+"/rest/api/3/myself", auth, &me); err != nil {
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			return CheckInfo{}, fmt.Errorf("jira refused the credentials (%d)", status)
		}
		return CheckInfo{}, fmt.Errorf("jira /myself: %w", err)
	}
	info := CheckInfo{AccountID: me.AccountID}

	issueType := cfg.IssueType
	if issueType == "" {
		issueType = "Bug"
	}
	project := url.PathEscape(cfg.DefaultProject)
	var types struct {
		IssueTypes []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"issueTypes"`
		Values []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"values"`
	}
	if _, err := c.getJSON(ctx, base+"/rest/api/3/issue/createmeta/"+project+"/issuetypes", auth, &types); err != nil {
		return info, fmt.Errorf("jira project %q: create metadata unavailable: %w", cfg.DefaultProject, err)
	}
	typeID := ""
	for _, t := range append(types.IssueTypes, types.Values...) {
		if strings.EqualFold(t.Name, issueType) {
			typeID = t.ID
		}
	}
	if typeID == "" {
		return info, fmt.Errorf("jira project %q has no issue type %q", cfg.DefaultProject, issueType)
	}
	var fields struct {
		Fields []struct {
			FieldID string `json:"fieldId"`
		} `json:"fields"`
		Values []struct {
			FieldID string `json:"fieldId"`
		} `json:"values"`
	}
	if _, err := c.getJSON(ctx, base+"/rest/api/3/issue/createmeta/"+project+"/issuetypes/"+url.PathEscape(typeID)+"?maxResults=200", auth, &fields); err != nil {
		return info, fmt.Errorf("jira create fields of %q: %w", issueType, err)
	}
	for _, f := range append(fields.Fields, fields.Values...) {
		info.AcceptedFields = append(info.AcceptedFields, f.FieldID)
	}
	return info, nil
}

// checkGitHub verifies the repository and that the token can push to it. Without push access GitHub creates the
// issue and silently drops its labels and assignees (docs/20 §4), and the label is how a lost answer is found again
// (D70 B2).
func (c *DefaultChecker) checkGitHub(ctx context.Context, conn domain.Connector, secret []byte) error {
	cfg := conn.Spec.GitHub
	if cfg == nil || cfg.Owner == "" || cfg.Repo == "" {
		return errors.New("github owner and repo are required")
	}
	token := strings.TrimSpace(string(secret))
	if token == "" {
		return errors.New("github token is empty")
	}
	api := c.githubAPI
	if api == "" {
		api = "https://api.github.com"
	}
	var repo struct {
		Permissions struct {
			Push bool `json:"push"`
		} `json:"permissions"`
	}
	status, err := c.getJSON(ctx, strings.TrimRight(api, "/")+"/repos/"+url.PathEscape(cfg.Owner)+"/"+url.PathEscape(cfg.Repo), "Bearer "+token, &repo)
	if err != nil {
		if status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusNotFound {
			return fmt.Errorf("github refused the token or the repository is not visible to it (%d)", status)
		}
		return fmt.Errorf("github: %w", err)
	}
	if !repo.Permissions.Push {
		return errors.New("the github token has no push access: labels would be dropped silently")
	}
	return nil
}
