package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ServerConnection represents connectivity to the Rampart server.
type ServerConnection struct {
	URL       string `json:"url"`
	Source    string `json:"source"`
	Connected bool   `json:"connected"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	LatencyMs int64  `json:"latency_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// UserDetails represents the authenticated user profile.
type UserDetails struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Email   string `json:"email,omitempty"`
	Subject string `json:"subject,omitempty"`
}

// TenantDetails represents the authenticated tenant.
type TenantDetails struct {
	ID   string `json:"id,omitempty"`
	Slug string `json:"slug,omitempty"`
	Name string `json:"name,omitempty"`
}

// AuthStatus represents the current authentication state.
type AuthStatus struct {
	Authenticated bool           `json:"authenticated"`
	Source        string         `json:"source"`
	TokenMasked   string         `json:"token_masked,omitempty"`
	User          *UserDetails   `json:"user,omitempty"`
	Tenant        *TenantDetails `json:"tenant,omitempty"`
	Role          string         `json:"role,omitempty"`
	Error         string         `json:"error,omitempty"`
}

// StatusReport holds complete CLI connectivity and authentication state.
type StatusReport struct {
	ClientVersion string           `json:"client_version"`
	Server        ServerConnection `json:"server"`
	Auth          AuthStatus       `json:"auth"`
}

func resolveServerWithSource(explicit string) (string, string) {
	if explicit != "" {
		return explicit, "flag (--server)"
	}
	if env := os.Getenv("RAMPART_SERVER"); env != "" {
		return env, "environment (RAMPART_SERVER)"
	}
	homeDir, _ := os.UserHomeDir()
	cfgPath := filepath.Join(homeDir, ".rampart", "credentials.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var creds map[string]string
		if json.Unmarshal(data, &creds) == nil && creds["server"] != "" {
			return creds["server"], "credentials file (~/.rampart/credentials.json)"
		}
	}
	return "http://localhost:8080", "default"
}

func resolveTokenWithSource(explicit string) (string, string) {
	if explicit != "" {
		return explicit, "flag (--token)"
	}
	if env := os.Getenv("RAMPART_TOKEN"); env != "" {
		return env, "environment (RAMPART_TOKEN)"
	}
	homeDir, _ := os.UserHomeDir()
	cfgPath := filepath.Join(homeDir, ".rampart", "credentials.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var creds map[string]string
		if json.Unmarshal(data, &creds) == nil && creds["token"] != "" {
			return creds["token"], "credentials file (~/.rampart/credentials.json)"
		}
	}
	return "", "none"
}

func maskToken(tok string) string {
	if tok == "" {
		return ""
	}
	if len(tok) <= 8 {
		return "••••••••"
	}
	return tok[:4] + "••••" + tok[len(tok)-4:]
}

func checkServerConnection(ctx context.Context, serverURL string, client *http.Client) ServerConnection {
	info := ServerConnection{
		URL: serverURL,
	}
	configURL := strings.TrimRight(serverURL, "/") + "/api/v1/ui-config"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		info.Connected = false
		info.Error = err.Error()
		return info
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		info.Connected = false
		info.Error = err.Error()
		return info
	}
	defer func() { _ = resp.Body.Close() }()
	info.LatencyMs = time.Since(start).Milliseconds()

	if resp.StatusCode != http.StatusOK {
		info.Connected = false
		info.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return info
	}

	var data struct {
		Product string `json:"product"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		info.Connected = true
		info.Product = "Rampart"
		return info
	}

	info.Connected = true
	info.Product = data.Product
	info.Version = data.Version
	return info
}

func checkAuthStatus(ctx context.Context, serverURL string, token string, client *http.Client) AuthStatus {
	st := AuthStatus{
		TokenMasked: maskToken(token),
	}
	if token == "" {
		st.Authenticated = false
		st.Error = "no token configured"
		return st
	}

	meURL := strings.TrimRight(serverURL, "/") + "/api/v1/me"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, meURL, nil)
	if err != nil {
		st.Authenticated = false
		st.Error = err.Error()
		return st
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := client.Do(req)
	if err != nil {
		st.Authenticated = false
		st.Error = fmt.Sprintf("connection error: %v", err)
		return st
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		st.Authenticated = false
		st.Error = "invalid or expired token (HTTP 401)"
		return st
	}
	if resp.StatusCode == http.StatusForbidden {
		st.Authenticated = false
		st.Error = "access forbidden (HTTP 403)"
		return st
	}
	if resp.StatusCode != http.StatusOK {
		st.Authenticated = false
		st.Error = fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		return st
	}

	var meResp struct {
		User struct {
			ID      string `json:"id"`
			Email   string `json:"email"`
			Name    string `json:"name"`
			Subject string `json:"subject"`
		} `json:"user"`
		Tenant struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
			Name string `json:"name"`
		} `json:"tenant"`
		Role string `json:"role"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&meResp); err != nil {
		st.Authenticated = false
		st.Error = fmt.Sprintf("failed to decode user profile: %v", err)
		return st
	}

	st.Authenticated = true
	st.User = &UserDetails{
		ID:      meResp.User.ID,
		Name:    meResp.User.Name,
		Email:   meResp.User.Email,
		Subject: meResp.User.Subject,
	}
	st.Tenant = &TenantDetails{
		ID:   meResp.Tenant.ID,
		Slug: meResp.Tenant.Slug,
		Name: meResp.Tenant.Name,
	}
	st.Role = meResp.Role
	return st
}

func runStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	server := fs.String("server", "", "Rampart server URL")
	token := fs.String("token", "", "API token")
	jsonOut := fs.Bool("json", false, "Output status as JSON")
	timeout := fs.Duration("timeout", 5*time.Second, "Timeout for server checks")

	if _, err := parseFlexibleFlags(fs, args); err != nil {
		return err
	}

	targetServer, srvSource := resolveServerWithSource(*server)
	targetToken, tokSource := resolveTokenWithSource(*token)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := &http.Client{Timeout: *timeout}
	srvInfo := checkServerConnection(ctx, targetServer, client)
	srvInfo.Source = srvSource

	var authInfo AuthStatus
	if srvInfo.Connected {
		authInfo = checkAuthStatus(ctx, targetServer, targetToken, client)
	} else if targetToken != "" {
		authInfo = AuthStatus{
			Authenticated: false,
			TokenMasked:   maskToken(targetToken),
			Error:         "server unreachable",
		}
	} else {
		authInfo = AuthStatus{
			Authenticated: false,
			Error:         "not logged in",
		}
	}
	authInfo.Source = tokSource

	report := StatusReport{
		ClientVersion: Version,
		Server:        srvInfo,
		Auth:          authInfo,
	}

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}

	_, _ = fmt.Fprintln(out, "Rampart ASPM Status")
	_, _ = fmt.Fprintln(out, "===================")
	_, _ = fmt.Fprintf(out, "Client Version: %s\n\n", Version)

	_, _ = fmt.Fprintln(out, "Server Connection:")
	_, _ = fmt.Fprintf(out, "  URL:     %s (%s)\n", srvInfo.URL, srvInfo.Source)
	if srvInfo.Connected {
		srvVer := srvInfo.Version
		if srvVer == "" {
			srvVer = "unknown"
		}
		prodName := srvInfo.Product
		if prodName == "" {
			prodName = "Rampart"
		}
		_, _ = fmt.Fprintf(out, "  Status:  Connected (%dms)\n", srvInfo.LatencyMs)
		_, _ = fmt.Fprintf(out, "  Version: %s (%s)\n\n", srvVer, prodName)
	} else {
		_, _ = fmt.Fprintf(out, "  Status:  Unreachable (%s)\n\n", srvInfo.Error)
	}

	_, _ = fmt.Fprintln(out, "Authentication:")
	if authInfo.Authenticated {
		_, _ = fmt.Fprintf(out, "  Status:  Authenticated (%s)\n", authInfo.Source)
		if authInfo.User != nil {
			displayName := authInfo.User.Name
			if displayName == "" {
				displayName = authInfo.User.Email
			} else if authInfo.User.Email != "" && authInfo.User.Email != displayName {
				displayName += fmt.Sprintf(" <%s>", authInfo.User.Email)
			}
			_, _ = fmt.Fprintf(out, "  User:    %s\n", displayName)
		}
		if authInfo.Role != "" {
			_, _ = fmt.Fprintf(out, "  Role:    %s\n", authInfo.Role)
		}
		if authInfo.Tenant != nil && authInfo.Tenant.Slug != "" {
			tenantName := authInfo.Tenant.Slug
			if authInfo.Tenant.Name != "" && authInfo.Tenant.Name != authInfo.Tenant.Slug {
				tenantName += fmt.Sprintf(" (%s)", authInfo.Tenant.Name)
			}
			_, _ = fmt.Fprintf(out, "  Tenant:  %s\n", tenantName)
		}
		if authInfo.TokenMasked != "" {
			_, _ = fmt.Fprintf(out, "  Token:   %s\n", authInfo.TokenMasked)
		}
	} else {
		if targetToken != "" {
			_, _ = fmt.Fprintf(out, "  Status:  Failed (%s)\n", authInfo.Error)
			_, _ = fmt.Fprintf(out, "  Token:   %s (%s)\n", authInfo.TokenMasked, authInfo.Source)
			_, _ = fmt.Fprintln(out, "  Note:    Token is invalid, expired, or server rejected it. Run 'rampart login'.")
		} else {
			_, _ = fmt.Fprintln(out, "  Status:  Not logged in")
			_, _ = fmt.Fprintln(out, "  Note:    Run 'rampart login' or export RAMPART_TOKEN to authenticate.")
		}
	}

	return nil
}

func runWhoami(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	server := fs.String("server", "", "Rampart server URL")
	token := fs.String("token", "", "API token")
	jsonOut := fs.Bool("json", false, "Output profile as JSON")
	timeout := fs.Duration("timeout", 5*time.Second, "Timeout for server checks")

	if _, err := parseFlexibleFlags(fs, args); err != nil {
		return err
	}

	targetServer, _ := resolveServerWithSource(*server)
	targetToken, _ := resolveTokenWithSource(*token)

	if targetToken == "" {
		if *jsonOut {
			_ = json.NewEncoder(out).Encode(map[string]any{
				"authenticated": false,
				"error":         "not logged in",
			})
		}
		return errors.New("not logged in: run 'rampart login' or set RAMPART_TOKEN to authenticate")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := &http.Client{Timeout: *timeout}
	authInfo := checkAuthStatus(ctx, targetServer, targetToken, client)
	if !authInfo.Authenticated {
		if *jsonOut {
			_ = json.NewEncoder(out).Encode(map[string]any{
				"authenticated": false,
				"error":         authInfo.Error,
			})
		}
		return fmt.Errorf("authentication failed: %s", authInfo.Error)
	}

	if *jsonOut {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{
			"authenticated": true,
			"server":        targetServer,
			"user":          authInfo.User,
			"tenant":        authInfo.Tenant,
			"role":          authInfo.Role,
		})
	}

	userStr := ""
	if authInfo.User != nil {
		userStr = authInfo.User.Email
		if userStr == "" {
			userStr = authInfo.User.Name
		}
		if userStr == "" {
			userStr = authInfo.User.Subject
		}
	}
	tenantStr := ""
	if authInfo.Tenant != nil {
		tenantStr = authInfo.Tenant.Slug
	}
	roleStr := authInfo.Role

	_, _ = fmt.Fprintf(out, "Logged in to %s as %s (role: %s, tenant: %s)\n", targetServer, userStr, roleStr, tenantStr)
	return nil
}

func runLogout(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("logout", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("logout: failed to locate home directory: %w", err)
	}
	cfgPath := filepath.Join(homeDir, ".rampart", "credentials.json")

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		if os.IsNotExist(err) {
			_, _ = fmt.Fprintln(out, "No saved credentials found. Already logged out.")
			return nil
		}
		return fmt.Errorf("logout: failed to read credentials: %w", err)
	}

	var creds map[string]string
	_ = json.Unmarshal(data, &creds)
	server := creds["server"]

	if err := os.Remove(cfgPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("logout: failed to remove credentials file: %w", err)
	}

	if server != "" {
		_, _ = fmt.Fprintf(out, "Successfully logged out. Removed credentials for %s.\n", server)
	} else {
		_, _ = fmt.Fprintln(out, "Successfully logged out. Removed stored credentials.")
	}
	return nil
}

func runVersion(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	server := fs.String("server", "", "Rampart server URL")
	short := fs.Bool("short", false, "Print only the client version number")
	jsonOut := fs.Bool("json", false, "Output version information as JSON")
	checkServer := fs.Bool("check-server", true, "Check and display server version")
	timeout := fs.Duration("timeout", 3*time.Second, "Timeout for server check")

	if _, err := parseFlexibleFlags(fs, args); err != nil {
		return err
	}

	if *short {
		_, _ = fmt.Fprintln(out, Version)
		return nil
	}

	targetServer, _ := resolveServerWithSource(*server)

	var srvInfo ServerConnection
	if *checkServer {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		client := &http.Client{Timeout: *timeout}
		srvInfo = checkServerConnection(ctx, targetServer, client)
	}

	if *jsonOut {
		payload := map[string]any{
			"client_version": Version,
		}
		if *checkServer {
			payload["server"] = map[string]any{
				"url":        srvInfo.URL,
				"connected":  srvInfo.Connected,
				"version":    srvInfo.Version,
				"product":    srvInfo.Product,
				"latency_ms": srvInfo.LatencyMs,
				"error":      srvInfo.Error,
			}
		}
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(payload)
	}

	_, _ = fmt.Fprintf(out, "Rampart ASPM Platform v%s (Client)\n", Version)
	if *checkServer {
		if srvInfo.Connected {
			ver := srvInfo.Version
			if ver == "" {
				ver = "unknown"
			}
			_, _ = fmt.Fprintf(out, "Connected Server: %s (v%s, %dms)\n", srvInfo.URL, ver, srvInfo.LatencyMs)
		} else {
			_, _ = fmt.Fprintf(out, "Server (%s): unreachable\n", srvInfo.URL)
		}
	}
	return nil
}

func runAuth(args []string, out io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rampart auth <status|whoami|login|logout> [flags]")
	}
	sub := args[0]
	switch sub {
	case "status":
		return runStatus(args[1:], out)
	case "whoami":
		return runWhoami(args[1:], out)
	case "login":
		return runLogin(args[1:])
	case "logout":
		return runLogout(args[1:], out)
	default:
		return fmt.Errorf("unknown auth subcommand %q, expected 'status', 'whoami', 'login', or 'logout'", sub)
	}
}

func printCLIHelp(out io.Writer) {
	_, _ = fmt.Fprintf(out, `Rampart Cloud-Native Application Security Posture Management (ASPM) CLI

Usage:
  rampart <command> [flags]

Available Commands:
  status       Show server connectivity and authentication status
  whoami       Display currently authenticated user, tenant, and role
  version      Show CLI version and connected server version (-v, --version)
  login        Authenticate with Rampart server (via API token or device flow)
  logout       Clear stored local authentication credentials
  auth         Manage authentication (status, whoami, login, logout)
  upload       Upload scan reports (SAST, DAST, containers)
  sbom         Inspect, graph, or upload SBOM documents (CycloneDX, SPDX)
  gate         Evaluate security gate policy against a commit or digest
  findings     Search, list, and triage security findings
  vex          Export or import VEX statements
  apply        Apply declarative tenant configurations
  migrate      Run database schema migrations
  maintenance  Execute audit and data retention maintenance tasks
  admin        Manage initial administrator credentials

Flags:
  -h, --help      Show help for rampart CLI
  -v, --version   Show version information

Use "rampart <command> --help" for more information about a command.
`)
}
