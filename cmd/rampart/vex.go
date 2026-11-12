package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// runVEX is `rampart vex export|import` (docs/11, docs/16 D47).
func runVEX(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("vex: a subcommand is required (export, import)")
	}
	switch args[0] {
	case "export":
		return runVEXExport(args[1:], stdout)
	case "import":
		return runVEXImport(args[1:], stdout)
	}
	return fmt.Errorf("vex: unknown subcommand %q (valid: export, import)", args[0])
}

func vexRequest(method, server, path, token string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, strings.TrimRight(server, "/")+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := resolveToken(token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return (&http.Client{Timeout: 2 * time.Minute}).Do(req)
}

func runVEXExport(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vex export", flag.ContinueOnError)
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	token := fs.String("token", "", "API token")
	app := fs.String("app", "", "Application id")
	asset := fs.String("asset", "", "Asset id (instead of --app)")
	format := fs.String("format", "openvex", "openvex | cyclonedx")
	if _, err := parseFlexibleFlags(fs, args); err != nil {
		return err
	}
	if (*app == "") == (*asset == "") {
		return fmt.Errorf("vex export: give exactly one of --app and --asset")
	}
	path := "/api/v1/applications/" + url.PathEscape(*app) + "/vex"
	if *asset != "" {
		path = "/api/v1/assets/" + url.PathEscape(*asset) + "/vex"
	}
	resp, err := vexRequest("GET", *server, path+"?format="+url.QueryEscape(*format), *token, nil)
	if err != nil {
		return fmt.Errorf("vex export failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	_, err = io.Copy(stdout, resp.Body)
	return err
}

func runVEXImport(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("vex import", flag.ContinueOnError)
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	token := fs.String("token", "", "API token")
	app := fs.String("app", "", "Only decide findings of this application")
	dry := fs.Bool("dry-run", false, "Say what would change and change nothing")
	pos, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return fmt.Errorf("vex import: give one file (or - for standard input)")
	}
	var data []byte
	if pos[0] == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(pos[0])
	}
	if err != nil {
		return err
	}
	q := url.Values{}
	if *app != "" {
		q.Set("application", *app)
	}
	if *dry {
		q.Set("dryRun", "true")
	}
	resp, err := vexRequest("POST", *server, "/api/v1/vex?"+q.Encode(), *token, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("vex import failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var rep struct {
		Format                                         string
		DryRun                                         bool `json:"dry_run"`
		Statements, Matched, Applied, Unchanged, Stale int
		Rejected, Unmatched                            []struct{ Vulnerability, Reason string }
		Failed                                         []struct{ ID, Error string }
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return fmt.Errorf("failed to decode the response: %w", err)
	}
	verb := "applied"
	if rep.DryRun {
		verb = "would apply"
	}
	_, _ = fmt.Fprintf(stdout, "%s: %d statements, %d findings matched: %s %d, unchanged %d, newer decision kept %d\n",
		rep.Format, rep.Statements, rep.Matched, verb, rep.Applied, rep.Unchanged, rep.Stale)
	for _, r := range rep.Rejected {
		_, _ = fmt.Fprintf(stdout, "  rejected %s: %s\n", r.Vulnerability, r.Reason)
	}
	for _, r := range rep.Unmatched {
		_, _ = fmt.Fprintf(stdout, "  no finding for %s\n", r.Vulnerability)
	}
	for _, f := range rep.Failed {
		_, _ = fmt.Fprintf(stdout, "  refused %s: %s\n", f.ID, f.Error)
	}
	if len(rep.Failed) > 0 {
		return fmt.Errorf("%d findings could not be decided", len(rep.Failed))
	}
	return nil
}
