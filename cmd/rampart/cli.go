package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rampart/internal/auth"
	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/graph"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
	"rampart/internal/store"
	"rampart/internal/version"
)

// Version is the build version (set with -ldflags -X rampart/internal/version.Version).
var Version = version.Version

const (
	ExitSuccess     = 0
	ExitGateFailed  = 1
	ExitUsageError  = 2
	ExitServerError = 3
)

func handleCLI(args []string) (bool, error) {
	if len(args) == 0 {
		return false, nil
	}

	cmd := args[0]
	if strings.HasPrefix(cmd, "-") {
		return false, nil // Normal flag for target server runner
	}

	switch cmd {
	case "version":
		fmt.Printf("Rampart ASPM Platform v%s (Phase 1 Ingest Core)\n", Version)
		return true, nil

	case "login":
		return true, runLogin(args[1:])

	case "upload":
		return true, runUpload(args[1:])

	case "sbom":
		return true, runSBOM(args[1:])

	case "gate":
		return true, runGate(args[1:])

	case "vex":
		return true, runVEX(args[1:], os.Stdout)

	case "apply":
		return true, runApply(args[1:])

	case "migrate":
		return true, runMigrate(args[1:])

	case "admin":
		return true, runAdmin(args[1:], os.Stdin)

	default:
		return false, fmt.Errorf("unknown command %q", cmd)
	}
}

func runLogin(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	token := fs.String("token", "", "API token for authentication")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *token == "" {
		return fmt.Errorf("login: --token is required in Phase 1 (D8, D11)")
	}

	// In a real CLI, store in ~/.rampart/config.json
	homeDir, _ := os.UserHomeDir()
	cfgDir := filepath.Join(homeDir, ".rampart")
	_ = os.MkdirAll(cfgDir, 0700)
	cfgPath := filepath.Join(cfgDir, "credentials.json")

	creds := map[string]string{
		"server": *server,
		"token":  *token,
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	_ = os.WriteFile(cfgPath, data, 0600)

	fmt.Printf("Successfully logged into Rampart server at %s\n", *server)
	return nil
}

func runUpload(args []string) error {
	fs := flag.NewFlagSet("upload", flag.ContinueOnError)
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	source := fs.String("source", "", "Scan source ID")
	ci := detectCI()
	track := fs.String("track", "", "Track or branch (default: the CI branch, else main)")
	branch := fs.String("branch", "", "Branch or ref; a pull request ref makes the run ephemeral (D10)")
	commit := fs.String("commit", ci.Commit, "Commit the report is for (default: from the CI environment)")
	repository := fs.String("repository", ci.Repository, "Repository, for example github.com/acme/shop")
	imageRef := fs.String("image-ref", "", "Container image reference")
	imageDigest := fs.String("image-digest", "", "Container image digest")
	environment := fs.String("environment", "", "Environment, for example production")
	scanner := fs.String("scanner", "", "Scanner name when the report does not say")
	format := fs.String("format", "", "Report format hint")
	buildID := fs.String("build-id", ci.BuildID, "Build id")
	pipelineURL := fs.String("pipeline-url", ci.PipelineURL, "Pipeline URL")
	token := fs.String("token", "", "API token")

	files, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}

	if len(files) < 1 {
		return fmt.Errorf("usage: rampart upload <file> [--source <id>] [--server <url>]")
	}

	filePath := files[0]
	fileData, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read report file: %w", err)
	}

	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	if *source != "" {
		_ = w.WriteField("source", *source)
	}
	ref := firstNonEmptyCLI(*branch, *track, ci.Ref, "main")
	_ = w.WriteField("branch", ref)
	for k, v := range map[string]string{"commit": *commit, "repository": *repository, "imageRef": *imageRef, "imageDigest": *imageDigest,
		"environment": *environment, "scanner": *scanner, "format": *format, "buildId": *buildID, "pipelineUrl": *pipelineURL} {
		if v != "" {
			_ = w.WriteField(k, v)
		}
	}

	part, err := w.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return err
	}
	if _, err := part.Write(fileData); err != nil {
		return err
	}
	_ = w.Close()

	uploadURL := strings.TrimRight(*server, "/") + "/ingest/v1/reports"
	req, err := http.NewRequest("POST", uploadURL, &b)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	if tok := resolveToken(*token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("upload failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		IngestRunID string `json:"ingestRunId"`
		Status      string `json:"status"`
		Staged      int    `json:"staged"`
		Created     int    `json:"created"`
		Updated     int    `json:"updated"`
		Closed      int    `json:"closed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)

	fmt.Printf("Report uploaded successfully!\n  Run ID:  %s\n  Status:  %s\n  Staged:  %d\n  Created: %d\n  Updated: %d\n  Closed:  %d\n",
		res.IngestRunID, res.Status, res.Staged, res.Created, res.Updated, res.Closed)
	return nil
}

func runSBOM(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: rampart sbom <upload|graph|path> [args...]")
	}

	sub := args[0]
	switch sub {
	case "upload":
		return runSBOMUpload(args[1:])
	case "graph":
		return runSBOMGraph(args[1:])
	case "path":
		return runSBOMPath(args[1:])
	default:
		return fmt.Errorf("unknown sbom subcommand %q, expected 'upload', 'graph', or 'path'", sub)
	}
}

func runSBOMUpload(args []string) error {
	fs := flag.NewFlagSet("sbom upload", flag.ContinueOnError)
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	source := fs.String("source", "", "Scan source ID")
	token := fs.String("token", "", "API token")

	files, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}

	if len(files) < 1 {
		return fmt.Errorf("usage: rampart sbom upload <file>")
	}

	filePath := files[0]
	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	url := strings.TrimRight(*server, "/") + "/ingest/v1/sbom"
	if *source != "" {
		url += "?source=" + *source
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	if tok := resolveToken(*token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sbom upload failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	var res struct {
		IngestRunID    string `json:"ingestRunId"`
		ComponentCount int    `json:"componentCount"`
		Created        int    `json:"created"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)

	fmt.Printf("SBOM uploaded successfully!\n  Run ID:     %s\n  Components: %d\n  Findings:   %d\n",
		res.IngestRunID, res.ComponentCount, res.Created)
	return nil
}

func runSBOMGraph(args []string) error {
	fs := flag.NewFlagSet("sbom graph", flag.ContinueOnError)
	viewFormat := fs.String("format", "all", "Output format: tree, mermaid, or all")

	files, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}
	if len(files) < 1 {
		return fmt.Errorf("usage: rampart sbom graph <file> [--format <tree|mermaid|all>]")
	}

	sbom, comps, g, err := parseLocalSBOM(files[0])
	if err != nil {
		return err
	}

	directCount := 0
	transitiveCount := 0
	for _, c := range comps {
		if c.Direct {
			directCount++
		} else {
			transitiveCount++
		}
	}

	fmt.Printf("=== SBOM Dependency Graph ===\n")
	fmt.Printf("Format:               %s (version %s)\n", sbom.Format, sbom.SpecVersion)
	fmt.Printf("Root Component:       %s\n", sbom.RootComponent)
	fmt.Printf("Total Components:     %d\n", len(comps))
	fmt.Printf("Direct Dependencies:  %d\n", directCount)
	fmt.Printf("Transitive Deps:      %d\n", transitiveCount)
	fmt.Printf("Total Edges:          %d\n\n", len(sbom.Dependencies))

	if *viewFormat == "all" || *viewFormat == "tree" {
		fmt.Printf("--- Hierarchy Tree ---\n")
		fmt.Println(g.RenderTextTree())
	}

	if *viewFormat == "all" || *viewFormat == "mermaid" {
		fmt.Printf("--- Mermaid Flowchart ---\n")
		fmt.Println(g.RenderMermaid())
	}

	return nil
}

func runSBOMPath(args []string) error {
	fs := flag.NewFlagSet("sbom path", flag.ContinueOnError)
	target := fs.String("target", "", "Target component identifier (PURL or Name)")

	files, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}
	if len(files) < 1 || *target == "" {
		return fmt.Errorf("usage: rampart sbom path <file> --target <purl-or-name>")
	}

	_, _, g, err := parseLocalSBOM(files[0])
	if err != nil {
		return err
	}

	path := g.FindShortestPath(*target)
	if path == nil {
		return fmt.Errorf("no path found to %q from root %q", *target, g.RootRef)
	}

	fmt.Printf("Path from root [%s] to [%s] (depth %d):\n", g.RootRef, *target, len(path)-1)
	for i, node := range path {
		indent := strings.Repeat("  ", i)
		if i == 0 {
			fmt.Printf("%s└─ (root) %s\n", indent, node)
		} else if i == len(path)-1 {
			fmt.Printf("%s└─ (target) %s\n", indent, node)
		} else {
			fmt.Printf("%s└─ %s\n", indent, node)
		}
	}

	return nil
}

func parseLocalSBOM(filePath string) (*domain.SBOM, []domain.SBOMComponent, *graph.DependencyGraph, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to read SBOM file: %w", err)
	}

	head := data
	if len(head) > 2048 {
		head = head[:2048]
	}

	cdxP := cyclonedx.NewParser()
	spdxP := spdx.NewParser()
	syftP := syft.NewParser()

	scoreCDX := cdxP.Detect(head, filePath, "")
	scoreSPDX := spdxP.Detect(head, filePath, "")
	scoreSyft := syftP.Detect(head, filePath, "")

	if scoreCDX >= scoreSPDX && scoreCDX >= scoreSyft && scoreCDX > 30 {
		return cdxP.ParseSBOM(bytes.NewReader(data))
	} else if scoreSPDX >= scoreSyft && scoreSPDX > 30 {
		return spdxP.ParseSBOM(bytes.NewReader(data))
	} else if scoreSyft > 30 {
		return syftP.ParseSBOM(bytes.NewReader(data))
	}

	// Fallback trial
	if sbom, comps, g, err := cdxP.ParseSBOM(bytes.NewReader(data)); err == nil && len(comps) > 0 {
		return sbom, comps, g, nil
	}
	if sbom, comps, g, err := spdxP.ParseSBOM(bytes.NewReader(data)); err == nil && len(comps) > 0 {
		return sbom, comps, g, nil
	}
	if sbom, comps, g, err := syftP.ParseSBOM(bytes.NewReader(data)); err == nil && len(comps) > 0 {
		return sbom, comps, g, nil
	}

	return nil, nil, nil, fmt.Errorf("unable to detect SBOM format for %s", filePath)
}

func runApply(args []string) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	file := fs.String("f", "", "Path to YAML resource manifest")
	dbURL := fs.String("db-url", "", "PostgreSQL URL to apply resources directly into")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *file == "" {
		return fmt.Errorf("apply: -f <file> is required")
	}

	data, err := os.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("failed to read manifest file: %w", err)
	}

	var configStore apply.ConfigStore
	targetDB := *dbURL
	if targetDB == "" {
		targetDB = os.Getenv("RAMPART_DATABASE_URL")
	}
	if targetDB == "" {
		targetDB = os.Getenv("DATABASE_URL")
	}

	if targetDB != "" {
		pg, err := store.ConnectPostgres(context.Background(), targetDB)
		if err != nil {
			return fmt.Errorf("apply: database connection failed: %w", err)
		}
		defer pg.Close()
		configStore = pg
	} else {
		configStore = apply.NewMemoryConfigStore()
	}

	applier := apply.NewApplier(configStore)
	results, err := applier.ApplyMultiDocument(context.Background(), data)
	if err != nil {
		return fmt.Errorf("apply error: %w", err)
	}

	for _, resultMsg := range results {
		fmt.Printf("Applied configuration successfully: %s\n", resultMsg)
	}
	return nil
}

func runMigrate(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("migrate: subcommand required: 'up' or 'wait'")
	}

	subcmd := args[0]
	switch subcmd {
	case "up":
		fs := flag.NewFlagSet("migrate up", flag.ContinueOnError)
		directURL := fs.String("direct-url", "", "PostgreSQL direct connection URL (rampart_owner)")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		connURL := *directURL
		if connURL == "" {
			connURL = os.Getenv("RAMPART_DATABASE_MIGRATE_URL") // rampart_owner (D4, D30)
		}
		if connURL == "" {
			connURL = os.Getenv("RAMPART_DATABASE_DIRECT_URL")
		}
		if connURL == "" {
			connURL = os.Getenv("DATABASE_DIRECT_URL")
		}
		if connURL == "" {
			connURL = os.Getenv("RAMPART_DATABASE_URL")
		}
		if connURL == "" {
			connURL = os.Getenv("DATABASE_URL")
		}
		if connURL == "" {
			return fmt.Errorf("migrate up: direct PostgreSQL URL is required (via --direct-url or RAMPART_DATABASE_DIRECT_URL)")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()

		if err := store.MigrateUp(ctx, connURL); err != nil {
			return fmt.Errorf("migrate up failed: %w", err)
		}
		fmt.Println("Database schema migrations, River tables, and monthly partitions applied successfully.")
		return nil

	case "wait":
		fs := flag.NewFlagSet("migrate wait", flag.ContinueOnError)
		dbURL := fs.String("db-url", "", "PostgreSQL connection URL to poll")
		minVer := fs.Int64("min-version", 1, "Minimum schema version required")
		timeout := fs.Duration("timeout", 60*time.Second, "Timeout waiting for migrations")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		connURL := *dbURL
		if connURL == "" {
			connURL = os.Getenv("RAMPART_DATABASE_URL")
		}
		if connURL == "" {
			connURL = os.Getenv("DATABASE_URL")
		}
		if connURL == "" {
			connURL = os.Getenv("RAMPART_DATABASE_DIRECT_URL")
		}
		if connURL == "" {
			return fmt.Errorf("migrate wait: database URL is required (via --db-url or RAMPART_DATABASE_URL)")
		}

		ctx, cancel := context.WithTimeout(context.Background(), *timeout+5*time.Second)
		defer cancel()

		if err := store.MigrateWait(ctx, connURL, *minVer, *timeout); err != nil {
			return fmt.Errorf("migrate wait failed: %w", err)
		}
		fmt.Printf("Database schema version >= %d is ready.\n", *minVer)
		return nil

	default:
		return fmt.Errorf("migrate: unknown subcommand %q (valid: up, wait)", subcmd)
	}
}

func runGate(args []string) error {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	ci := detectCI()
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	source := fs.String("source", "", "Scan source (default: the tenant's default source)")
	token := fs.String("token", "", "API token")
	commit := fs.String("commit", ci.Commit, "Commit whose runs the gate evaluates (default: from the CI environment)")
	imageDigest := fs.String("image-digest", "", "Image digest whose runs the gate evaluates")
	expect := fs.String("expect", "", "What the pipeline uploads, comma separated, for example semgrep,trivy,sbom")
	wait := fs.Bool("wait", true, "Wait for the declared runs to finish")
	timeout := fs.Duration("timeout", 5*time.Minute, "How long to wait (at most 30m)")
	failOn := fs.String("fail-on", "critical", "A new or reactivated finding at this severity or above fails the gate: critical | high | medium | low")

	if _, err := parseFlexibleFlags(fs, args); err != nil {
		return err
	}
	if *commit == "" && *imageDigest == "" {
		return fmt.Errorf("--commit or --image-digest is required (it is how the gate finds the runs of this build)")
	}
	var want []string
	for _, e := range strings.Split(*expect, ",") {
		if e = strings.TrimSpace(e); e != "" {
			want = append(want, e)
		}
	}
	if len(want) == 0 {
		return fmt.Errorf("--expect is required: declare what the pipeline uploads, for example --expect semgrep,trivy")
	}

	body, _ := json.Marshal(map[string]any{
		"source": *source, "context": map[string]string{"commit": *commit, "imageDigest": *imageDigest},
		"expect": want, "wait": *wait, "timeoutSeconds": int(timeout.Seconds()), "failOn": *failOn,
	})
	req, err := http.NewRequest("POST", strings.TrimRight(*server, "/")+"/api/v1/gate", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := resolveToken(*token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := (&http.Client{Timeout: *timeout + 30*time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gate request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(b))
	}
	var res struct {
		Pass    bool     `json:"pass"`
		Reasons []string `json:"reasons"`
		Summary struct {
			New, Fixed, Existing int
		} `json:"summary"`
		Blocking []struct {
			Severity string `json:"severity"`
			Title    string `json:"title"`
			Key      string `json:"key"`
			Path     string `json:"path"`
		} `json:"blocking"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("failed to decode the gate response: %w", err)
	}
	fmt.Printf("new %d, fixed %d, existing %d\n", res.Summary.New, res.Summary.Fixed, res.Summary.Existing)
	for _, b := range res.Blocking {
		fmt.Printf("  - [%s] %s %s\n", strings.ToUpper(b.Severity), firstNonEmptyCLI(b.Title, b.Key), b.Path)
	}
	if !res.Pass {
		fmt.Printf("Gate FAILED: %s\n", strings.Join(res.Reasons, "; "))
		return fmt.Errorf("gate failed")
	}
	fmt.Printf("Gate PASSED: %s\n", strings.Join(res.Reasons, "; "))
	return nil
}

// ciInfo is what the CI system already knows about the build.
type ciInfo struct{ Commit, Ref, Repository, BuildID, PipelineURL string }

// detectCI reads GitHub Actions and GitLab CI variables, so a pipeline step needs no flags for them. A pull
// request ref is passed through, which makes the run ephemeral (D10).
func detectCI() ciInfo {
	env := os.Getenv
	switch {
	case env("GITHUB_ACTIONS") == "true":
		ref := env("GITHUB_REF_NAME")
		if strings.HasPrefix(env("GITHUB_REF"), "refs/pull/") {
			ref = env("GITHUB_REF")
		}
		url := ""
		if env("GITHUB_REPOSITORY") != "" && env("GITHUB_RUN_ID") != "" {
			url = env("GITHUB_SERVER_URL") + "/" + env("GITHUB_REPOSITORY") + "/actions/runs/" + env("GITHUB_RUN_ID")
		}
		return ciInfo{env("GITHUB_SHA"), ref, "github.com/" + env("GITHUB_REPOSITORY"), env("GITHUB_RUN_ID"), url}
	case env("GITLAB_CI") == "true":
		ref := env("CI_COMMIT_REF_NAME")
		if env("CI_MERGE_REQUEST_IID") != "" {
			ref = "merge-requests/" + env("CI_MERGE_REQUEST_IID")
		}
		return ciInfo{env("CI_COMMIT_SHA"), ref, strings.TrimPrefix(strings.TrimPrefix(env("CI_PROJECT_URL"), "https://"), "http://"), env("CI_PIPELINE_ID"), env("CI_PIPELINE_URL")}
	}
	return ciInfo{}
}

func firstNonEmptyCLI(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// parseFlexibleFlags separates positional arguments from flags so flags can be passed anywhere.
func parseFlexibleFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var flagArgs []string
	var positional []string

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") {
				flagName := strings.TrimLeft(arg, "-")
				fl := fs.Lookup(flagName)
				if fl != nil {
					if bf, ok := fl.Value.(interface{ IsBoolFlag() bool }); !ok || !bf.IsBoolFlag() {
						if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
							i++
							flagArgs = append(flagArgs, args[i])
						}
					}
				}
			}
		} else {
			positional = append(positional, arg)
		}
	}

	if err := fs.Parse(flagArgs); err != nil {
		return nil, err
	}
	return positional, nil
}

func resolveToken(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if env := os.Getenv("RAMPART_TOKEN"); env != "" {
		return env
	}
	homeDir, _ := os.UserHomeDir()
	cfgPath := filepath.Join(homeDir, ".rampart", "credentials.json")
	if data, err := os.ReadFile(cfgPath); err == nil {
		var creds map[string]string
		if json.Unmarshal(data, &creds) == nil {
			return creds["token"]
		}
	}
	return ""
}

// runAdmin implements `rampart admin set-password`: recovery for the break-glass local administrator
// (D3). It talks to the database directly as rampart_system, so it works when nobody can sign in. The
// new password is read from a file or from standard input, never from the command line (argv shows up
// in process listings and shell history).
func runAdmin(args []string, stdin io.Reader) error {
	if len(args) == 0 || args[0] != "set-password" {
		return fmt.Errorf("admin: subcommand required: 'set-password'")
	}
	fs := flag.NewFlagSet("admin set-password", flag.ContinueOnError)
	tenantSlug := fs.String("tenant", "default", "tenant slug")
	username := fs.String("username", "admin", "local administrator username")
	pwFile := fs.String("password-file", "", "file holding the new password (default: read standard input)")
	dbURL := fs.String("db-system-url", "", "PostgreSQL URL of rampart_system (default: $RAMPART_DATABASE_SYSTEM_URL)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	conn := *dbURL
	if conn == "" {
		conn = os.Getenv("RAMPART_DATABASE_SYSTEM_URL")
	}
	if conn == "" {
		return fmt.Errorf("admin set-password: the rampart_system database URL is required (--db-system-url or RAMPART_DATABASE_SYSTEM_URL)")
	}

	var raw []byte
	var err error
	if *pwFile != "" {
		raw, err = os.ReadFile(*pwFile)
	} else {
		raw, err = io.ReadAll(io.LimitReader(stdin, 4096))
	}
	if err != nil {
		return fmt.Errorf("admin set-password: reading the new password: %w", err)
	}
	password := strings.TrimRight(string(raw), "\r\n")
	if len(password) < auth.MinPasswordLength {
		return auth.ErrWeakPassword
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.ConnectPostgres(ctx, conn)
	if err != nil {
		return fmt.Errorf("admin set-password: %w", err)
	}
	defer st.Close()
	tenant, err := st.GetTenantBySlug(ctx, *tenantSlug)
	if err != nil || tenant == nil {
		return fmt.Errorf("admin set-password: tenant %q not found", *tenantSlug)
	}
	if err := st.SetLocalAdminPassword(ctx, tenant.ID, *username, hash); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fmt.Errorf("admin set-password: there is no local administrator %q in tenant %q; start the server with auth.bootstrapAdmin.passwordFile first", *username, *tenantSlug)
		}
		return err
	}
	fmt.Printf("Password changed for %s in tenant %s. Its sessions were ended and any lock was cleared.\n", *username, *tenantSlug)
	return nil
}
