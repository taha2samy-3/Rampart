package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rampart/internal/config/apply"
	"rampart/internal/domain"
	"rampart/internal/graph"
	"rampart/internal/parsers/cyclonedx"
	"rampart/internal/parsers/spdx"
	"rampart/internal/parsers/syft"
	"rampart/internal/store"
)

const (
	Version         = "0.1.0-phase1"
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

	case "apply":
		return true, runApply(args[1:])

	case "migrate":
		return true, runMigrate(args[1:])

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
	track := fs.String("track", "main", "Track or branch")
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
	_ = w.WriteField("track", *track)

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
	server := fs.String("server", "http://localhost:8080", "Rampart server URL")
	source := fs.String("source", "", "Scan source ID")
	token := fs.String("token", "", "API token")
	failOn := fs.String("fail-on", "critical", "Fail threshold severity: critical | high | medium | low")

	_, err := parseFlexibleFlags(fs, args)
	if err != nil {
		return err
	}

	url := strings.TrimRight(*server, "/") + "/api/v1/findings?q=state:open,affected,under_investigation"
	if *source != "" {
		url += " source:" + *source
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if tok := resolveToken(*token); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gate check request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server error (%d): %s", resp.StatusCode, string(body))
	}

	var listRes struct {
		Items []struct {
			Finding struct {
				ID       string `json:"id"`
				RuleID   string `json:"rule_id"`
				Title    string `json:"title"`
				Severity string `json:"severity"`
			} `json:"finding"`
		} `json:"items"`
		Total int `json:"total"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&listRes); err != nil {
		return fmt.Errorf("failed to decode gate response: %w", err)
	}

	failRank := severityRank(*failOn)
	var blocking []string

	for _, item := range listRes.Items {
		if severityRank(item.Finding.Severity) >= failRank {
			blocking = append(blocking, fmt.Sprintf("[%s] %s: %s (%s)",
				strings.ToUpper(item.Finding.Severity), item.Finding.RuleID, item.Finding.Title, item.Finding.ID))
		}
	}

	if len(blocking) > 0 {
		fmt.Printf("CI Gate FAILED! Found %d blocking finding(s) with severity >= %s:\n", len(blocking), *failOn)
		for _, b := range blocking {
			fmt.Printf("  - %s\n", b)
		}
		return fmt.Errorf("gate check failed: %d blocking issues", len(blocking))
	}

	fmt.Printf("CI Gate PASSED: 0 blocking findings (fail threshold: %s)\n", *failOn)
	return nil
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 50
	case "high":
		return 40
	case "medium":
		return 30
	case "low":
		return 20
	case "info":
		return 10
	default:
		return 0
	}
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
