package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// triageRule defines a single triage classification rule with compiled regex patterns.
type triageRule struct {
	ID         string
	Desc       string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Priority   string
	Patterns   map[string]*regexp.Regexp // extension -> compiled regex
}

// Compiled regex patterns for each triage rule.
var rules = []triageRule{
	{
		ID:         "TRIAGE-001",
		Desc:       "Critical security pattern requiring immediate review: dangerous code execution with user input",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceHigh,
		Priority:   "immediate",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(exec\.Command\(.*\+|os\.Exec|syscall\.Exec)`),
			".py": regexp.MustCompile(`(?i)(eval\(|exec\(|os\.system\(|subprocess\.call\(.*shell\s*=\s*True|__import__\()`),
			".js": regexp.MustCompile(`(?i)(eval\(|new\s+Function\(|child_process\.\w+\(|vm\.runInNewContext)`),
			".ts": regexp.MustCompile(`(?i)(eval\(|new\s+Function\(|child_process\.\w+\(|vm\.runInNewContext)`),
		},
	},
	{
		ID:         "TRIAGE-002",
		Desc:       "High-priority pattern for scheduled review: missing input validation on external data",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceHigh,
		Priority:   "scheduled",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(r\.URL\.Query\(\)\.Get\(|r\.FormValue\(|r\.Body|json\.Unmarshal\(.*req)`),
			".py": regexp.MustCompile(`(?i)(request\.(args|form|json|data|values)\[|request\.get_json\(|flask\.request\.(args|form))`),
			".js": regexp.MustCompile(`(?i)(req\.(body|query|params)\[|req\.(body|query|params)\.\w+)`),
			".ts": regexp.MustCompile(`(?i)(req\.(body|query|params)\[|req\.(body|query|params)\.\w+)`),
		},
	},
	{
		ID:         "TRIAGE-003",
		Desc:       "Low-priority hygiene pattern: deprecated API usage or security-related TODO comments",
		Severity:   sdk.SeverityLow,
		Confidence: sdk.ConfidenceMedium,
		Priority:   "backlog",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(//\s*(TODO|FIXME|HACK|XXX)\s*.*secur|ioutil\.|crypto/md5|crypto/sha1|crypto/des)`),
			".py": regexp.MustCompile(`(?i)(#\s*(TODO|FIXME|HACK|XXX)\s*.*secur|import\s+md5|import\s+sha\b|hashlib\.md5)`),
			".js": regexp.MustCompile(`(?i)(//\s*(TODO|FIXME|HACK|XXX)\s*.*secur|document\.write\(|escape\(|unescape\()`),
			".ts": regexp.MustCompile(`(?i)(//\s*(TODO|FIXME|HACK|XXX)\s*.*secur|document\.write\(|escape\(|unescape\()`),
		},
	},
	{
		ID:         "TRIAGE-004",
		Desc:       "Informational pattern for context: security-relevant code areas for review",
		Severity:   sdk.SeverityInfo,
		Confidence: sdk.ConfidenceHigh,
		Priority:   "informational",
		Patterns: map[string]*regexp.Regexp{
			".go": regexp.MustCompile(`(?i)(crypto\.|tls\.|x509\.|net/http\.Handle|middleware|jwt\.|bcrypt\.|oauth)`),
			".py": regexp.MustCompile(`(?i)(cryptography\.|hashlib\.|hmac\.|ssl\.|jwt\.|bcrypt\.|passlib\.|oauth)`),
			".js": regexp.MustCompile(`(?i)(crypto\.|jsonwebtoken|bcrypt|passport|helmet|cors|csrf|oauth)`),
			".ts": regexp.MustCompile(`(?i)(crypto\.|jsonwebtoken|bcrypt|passport|helmet|cors|csrf|oauth)`),
		},
	},
}

// supportedExtensions lists file extensions that the triage scanner processes.
var supportedExtensions = map[string]bool{
	".go": true,
	".py": true,
	".js": true,
	".ts": true,
}

// skippedDirs contains directory names to skip during recursive walks.
var skippedDirs = map[string]bool{
	".git":         true,
	"vendor":       true,
	"node_modules": true,
	"__pycache__":  true,
	".venv":        true,
	"dist":         true,
	"build":        true,
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/triage-agent", version).
		Capability("triage-agent", "Prioritizes and classifies code patterns for security review").
		Tool("scan", "Scan source files to triage and prioritize security patterns for review", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	workspaceRoot, _ := req.Input["workspace_root"].(string)
	if workspaceRoot == "" {
		workspaceRoot = req.WorkspaceRoot
	}

	resp := sdk.NewResponse()

	if workspaceRoot == "" {
		return resp.Build(), nil
	}

	err := filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		ext := filepath.Ext(path)
		if !supportedExtensions[ext] {
			return nil
		}

		return scanFile(resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

func scanFile(resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for i := range rules {
			rule := &rules[i]
			pattern, ok := rule.Patterns[ext]
			if !ok {
				continue
			}
			if pattern.MatchString(line) {
				resp.Finding(
					rule.ID,
					rule.Severity,
					rule.Confidence,
					fmt.Sprintf("%s: %s", rule.Desc, strings.TrimSpace(line)),
				).
					At(filePath, lineNum, lineNum).
					WithMetadata("priority", rule.Priority).
					WithMetadata("language", extToLanguage(ext)).
					Done()
			}
		}
	}

	return scanner.Err()
}

func extToLanguage(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".js":
		return "javascript"
	case ".ts":
		return "typescript"
	default:
		return "unknown"
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-triage-agent: %v\n", err)
		os.Exit(1)
	}
}
