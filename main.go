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

// dastRule defines a single DAST detection rule with compiled regex patterns
// keyed by file extension.
type dastRule struct {
	ID         string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	CWE        string
	Patterns   map[string][]*regexp.Regexp // extension -> compiled patterns
}

// Compiled regex patterns for each rule, grouped by language extension.
//
// DAST-001: Missing security headers in server response configuration.
// DAST-002: Insecure CORS configuration allowing wildcard or credentials with wildcard.
// DAST-003: Missing TLS/HTTPS enforcement (http:// URLs, disabled cert verification).
// DAST-004: Insecure cookie settings (missing Secure, HttpOnly, SameSite flags).
// DAST-005: Missing rate limiting on API endpoints.
// DAST-006: Open redirect patterns (user input in redirect URLs).
var rules = []dastRule{
	{
		ID:         "DAST-001",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Missing security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)",
		CWE:        "CWE-693",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)w\.Header\(\)\.Set\s*\(\s*["'](?:Content-Type)["']`),
				regexp.MustCompile(`(?i)\.WriteHeader\s*\(`),
				regexp.MustCompile(`(?i)http\.ListenAndServe\(`),
			},
			".py": {
				regexp.MustCompile(`(?i)response\s*=\s*(?:HttpResponse|JsonResponse|make_response)\(`),
				regexp.MustCompile(`(?i)return\s+(?:HttpResponse|JsonResponse)\(`),
				regexp.MustCompile(`(?i)@app\.(?:route|after_request)`),
			},
			".js": {
				regexp.MustCompile(`(?i)res\.(?:send|json|render|write)\s*\(`),
				regexp.MustCompile(`(?i)app\.listen\s*\(`),
			},
			".ts": {
				regexp.MustCompile(`(?i)res\.(?:send|json|render|write)\s*\(`),
				regexp.MustCompile(`(?i)app\.listen\s*\(`),
			},
		},
	},
	{
		ID:         "DAST-002",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Insecure CORS configuration",
		CWE:        "CWE-942",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)Access-Control-Allow-Origin["'],?\s*["']\*["']`),
				regexp.MustCompile(`(?i)AllowAllOrigins\s*:\s*true`),
				regexp.MustCompile(`(?i)AllowOrigins.*\*`),
			},
			".py": {
				regexp.MustCompile(`(?i)CORS_ALLOW_ALL_ORIGINS\s*=\s*True`),
				regexp.MustCompile(`(?i)Access-Control-Allow-Origin.*\*`),
				regexp.MustCompile(`(?i)CORS\s*\(\s*app\s*,\s*resources.*origins.*\*`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:cors|access-control-allow-origin).*\*`),
				regexp.MustCompile(`(?i)origin\s*:\s*(?:true|['"]?\*['"]?)`),
				regexp.MustCompile(`(?i)credentials\s*:\s*true.*origin\s*:\s*true`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:cors|access-control-allow-origin).*\*`),
				regexp.MustCompile(`(?i)origin\s*:\s*(?:true|['"]?\*['"]?)`),
				regexp.MustCompile(`(?i)credentials\s*:\s*true.*origin\s*:\s*true`),
			},
		},
	},
	{
		ID:         "DAST-003",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Missing TLS/HTTPS enforcement",
		CWE:        "CWE-319",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`http\.ListenAndServe\(`),
				regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`),
				regexp.MustCompile(`["']http://[^"']+["']`),
			},
			".py": {
				regexp.MustCompile(`verify\s*=\s*False`),
				regexp.MustCompile(`["']http://[^"']+["']`),
				regexp.MustCompile(`SECURE_SSL_REDIRECT\s*=\s*False`),
			},
			".js": {
				regexp.MustCompile(`rejectUnauthorized\s*:\s*false`),
				regexp.MustCompile(`["']http://[^"']+["']`),
				regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED.*["']0["']`),
			},
			".ts": {
				regexp.MustCompile(`rejectUnauthorized\s*:\s*false`),
				regexp.MustCompile(`["']http://[^"']+["']`),
				regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED.*["']0["']`),
			},
		},
	},
	{
		ID:         "DAST-004",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Insecure cookie settings (missing Secure, HttpOnly, or SameSite flags)",
		CWE:        "CWE-614",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`http\.Cookie\s*\{`),
				regexp.MustCompile(`Secure\s*:\s*false`),
				regexp.MustCompile(`HttpOnly\s*:\s*false`),
				regexp.MustCompile(`(?i)\.SetCookie\(`),
			},
			".py": {
				regexp.MustCompile(`(?i)set_cookie\s*\(`),
				regexp.MustCompile(`(?i)SESSION_COOKIE_SECURE\s*=\s*False`),
				regexp.MustCompile(`(?i)SESSION_COOKIE_HTTPONLY\s*=\s*False`),
				regexp.MustCompile(`(?i)httponly\s*=\s*False`),
			},
			".js": {
				regexp.MustCompile(`(?i)res\.cookie\s*\(`),
				regexp.MustCompile(`(?i)secure\s*:\s*false`),
				regexp.MustCompile(`(?i)httpOnly\s*:\s*false`),
				regexp.MustCompile(`(?i)document\.cookie\s*=`),
			},
			".ts": {
				regexp.MustCompile(`(?i)res\.cookie\s*\(`),
				regexp.MustCompile(`(?i)secure\s*:\s*false`),
				regexp.MustCompile(`(?i)httpOnly\s*:\s*false`),
				regexp.MustCompile(`(?i)document\.cookie\s*=`),
			},
		},
	},
	{
		ID:         "DAST-005",
		Severity:   sdk.SeverityMedium,
		Confidence: sdk.ConfidenceMedium,
		Message:    "Missing rate limiting on API endpoint",
		CWE:        "CWE-770",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`(?i)http\.HandleFunc\s*\(\s*["']/api/`),
				regexp.MustCompile(`(?i)\.(?:GET|POST|PUT|DELETE|PATCH)\s*\(\s*["']/api/`),
				regexp.MustCompile(`(?i)r\.Route\s*\(\s*["']/api/`),
			},
			".py": {
				regexp.MustCompile(`(?i)@app\.(?:route|get|post|put|delete)\s*\(\s*["']/api/`),
				regexp.MustCompile(`(?i)path\s*\(\s*["']api/`),
				regexp.MustCompile(`(?i)@router\.(?:get|post|put|delete)\s*\(\s*["']/api/`),
			},
			".js": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/api\/`),
			},
			".ts": {
				regexp.MustCompile(`(?i)(?:app|router)\.(?:get|post|put|delete|patch)\s*\(\s*['"]\/api\/`),
			},
		},
	},
	{
		ID:         "DAST-006",
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceHigh,
		Message:    "Open redirect: user input used in redirect URL",
		CWE:        "CWE-601",
		Patterns: map[string][]*regexp.Regexp{
			".go": {
				regexp.MustCompile(`http\.Redirect\s*\(.*r\.(URL|Form|FormValue|Query)`),
				regexp.MustCompile(`http\.Redirect\s*\(.*req\.(URL|Form|FormValue|Query)`),
			},
			".py": {
				regexp.MustCompile(`redirect\s*\(\s*request\.(GET|POST|args|form)`),
				regexp.MustCompile(`HttpResponseRedirect\s*\(\s*request\.(GET|POST|args|form)`),
			},
			".js": {
				regexp.MustCompile(`res\.redirect\s*\(\s*req\.(query|body|params)`),
			},
			".ts": {
				regexp.MustCompile(`res\.redirect\s*\(\s*req\.(query|body|params)`),
			},
		},
	},
}

// mitigationCheck allows suppressing findings when a mitigation pattern is present
// in the same file.
type mitigationCheck struct {
	RuleID  string
	Pattern *regexp.Regexp
}

// mitigations are file-wide patterns that indicate a security control is in place.
var mitigations = []mitigationCheck{
	{"DAST-001", regexp.MustCompile(`(?i)(?:Content-Security-Policy|Strict-Transport-Security|X-Frame-Options|X-Content-Type-Options|helmet)`)},
	{"DAST-005", regexp.MustCompile(`(?i)(?:rate_limit|ratelimit|throttle|limiter|RateLimiter|slowDown)`)},
}

// supportedExtensions lists file extensions that the DAST scanner processes.
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
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/dast", version).
		Capability("dast", "Detect web/API security misconfigurations in server code").
		Tool("scan", "Scan source files for missing security headers, CORS issues, TLS gaps, cookie flaws, rate limiting, and open redirects", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskActive), sdk.WithNeedsConfirmation()).
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

		return scanFile(ctx, resp, path, ext)
	})
	if err != nil && err != context.Canceled {
		return nil, fmt.Errorf("walking workspace: %w", err)
	}

	return resp.Build(), nil
}

// scanFile reads a file and checks each line against all DAST rules.
// Mitigations found anywhere in the file suppress associated findings.
func scanFile(_ context.Context, resp *sdk.ResponseBuilder, filePath, ext string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	fullContent := strings.Join(lines, "\n")

	// Determine which rules have mitigations present in this file.
	mitigated := make(map[string]bool)
	for _, m := range mitigations {
		if m.Pattern.MatchString(fullContent) {
			mitigated[m.RuleID] = true
		}
	}

	for lineNum, line := range lines {
		for i := range rules {
			rule := &rules[i]
			patterns, ok := rule.Patterns[ext]
			if !ok {
				continue
			}

			matched := false
			for _, pattern := range patterns {
				if pattern.MatchString(line) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			if mitigated[rule.ID] {
				continue
			}

			resp.Finding(
				rule.ID,
				rule.Severity,
				rule.Confidence,
				fmt.Sprintf("%s: %s", rule.Message, strings.TrimSpace(line)),
			).
				At(filePath, lineNum+1, lineNum+1).
				WithMetadata("cwe", rule.CWE).
				WithMetadata("language", extToLanguage(ext)).
				Done()
		}
	}

	return nil
}

// extToLanguage maps file extensions to human-readable language names.
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
		fmt.Fprintf(os.Stderr, "nox-plugin-dast: %v\n", err)
		os.Exit(1)
	}
}
