package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// securityHeaders lists the HTTP response headers checked by DAST-001.
var securityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Frame-Options",
	"X-Content-Type-Options",
}

// checkResult holds the outcome of a single DAST probe.
type checkResult struct {
	RuleID     string
	Severity   pluginv1.Severity
	Confidence pluginv1.Confidence
	Message    string
	CWE        string
	Metadata   map[string]string
}

// newHTTPClient creates a client configured for DAST probing.
// It follows redirects only once (to detect redirect behaviour) and
// has a 10-second overall timeout.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 1 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

// checkMissingHeaders (DAST-001) sends a GET request and reports any
// missing security headers.
func checkMissingHeaders(ctx context.Context, client *http.Client, targetURL string) []checkResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var results []checkResult
	var missing []string
	for _, h := range securityHeaders {
		if resp.Header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if len(missing) > 0 {
		results = append(results, checkResult{
			RuleID:     "DAST-001",
			Severity:   sdk.SeverityHigh,
			Confidence: sdk.ConfidenceHigh,
			Message:    fmt.Sprintf("Missing security headers: %s", strings.Join(missing, ", ")),
			CWE:        "CWE-693",
			Metadata: map[string]string{
				"missing_headers": strings.Join(missing, ","),
				"target_url":      targetURL,
			},
		})
	}
	return results
}

// checkInsecureCORS (DAST-002) sends an OPTIONS request with a foreign
// Origin and checks whether the server responds with a wildcard
// Access-Control-Allow-Origin or reflects credentials with a wildcard.
func checkInsecureCORS(ctx context.Context, client *http.Client, targetURL string) []checkResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, targetURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "GET")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	var results []checkResult
	if acao == "*" {
		msg := "CORS allows wildcard origin (*)"
		if strings.EqualFold(acac, "true") {
			msg = "CORS allows wildcard origin (*) with credentials"
		}
		results = append(results, checkResult{
			RuleID:     "DAST-002",
			Severity:   sdk.SeverityHigh,
			Confidence: sdk.ConfidenceMedium,
			Message:    msg,
			CWE:        "CWE-942",
			Metadata: map[string]string{
				"acao":       acao,
				"acac":       acac,
				"target_url": targetURL,
			},
		})
	} else if acao == "https://evil.example.com" {
		results = append(results, checkResult{
			RuleID:     "DAST-002",
			Severity:   sdk.SeverityHigh,
			Confidence: sdk.ConfidenceHigh,
			Message:    "CORS reflects arbitrary origin",
			CWE:        "CWE-942",
			Metadata: map[string]string{
				"acao":       acao,
				"target_url": targetURL,
			},
		})
	}
	return results
}

// checkMissingTLS (DAST-003) reports when the target URL uses plain HTTP
// instead of HTTPS. For HTTPS targets it performs a TLS handshake to
// verify the certificate chain.
func checkMissingTLS(ctx context.Context, _ *http.Client, targetURL string) []checkResult {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	var results []checkResult
	if parsed.Scheme == "http" {
		results = append(results, checkResult{
			RuleID:     "DAST-003",
			Severity:   sdk.SeverityMedium,
			Confidence: sdk.ConfidenceHigh,
			Message:    "Target uses plain HTTP instead of HTTPS",
			CWE:        "CWE-319",
			Metadata: map[string]string{
				"scheme":     "http",
				"target_url": targetURL,
			},
		})
	} else if parsed.Scheme == "https" {
		host := parsed.Host
		if !strings.Contains(host, ":") {
			host += ":443"
		}
		dialer := tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12}}
		conn, err := dialer.DialContext(ctx, "tcp", host)
		if err != nil {
			results = append(results, checkResult{
				RuleID:     "DAST-003",
				Severity:   sdk.SeverityHigh,
				Confidence: sdk.ConfidenceHigh,
				Message:    fmt.Sprintf("TLS handshake failed: %v", err),
				CWE:        "CWE-319",
				Metadata: map[string]string{
					"error":      err.Error(),
					"target_url": targetURL,
				},
			})
		} else {
			conn.Close()
		}
	}
	return results
}

// checkInsecureCookies (DAST-004) sends a GET request and inspects
// Set-Cookie headers for missing Secure, HttpOnly, or SameSite flags.
func checkInsecureCookies(ctx context.Context, client *http.Client, targetURL string) []checkResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var results []checkResult
	for _, cookie := range resp.Cookies() {
		var issues []string
		if !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}
		if cookie.SameSite == http.SameSiteDefaultMode || cookie.SameSite == 0 {
			issues = append(issues, "missing SameSite attribute")
		}
		if len(issues) > 0 {
			results = append(results, checkResult{
				RuleID:     "DAST-004",
				Severity:   sdk.SeverityHigh,
				Confidence: sdk.ConfidenceMedium,
				Message:    fmt.Sprintf("Cookie %q: %s", cookie.Name, strings.Join(issues, ", ")),
				CWE:        "CWE-614",
				Metadata: map[string]string{
					"cookie_name": cookie.Name,
					"issues":      strings.Join(issues, ","),
					"target_url":  targetURL,
				},
			})
		}
	}
	return results
}

// checkMissingRateLimit (DAST-005) sends a burst of rapid requests and
// checks whether the server responds with 429 or rate-limiting headers.
func checkMissingRateLimit(ctx context.Context, client *http.Client, targetURL string) []checkResult {
	const burstCount = 5

	gotRateLimited := false
	for i := 0; i < burstCount; i++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if err != nil {
			return nil
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode == http.StatusTooManyRequests {
			gotRateLimited = true
			break
		}
		// Check for common rate limit headers.
		if resp.Header.Get("X-RateLimit-Limit") != "" ||
			resp.Header.Get("RateLimit-Limit") != "" ||
			resp.Header.Get("Retry-After") != "" {
			gotRateLimited = true
			break
		}
	}

	if !gotRateLimited {
		return []checkResult{{
			RuleID:     "DAST-005",
			Severity:   sdk.SeverityMedium,
			Confidence: sdk.ConfidenceMedium,
			Message:    fmt.Sprintf("No rate limiting detected after %d rapid requests", burstCount),
			CWE:        "CWE-770",
			Metadata: map[string]string{
				"burst_count": fmt.Sprintf("%d", burstCount),
				"target_url":  targetURL,
			},
		}}
	}
	return nil
}

// checkOpenRedirect (DAST-006) tests common redirect parameters to see
// if the server redirects to an attacker-controlled URL. It uses a
// non-redirecting client to inspect the raw Location header.
func checkOpenRedirect(ctx context.Context, client *http.Client, targetURL string) []checkResult {
	evilURL := "https://evil.example.com"
	params := []string{"redirect", "url", "next", "return_to", "redirect_uri"}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil
	}

	// Build a non-redirecting client that shares the base client's transport.
	noRedirect := &http.Client{
		Transport: client.Transport,
		Timeout:   client.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var results []checkResult
	for _, param := range params {
		q := parsed.Query()
		q.Set(param, evilURL)
		u := *parsed
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			continue
		}

		resp, err := noRedirect.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			location := resp.Header.Get("Location")
			if strings.HasPrefix(location, evilURL) {
				results = append(results, checkResult{
					RuleID:     "DAST-006",
					Severity:   sdk.SeverityHigh,
					Confidence: sdk.ConfidenceHigh,
					Message:    fmt.Sprintf("Open redirect via %q parameter", param),
					CWE:        "CWE-601",
					Metadata: map[string]string{
						"param":      param,
						"location":   location,
						"target_url": targetURL,
					},
				})
			}
		}
	}
	return results
}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/dast", version).
		Capability("dast", "Dynamic application security testing against live HTTP targets").
		Tool("scan", "Probe a target URL for security misconfigurations (headers, CORS, TLS, cookies, rate limiting, redirects)", true).
		Done().
		Safety(
			sdk.WithRiskClass(sdk.RiskActive),
			sdk.WithNeedsConfirmation(),
			sdk.WithNetworkHosts("*"),
		).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("scan", handleScan)
}

func handleScan(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	targetURL := req.InputString("target_url")
	if targetURL == "" {
		resp := sdk.NewResponse()
		return resp.Build(), nil
	}

	// Ensure the URL has a scheme.
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	client := newHTTPClient()
	resp := sdk.NewResponse()

	checks := []func(context.Context, *http.Client, string) []checkResult{
		checkMissingHeaders,
		checkInsecureCORS,
		checkMissingTLS,
		checkInsecureCookies,
		checkMissingRateLimit,
		checkOpenRedirect,
	}

	for _, check := range checks {
		for _, r := range check(ctx, client, targetURL) {
			fb := resp.Finding(r.RuleID, r.Severity, r.Confidence, r.Message).
				WithMetadata("cwe", r.CWE)
			for k, v := range r.Metadata {
				fb.WithMetadata(k, v)
			}
			fb.Done()
		}
	}

	return resp.Build(), nil
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
