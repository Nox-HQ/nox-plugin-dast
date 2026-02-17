package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackDynamicRuntime)
}

// --- DAST-001: Missing Security Headers ---

func TestDAST001_MissingHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingHeaders(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-001 finding for server with no security headers")
	}
	r := results[0]
	if r.RuleID != "DAST-001" {
		t.Errorf("rule = %q, want DAST-001", r.RuleID)
	}
	if r.CWE != "CWE-693" {
		t.Errorf("CWE = %q, want CWE-693", r.CWE)
	}
}

func TestDAST001_AllHeadersPresent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingHeaders(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings when all security headers present, got %d", len(results))
	}
}

// --- DAST-002: Insecure CORS ---

func TestDAST002_WildcardOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCORS(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-002 for wildcard CORS origin")
	}
	if results[0].CWE != "CWE-942" {
		t.Errorf("CWE = %q, want CWE-942", results[0].CWE)
	}
}

func TestDAST002_ReflectedOrigin(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCORS(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-002 for reflected CORS origin")
	}
	if results[0].Message != "CORS reflects arbitrary origin" {
		t.Errorf("message = %q, want 'CORS reflects arbitrary origin'", results[0].Message)
	}
}

func TestDAST002_SafeCORS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCORS(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings for safe CORS, got %d", len(results))
	}
}

// --- DAST-003: Missing TLS ---

func TestDAST003_PlainHTTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// httptest.NewServer uses http://, so this should trigger DAST-003.
	results := checkMissingTLS(context.Background(), nil, ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-003 for plain HTTP target")
	}
	if results[0].CWE != "CWE-319" {
		t.Errorf("CWE = %q, want CWE-319", results[0].CWE)
	}
}

func TestDAST003_ValidTLS(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// httptest.NewTLSServer uses a self-signed cert, which will fail our
	// strict TLS check. This validates the detection works.
	results := checkMissingTLS(context.Background(), nil, ts.URL)
	// The self-signed cert should cause a TLS handshake failure.
	if len(results) == 0 {
		t.Fatal("expected DAST-003 for self-signed TLS cert")
	}
}

// --- DAST-004: Insecure Cookies ---

func TestDAST004_InsecureCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:  "session",
			Value: "abc123",
			// Missing Secure, HttpOnly, SameSite
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCookies(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-004 for cookie without Secure/HttpOnly/SameSite")
	}
	if results[0].CWE != "CWE-614" {
		t.Errorf("CWE = %q, want CWE-614", results[0].CWE)
	}
	if results[0].Metadata["cookie_name"] != "session" {
		t.Errorf("cookie_name = %q, want session", results[0].Metadata["cookie_name"])
	}
}

func TestDAST004_SecureCookie(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    "abc123",
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCookies(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings for secure cookie, got %d", len(results))
	}
}

func TestDAST004_NoCookies(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCookies(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings when no cookies, got %d", len(results))
	}
}

// --- DAST-005: Missing Rate Limiting ---

func TestDAST005_NoRateLimit(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingRateLimit(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-005 for server without rate limiting")
	}
	if results[0].CWE != "CWE-770" {
		t.Errorf("CWE = %q, want CWE-770", results[0].CWE)
	}
}

func TestDAST005_WithRateLimit429(t *testing.T) {
	count := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		count++
		if count > 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingRateLimit(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings when rate limiting responds with 429, got %d", len(results))
	}
}

func TestDAST005_WithRateLimitHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingRateLimit(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings when rate limit headers present, got %d", len(results))
	}
}

// --- DAST-006: Open Redirect ---

func TestDAST006_OpenRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if redir := r.URL.Query().Get("redirect"); redir != "" {
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkOpenRedirect(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-006 for open redirect via 'redirect' param")
	}
	if results[0].CWE != "CWE-601" {
		t.Errorf("CWE = %q, want CWE-601", results[0].CWE)
	}
	if results[0].Metadata["param"] != "redirect" {
		t.Errorf("param = %q, want redirect", results[0].Metadata["param"])
	}
}

func TestDAST006_SafeRedirect(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkOpenRedirect(context.Background(), ts.Client(), ts.URL)
	if len(results) != 0 {
		t.Errorf("expected 0 findings for safe server, got %d", len(results))
	}
}

// --- Integration: Full scan via gRPC ---

func TestScanIntegration_VulnerableServer(t *testing.T) {
	// Set up a vulnerable test server.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No security headers (DAST-001)
		// Wildcard CORS (DAST-002)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// Insecure cookie (DAST-004)
		http.SetCookie(w, &http.Cookie{Name: "token", Value: "secret"})
		// Open redirect (DAST-006)
		if redir := r.URL.Query().Get("redirect"); redir != "" {
			http.Redirect(w, r, redir, http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := testClient(t)
	resp := invokeScan(t, client, ts.URL)

	findings := resp.GetFindings()
	if len(findings) == 0 {
		t.Fatal("expected findings from vulnerable server")
	}

	// Verify we got at least some of the expected rules.
	ruleIDs := make(map[string]bool)
	for _, f := range findings {
		ruleIDs[f.GetRuleId()] = true
	}

	// DAST-001 (missing headers), DAST-003 (plain HTTP), DAST-004 (insecure cookie),
	// DAST-005 (no rate limit) should all fire. DAST-002 fires on OPTIONS.
	// DAST-006 fires with redirect param.
	for _, want := range []string{"DAST-001", "DAST-003", "DAST-004", "DAST-005"} {
		if !ruleIDs[want] {
			t.Errorf("expected %s finding but not found (got %v)", want, ruleIDs)
		}
	}
}

func TestScanIntegration_SecureServer(t *testing.T) {
	reqCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reqCount++
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
		w.Header().Set("X-RateLimit-Limit", "100")
		http.SetCookie(w, &http.Cookie{
			Name: "session", Value: "v",
			Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	client := testClient(t)
	resp := invokeScan(t, client, ts.URL)

	// Should still get DAST-003 (plain HTTP from httptest) but fewer overall.
	for _, f := range resp.GetFindings() {
		if f.GetRuleId() == "DAST-001" {
			t.Error("secure server should not trigger DAST-001")
		}
		if f.GetRuleId() == "DAST-004" {
			t.Error("secure server should not trigger DAST-004")
		}
	}
}

func TestScanNoTarget(t *testing.T) {
	client := testClient(t)

	input, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected 0 findings without target_url, got %d", len(resp.GetFindings()))
	}
}

// --- Domain logic unit tests ---

func TestNewHTTPClient(t *testing.T) {
	client := newHTTPClient()
	if client == nil {
		t.Fatal("expected non-nil client")
	}
	if client.Timeout == 0 {
		t.Error("expected non-zero timeout")
	}
}

func TestCheckMissingHeaders_PartialHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkMissingHeaders(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected finding for partially missing headers")
	}
	// Should report CSP and HSTS as missing.
	meta := results[0].Metadata["missing_headers"]
	if meta == "" {
		t.Error("expected missing_headers metadata")
	}
	for _, h := range []string{"Content-Security-Policy", "Strict-Transport-Security"} {
		if !contains(meta, h) {
			t.Errorf("expected %q in missing headers: %s", h, meta)
		}
	}
}

func TestDAST002_WildcardWithCredentials(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkInsecureCORS(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected DAST-002 for wildcard + credentials")
	}
	if results[0].Message != "CORS allows wildcard origin (*) with credentials" {
		t.Errorf("message = %q, want credentials warning", results[0].Message)
	}
}

func TestCheckOpenRedirect_MultipleParams(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, p := range []string{"redirect", "url", "next", "return_to", "redirect_uri"} {
			if v := r.URL.Query().Get(p); v != "" {
				http.Redirect(w, r, v, http.StatusFound)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	results := checkOpenRedirect(context.Background(), ts.Client(), ts.URL)
	if len(results) == 0 {
		t.Fatal("expected at least one open redirect finding")
	}
	// The first param tested is "redirect".
	if results[0].Metadata["param"] != "redirect" {
		t.Errorf("param = %q, want redirect", results[0].Metadata["param"])
	}
}

// --- helpers ---

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	const bufSize = 1024 * 1024

	lis := bufconn.Listen(bufSize)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())

	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, targetURL string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"target_url": targetURL,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName: "scan",
		Input:    input,
	})
	if err != nil {
		t.Fatalf("InvokeTool(scan): %v", err)
	}
	return resp
}


