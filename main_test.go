package main

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
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

func TestDAST001_MissingSecurityHeaders(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-001")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-001 (Missing Security Headers) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("DAST-001 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetLocation() == nil || f.GetLocation().GetStartLine() == 0 {
			t.Error("finding must include a location with non-zero start line")
		}
		if f.GetMetadata()["cwe"] != "CWE-693" {
			t.Errorf("expected CWE-693, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestDAST002_InsecureCORS(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-002")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-002 (Insecure CORS) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-942" {
			t.Errorf("expected CWE-942, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestDAST003_MissingTLS(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-003")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-003 (Missing TLS/HTTPS) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityMedium {
			t.Errorf("DAST-003 severity should be MEDIUM, got %v", f.GetSeverity())
		}
	}
}

func TestDAST004_InsecureCookies(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-004")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-004 (Insecure Cookie) finding")
	}

	for _, f := range found {
		if f.GetMetadata()["cwe"] != "CWE-614" {
			t.Errorf("expected CWE-614, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestDAST005_MissingRateLimiting(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-005")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-005 (Missing Rate Limiting) finding")
	}
}

func TestDAST006_OpenRedirect(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, testdataDir(t))

	found := findByRule(resp.GetFindings(), "DAST-006")
	if len(found) == 0 {
		t.Fatal("expected at least one DAST-006 (Open Redirect) finding")
	}

	for _, f := range found {
		if f.GetSeverity() != sdk.SeverityHigh {
			t.Errorf("DAST-006 severity should be HIGH, got %v", f.GetSeverity())
		}
		if f.GetMetadata()["cwe"] != "CWE-601" {
			t.Errorf("expected CWE-601, got %q", f.GetMetadata()["cwe"])
		}
	}
}

func TestScanEmptyWorkspace(t *testing.T) {
	client := testClient(t)
	resp := invokeScan(t, client, t.TempDir())

	if len(resp.GetFindings()) != 0 {
		t.Errorf("expected zero findings for empty workspace, got %d", len(resp.GetFindings()))
	}
}

func TestScanNoWorkspace(t *testing.T) {
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
		t.Errorf("expected zero findings when no workspace provided, got %d", len(resp.GetFindings()))
	}
}

// --- helpers ---

func testdataDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("unable to determine test file path")
	}
	return filepath.Join(filepath.Dir(filename), "testdata")
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

func invokeScan(t *testing.T, client pluginv1.PluginServiceClient, workspaceRoot string) *pluginv1.InvokeToolResponse {
	t.Helper()
	input, err := structpb.NewStruct(map[string]any{
		"workspace_root": workspaceRoot,
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

func findByRule(findings []*pluginv1.Finding, ruleID string) []*pluginv1.Finding {
	var result []*pluginv1.Finding
	for _, f := range findings {
		if f.GetRuleId() == ruleID {
			result = append(result, f)
		}
	}
	return result
}
