package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nox-hq/nox/sdk"
)

// `nox scan` invokes the "scan" tool with workspace_root and exclude — never a
// target_url, because nox scans source trees and this plugin probes live
// endpoints. Returning an empty response for that case made "nothing to scan"
// look exactly like "scanned, all clear" in every scan of every project that
// listed nox/dast in plugins.required.
func TestNoTargetURLIsReportedRatherThanSilent(t *testing.T) {
	resp, err := handleScan(context.Background(), sdk.ToolRequest{
		ToolName:      "scan",
		WorkspaceRoot: t.TempDir(),
		Input:         map[string]any{"workspace_root": t.TempDir()},
	})
	if err != nil {
		t.Fatalf("handleScan: %v", err)
	}

	if n := len(resp.GetFindings()); n != 0 {
		t.Errorf("findings = %d, want 0: no probe can run without a target", n)
	}
	diags := resp.GetDiagnostics()
	if len(diags) == 0 {
		t.Fatal("no diagnostic: an empty result with no explanation reads as a clean scan")
	}
	joined := strings.ToLower(diags[0].GetMessage())
	for _, want := range []string{"target_url", "live endpoint"} {
		if !strings.Contains(joined, want) {
			t.Errorf("diagnostic does not mention %q: %q", want, diags[0].GetMessage())
		}
	}
}

// The diagnostic must not fire once a target is supplied, or every real scan
// would carry a spurious warning.
func TestTargetURLSuppressesTheDiagnostic(t *testing.T) {
	resp, err := handleScan(context.Background(), sdk.ToolRequest{
		ToolName: "scan",
		Input:    map[string]any{"target_url": "https://127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("handleScan: %v", err)
	}
	for _, d := range resp.GetDiagnostics() {
		if strings.Contains(d.GetMessage(), "no target_url given") {
			t.Errorf("the no-target diagnostic fired with a target supplied: %q", d.GetMessage())
		}
	}
}
