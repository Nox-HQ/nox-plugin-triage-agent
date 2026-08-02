package main

import (
	"context"
	"net"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestConformance(t *testing.T) {
	sdk.RunConformance(t, buildServer())
}

func TestTrackConformance(t *testing.T) {
	sdk.RunForTrack(t, buildServer(), registry.TrackAgentAssistance)
}

// The contract this plugin now keeps: it annotates the queue, it does not
// lengthen it. Emitting a finding of its own would double-count a defect the
// core scan already reported, and would make the total finding count depend on
// whether triage happened to be installed.
func TestTriage_EmitsEnrichmentsAndNeverFindings(t *testing.T) {
	resp := invokeTriage(t, testClient(t), []*pluginv1.Finding{
		finding("f1", pluginv1.Severity_SEVERITY_CRITICAL, pluginv1.Confidence_CONFIDENCE_HIGH, "internal/api/handler.go"),
		finding("f2", pluginv1.Severity_SEVERITY_LOW, pluginv1.Confidence_CONFIDENCE_MEDIUM, "internal/util/str.go"),
	})

	if got := len(resp.GetFindings()); got != 0 {
		t.Errorf("triage must not emit findings of its own, got %d", got)
	}
	if got := len(resp.GetEnrichments()); got != 2 {
		t.Fatalf("expected one enrichment per finding, got %d", got)
	}
	for _, e := range resp.GetEnrichments() {
		if e.GetKind() != "triage" {
			t.Errorf("enrichment kind should be %q, got %q", "triage", e.GetKind())
		}
		// Without the fingerprint the verdict cannot be attached to anything.
		if e.GetFindingFingerprint() == "" {
			t.Error("enrichment must carry the fingerprint of the finding it describes")
		}
		if e.GetMetadata()["priority"] == "" {
			t.Error("enrichment must carry a priority")
		}
	}
}

func TestTriage_NoFindingsIsSuccess(t *testing.T) {
	resp := invokeTriage(t, testClient(t), nil)
	if len(resp.GetEnrichments()) != 0 {
		t.Errorf("a clean scan should produce no enrichments, got %d", len(resp.GetEnrichments()))
	}
}

func TestTriage_PriorityBySeverityAndConfidence(t *testing.T) {
	tests := []struct {
		name string
		sev  pluginv1.Severity
		conf pluginv1.Confidence
		want priority
	}{
		{"critical leads", pluginv1.Severity_SEVERITY_CRITICAL, pluginv1.Confidence_CONFIDENCE_HIGH, priorityImmediate},
		{"high confident", pluginv1.Severity_SEVERITY_HIGH, pluginv1.Confidence_CONFIDENCE_HIGH, priorityImmediate},
		{"high unsure waits", pluginv1.Severity_SEVERITY_HIGH, pluginv1.Confidence_CONFIDENCE_LOW, priorityScheduled},
		{"medium confident", pluginv1.Severity_SEVERITY_MEDIUM, pluginv1.Confidence_CONFIDENCE_HIGH, priorityScheduled},
		{"medium unsure", pluginv1.Severity_SEVERITY_MEDIUM, pluginv1.Confidence_CONFIDENCE_LOW, priorityBacklog},
		{"low", pluginv1.Severity_SEVERITY_LOW, pluginv1.Confidence_CONFIDENCE_HIGH, priorityBacklog},
		{"info", pluginv1.Severity_SEVERITY_INFO, pluginv1.Confidence_CONFIDENCE_HIGH, priorityInformational},
		// An unspecified severity is a gap in the producing rule, not evidence
		// the finding is unimportant — it must stay visible.
		{"unspecified stays visible", pluginv1.Severity_SEVERITY_UNSPECIFIED, pluginv1.Confidence_CONFIDENCE_HIGH, priorityBacklog},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(finding("f", tc.sev, tc.conf, "internal/api/handler.go")).priority
			if got != tc.want {
				t.Errorf("classify() = %q, want %q", got, tc.want)
			}
		})
	}
}

// A critical finding in a test fixture does not run in production and must not
// outrank a real one in live code. This is the judgement severity alone cannot
// make, and the reason triage is worth running at all.
func TestClassify_DemotesNonProductionCode(t *testing.T) {
	live := classify(finding("a", pluginv1.Severity_SEVERITY_CRITICAL, pluginv1.Confidence_CONFIDENCE_HIGH, "internal/api/handler.go"))
	fixture := classify(finding("b", pluginv1.Severity_SEVERITY_CRITICAL, pluginv1.Confidence_CONFIDENCE_HIGH, "internal/api/testdata/payload.go"))

	if live.priority != priorityImmediate {
		t.Fatalf("production critical should be immediate, got %q", live.priority)
	}
	if fixture.rank() <= live.rank() {
		t.Errorf("a finding in testdata must rank below the same finding in live code: %q vs %q",
			fixture.priority, live.priority)
	}
}

func TestIsNonProduction(t *testing.T) {
	nonProd := []string{
		"internal/api/handler_test.go",
		"pkg/testdata/fixture.go",
		"src/__tests__/app.js",
		"src/app.test.ts",
		"src/app.spec.tsx",
		"tests/conftest.py",
		"api/test_client.py",
		"e2e/login_flow.go",
		"examples/demo/main.go",
		"src/main/java/FooTest.java",
	}
	for _, p := range nonProd {
		if !isNonProduction(p) {
			t.Errorf("isNonProduction(%q) = false, want true", p)
		}
	}

	// Substring matching would demote every one of these. They are production
	// code whose names merely contain a test-ish word.
	prod := []string{
		"internal/api/handler.go",
		"internal/latest/version.go",
		"src/contest/scoring.go",
		"pkg/attestation/verify.go",
		"internal/protest/parser.go",
		"cmd/spectrum/main.go",
	}
	for _, p := range prod {
		if isNonProduction(p) {
			t.Errorf("isNonProduction(%q) = true, want false", p)
		}
	}
}

// --- helpers ---

func finding(fp string, sev pluginv1.Severity, conf pluginv1.Confidence, file string) *pluginv1.Finding {
	return &pluginv1.Finding{
		Id:          fp,
		RuleId:      "CORE-001",
		Severity:    sev,
		Confidence:  conf,
		Fingerprint: fp,
		Message:     "example finding",
		Location:    &pluginv1.Location{FilePath: file, StartLine: 42},
	}
}

func testClient(t *testing.T) pluginv1.PluginServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	pluginv1.RegisterPluginServiceServer(grpcServer, buildServer())
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(func() { grpcServer.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pluginv1.NewPluginServiceClient(conn)
}

// invokeTriage calls the tool the way nox's post-scan host does: findings
// arrive in ScanContext, not in Input.
func invokeTriage(t *testing.T, client pluginv1.PluginServiceClient, findings []*pluginv1.Finding) *pluginv1.InvokeToolResponse {
	t.Helper()
	resp, err := client.InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:    "triage",
		ScanContext: &pluginv1.ScanContext{Findings: findings},
	})
	if err != nil {
		t.Fatalf("InvokeTool(triage): %v", err)
	}
	return resp
}
