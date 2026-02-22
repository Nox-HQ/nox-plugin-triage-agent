package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

// mockProvider implements plannerllm.Provider for testing without real LLM calls.
type mockProvider struct {
	response string
	err      error
}

func (m *mockProvider) Complete(_ context.Context, _ plannerllm.CompletionRequest) (plannerllm.CompletionResponse, error) {
	if m.err != nil {
		return plannerllm.CompletionResponse{}, m.err
	}
	return plannerllm.CompletionResponse{
		ID:    "mock-id",
		Model: "mock-model",
		Message: plannerllm.Message{
			Role:    "assistant",
			Content: m.response,
		},
	}, nil
}

func (m *mockProvider) Name() string { return "mock" }

func TestAITriageAdjustsSeverity(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:     "TRIAGE-001",
			Severity:   sdk.SeverityHigh,
			Confidence: sdk.ConfidenceHigh,
			Message:    "eval() with user input",
			Location:   &pluginv1.Location{FilePath: "app.py", StartLine: 7},
			Metadata:   map[string]string{"priority": "immediate"},
		},
	}

	adjustments := []triageAdjustment{
		{
			RuleID:           "TRIAGE-001",
			File:             "app.py",
			Line:             7,
			AdjustedSeverity: "critical",
			AdjustedPriority: "immediate",
			Classification:   "true_positive",
			Reason:           "eval() called with unsanitized user input from request.args",
		},
	}
	respJSON, _ := json.Marshal(adjustments)

	provider := &mockProvider{response: string(respJSON)}
	aiTriageFindings(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.GetSeverity() != sdk.SeverityCritical {
		t.Errorf("expected severity CRITICAL, got %v", f.GetSeverity())
	}
	if f.Metadata["ai_triaged"] != "true" {
		t.Error("expected ai_triaged=true metadata")
	}
	if f.Metadata["ai_classification"] != "true_positive" {
		t.Errorf("expected ai_classification=true_positive, got %q", f.Metadata["ai_classification"])
	}
	if f.Metadata["ai_triage_reason"] == "" {
		t.Error("expected ai_triage_reason to be set")
	}
	if f.Metadata["ai_original_severity"] == "" {
		t.Error("expected ai_original_severity to be set")
	}
}

func TestAITriageLowersSeverity(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:     "TRIAGE-002",
			Severity:   sdk.SeverityMedium,
			Confidence: sdk.ConfidenceHigh,
			Message:    "request.args access",
			Location:   &pluginv1.Location{FilePath: "api.py", StartLine: 12},
			Metadata:   map[string]string{"priority": "scheduled"},
		},
	}

	adjustments := []triageAdjustment{
		{
			RuleID:           "TRIAGE-002",
			File:             "api.py",
			Line:             12,
			AdjustedSeverity: "low",
			AdjustedPriority: "backlog",
			Classification:   "false_positive",
			Reason:           "input is validated by middleware before reaching this handler",
		},
	}
	respJSON, _ := json.Marshal(adjustments)

	provider := &mockProvider{response: string(respJSON)}
	aiTriageFindings(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.GetSeverity() != sdk.SeverityLow {
		t.Errorf("expected severity LOW, got %v", f.GetSeverity())
	}
	if f.Metadata["priority"] != "backlog" {
		t.Errorf("expected priority=backlog, got %q", f.Metadata["priority"])
	}
	if f.Metadata["ai_classification"] != "false_positive" {
		t.Errorf("expected ai_classification=false_positive, got %q", f.Metadata["ai_classification"])
	}
}

func TestAITriageGracefulDegradation(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "TRIAGE-001",
			Severity: sdk.SeverityHigh,
			Message:  "test finding",
			Location: &pluginv1.Location{FilePath: "app.py", StartLine: 1},
		},
	}

	provider := &mockProvider{err: errors.New("connection refused")}
	aiTriageFindings(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.GetSeverity() != sdk.SeverityHigh {
		t.Errorf("severity should remain HIGH on error, got %v", f.GetSeverity())
	}
	if f.Metadata["ai_triage_error"] == "" {
		t.Error("expected ai_triage_error metadata on failure")
	}
}

func TestAITriageMalformedResponse(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "TRIAGE-001",
			Severity: sdk.SeverityHigh,
			Message:  "test finding",
			Location: &pluginv1.Location{FilePath: "app.py", StartLine: 1},
		},
	}

	provider := &mockProvider{response: "this is not valid JSON"}
	aiTriageFindings(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.GetSeverity() != sdk.SeverityHigh {
		t.Errorf("severity should remain HIGH on malformed response, got %v", f.GetSeverity())
	}
	if f.Metadata["ai_triage_error"] == "" {
		t.Error("expected ai_triage_error metadata on malformed response")
	}
}

func TestAITriageEmptyFindings(t *testing.T) {
	provider := &mockProvider{err: errors.New("should not be called")}
	aiTriageFindings(context.Background(), provider, "mock-model", nil)
	// Should return immediately without calling provider.
}

func TestAITriageMarkdownCodeFences(t *testing.T) {
	findings := []*pluginv1.Finding{
		{
			RuleId:   "TRIAGE-003",
			Severity: sdk.SeverityLow,
			Message:  "deprecated API",
			Location: &pluginv1.Location{FilePath: "old.go", StartLine: 5},
			Metadata: map[string]string{"priority": "backlog"},
		},
	}

	adjustments := []triageAdjustment{
		{
			RuleID:           "TRIAGE-003",
			File:             "old.go",
			Line:             5,
			AdjustedSeverity: "info",
			AdjustedPriority: "informational",
			Classification:   "false_positive",
			Reason:           "deprecated but not security-relevant",
		},
	}
	inner, _ := json.Marshal(adjustments)
	wrapped := "```json\n" + string(inner) + "\n```"

	provider := &mockProvider{response: wrapped}
	aiTriageFindings(context.Background(), provider, "mock-model", findings)

	f := findings[0]
	if f.GetSeverity() != sdk.SeverityInfo {
		t.Errorf("expected severity INFO, got %v", f.GetSeverity())
	}
	if f.Metadata["ai_triaged"] != "true" {
		t.Error("expected ai_triaged=true metadata")
	}
}

func TestParseTriageResponseValid(t *testing.T) {
	input := `[{"rule_id":"TRIAGE-001","file":"a.py","line":1,"adjusted_severity":"high","adjusted_priority":"immediate","classification":"true_positive","reason":"test"}]`
	adj, err := parseTriageResponse(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(adj) != 1 {
		t.Fatalf("expected 1 adjustment, got %d", len(adj))
	}
	if adj[0].RuleID != "TRIAGE-001" {
		t.Errorf("expected rule_id TRIAGE-001, got %q", adj[0].RuleID)
	}
}

func TestParseTriageResponseInvalid(t *testing.T) {
	_, err := parseTriageResponse("not json")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  pluginv1.Severity
	}{
		{"critical", sdk.SeverityCritical},
		{"high", sdk.SeverityHigh},
		{"MEDIUM", sdk.SeverityMedium},
		{"Low", sdk.SeverityLow},
		{"INFO", sdk.SeverityInfo},
		{"unknown", pluginv1.Severity(0)},
	}
	for _, tt := range tests {
		got := parseSeverity(tt.input)
		if got != tt.want {
			t.Errorf("parseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}
