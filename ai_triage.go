package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	plannerllm "github.com/felixgeelhaar/agent-go/contrib/planner-llm"
	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

const triageSystemPrompt = `You are a security triage assistant. You analyze code security findings and provide contextual severity adjustments.

For each finding, you must:
1. Review the rule ID, current severity, and code context
2. Assess whether the severity should be kept, raised, or lowered
3. Classify the finding as "true_positive", "false_positive", or "needs_review"
4. Provide a brief reason for your assessment

Respond ONLY with a JSON array. Each element must have these fields:
- "rule_id": string (the original rule ID)
- "file": string (the file path)
- "line": integer (the line number)
- "adjusted_severity": string (one of: "critical", "high", "medium", "low", "info")
- "adjusted_priority": string (one of: "immediate", "scheduled", "backlog", "informational")
- "classification": string (one of: "true_positive", "false_positive", "needs_review")
- "reason": string (brief explanation)

Do not include any text outside the JSON array.`

// triageAdjustment represents a single LLM-suggested adjustment to a finding.
type triageAdjustment struct {
	RuleID           string `json:"rule_id"`
	File             string `json:"file"`
	Line             int    `json:"line"`
	AdjustedSeverity string `json:"adjusted_severity"`
	AdjustedPriority string `json:"adjusted_priority"`
	Classification   string `json:"classification"`
	Reason           string `json:"reason"`
}

// aiTriageFindings sends findings to an LLM for contextual severity adjustment.
// On any error, findings are returned unchanged with ai_triage_error metadata.
func aiTriageFindings(ctx context.Context, provider plannerllm.Provider, model string, findings []*pluginv1.Finding) {
	if len(findings) == 0 {
		return
	}

	userMsg := buildTriagePrompt(findings)

	resp, err := provider.Complete(ctx, plannerllm.CompletionRequest{
		Model: model,
		Messages: []plannerllm.Message{
			{Role: "system", Content: triageSystemPrompt},
			{Role: "user", Content: userMsg},
		},
		Temperature: 0.2,
		MaxTokens:   4096,
	})
	if err != nil {
		log.Printf("ai_triage: LLM call failed: %v", err)
		markTriageError(findings, fmt.Sprintf("LLM call failed: %v", err))
		return
	}

	adjustments, err := parseTriageResponse(resp.Message.Content)
	if err != nil {
		log.Printf("ai_triage: failed to parse LLM response: %v", err)
		markTriageError(findings, fmt.Sprintf("failed to parse LLM response: %v", err))
		return
	}

	applyAdjustments(findings, adjustments)
}

// buildTriagePrompt serializes findings into a user message for the LLM.
func buildTriagePrompt(findings []*pluginv1.Finding) string {
	type findingSummary struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		File     string `json:"file"`
		Line     int32  `json:"line"`
		Message  string `json:"message"`
		Priority string `json:"priority"`
	}

	summaries := make([]findingSummary, len(findings))
	for i, f := range findings {
		file := ""
		var line int32
		if f.GetLocation() != nil {
			file = f.GetLocation().GetFilePath()
			line = f.GetLocation().GetStartLine()
		}
		priority := ""
		if f.GetMetadata() != nil {
			priority = f.GetMetadata()["priority"]
		}
		summaries[i] = findingSummary{
			RuleID:   f.GetRuleId(),
			Severity: f.GetSeverity().String(),
			File:     file,
			Line:     line,
			Message:  f.GetMessage(),
			Priority: priority,
		}
	}

	data, _ := json.MarshalIndent(summaries, "", "  ")
	return fmt.Sprintf("Please triage the following %d security findings:\n\n%s", len(findings), string(data))
}

// parseTriageResponse extracts triage adjustments from the LLM response content.
func parseTriageResponse(content string) ([]triageAdjustment, error) {
	content = strings.TrimSpace(content)

	// Strip markdown code fences if present.
	if strings.HasPrefix(content, "```") {
		lines := strings.Split(content, "\n")
		if len(lines) >= 2 {
			lines = lines[1:]
		}
		if len(lines) > 0 && strings.HasPrefix(strings.TrimSpace(lines[len(lines)-1]), "```") {
			lines = lines[:len(lines)-1]
		}
		content = strings.Join(lines, "\n")
	}

	var adjustments []triageAdjustment
	if err := json.Unmarshal([]byte(content), &adjustments); err != nil {
		return nil, fmt.Errorf("invalid JSON in LLM response: %w", err)
	}
	return adjustments, nil
}

// applyAdjustments modifies findings in-place based on LLM suggestions.
func applyAdjustments(findings []*pluginv1.Finding, adjustments []triageAdjustment) {
	// Build lookup: (rule_id, file, line) -> adjustment
	type key struct {
		ruleID string
		file   string
		line   int32
	}
	lookup := make(map[key]triageAdjustment, len(adjustments))
	for _, a := range adjustments {
		lookup[key{a.RuleID, a.File, int32(a.Line)}] = a
	}

	for _, f := range findings {
		file := ""
		var line int32
		if f.GetLocation() != nil {
			file = f.GetLocation().GetFilePath()
			line = f.GetLocation().GetStartLine()
		}

		adj, ok := lookup[key{f.GetRuleId(), file, line}]
		if !ok {
			continue
		}

		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_triaged"] = "true"
		f.Metadata["ai_classification"] = adj.Classification
		f.Metadata["ai_triage_reason"] = adj.Reason

		if sev := parseSeverity(adj.AdjustedSeverity); sev != pluginv1.Severity(0) {
			f.Metadata["ai_original_severity"] = f.GetSeverity().String()
			f.Severity = sev
		}
		if adj.AdjustedPriority != "" {
			f.Metadata["ai_original_priority"] = f.Metadata["priority"]
			f.Metadata["priority"] = adj.AdjustedPriority
		}
	}
}

// markTriageError adds ai_triage_error metadata to all findings when LLM triage fails.
func markTriageError(findings []*pluginv1.Finding, errMsg string) {
	for _, f := range findings {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["ai_triage_error"] = errMsg
	}
}

// parseSeverity converts a severity string to the protobuf enum value.
func parseSeverity(s string) pluginv1.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return sdk.SeverityCritical
	case "high":
		return sdk.SeverityHigh
	case "medium":
		return sdk.SeverityMedium
	case "low":
		return sdk.SeverityLow
	case "info":
		return sdk.SeverityInfo
	default:
		return pluginv1.Severity(0)
	}
}
