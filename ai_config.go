package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

const (
	defaultMaxFindings = 200
	defaultConcurrency = 4
	defaultCallTimeout = 60 * time.Second
	// maxConcurrency caps ai_concurrency so a typo cannot open hundreds of
	// connections to a provider.
	maxConcurrency = 16
	// deadlineMargin is how long before the host's invocation deadline the AI
	// phase stops, leaving time to return the deterministic enrichments.
	deadlineMargin = 10 * time.Second
)

// aiConfig is the resolved configuration of the opt-in AI pass.
//
// nox's post-scan host sends a scan-context request with no tool input, so every
// setting can also come from an environment variable; an input, when present,
// wins.
type aiConfig struct {
	Enabled     bool
	UseCache    bool
	MaxFindings int
	Concurrency int
	Timeout     time.Duration
	Gates       triageGates
}

// triageGates restricts which findings are sent to the model so tokens go to
// the residual that needs a second opinion.
type triageGates struct {
	MinSeverity        int // findings below this severity rank are skipped
	SkipHighConfidence bool
	OnlyRules          []string
	SkipRules          []string
}

// loadAIConfig reads the AI settings from tool input, falling back to env
// (NOX_AI_TRIAGE, NOX_AI_CACHE, NOX_AI_MAX_FINDINGS, NOX_AI_CONCURRENCY,
// NOX_AI_TIMEOUT in seconds). Unusable values fall back to the default.
func loadAIConfig(input map[string]any, getenv func(string) string) aiConfig {
	return aiConfig{
		Enabled:     boolSetting(input, "ai_triage", getenv("NOX_AI_TRIAGE"), false),
		UseCache:    boolSetting(input, "ai_cache", getenv("NOX_AI_CACHE"), true),
		MaxFindings: intSetting(input, "ai_max_findings", getenv("NOX_AI_MAX_FINDINGS"), defaultMaxFindings, 0),
		Concurrency: intSetting(input, "ai_concurrency", getenv("NOX_AI_CONCURRENCY"), defaultConcurrency, maxConcurrency),
		Timeout: time.Duration(intSetting(input, "ai_timeout", getenv("NOX_AI_TIMEOUT"),
			int(defaultCallTimeout/time.Second), 600)) * time.Second,
		Gates: triageGates{
			MinSeverity:        severityRankByName(stringSetting(input, "ai_min_severity")),
			SkipHighConfidence: boolSetting(input, "ai_skip_high_confidence", "", false),
			OnlyRules:          listSetting(input, "ai_only_rules"),
			SkipRules:          listSetting(input, "ai_skip_rules"),
		},
	}
}

func boolSetting(input map[string]any, key, env string, def bool) bool {
	if v, ok := input[key].(bool); ok {
		return v
	}
	if b, err := strconv.ParseBool(strings.TrimSpace(env)); err == nil {
		return b
	}
	return def
}

// intSetting reads a positive integer (JSON numbers arrive as float64). A value
// of zero or less, or one that does not parse, yields def; ceiling, when
// positive, caps the result.
func intSetting(input map[string]any, key, env string, def, ceiling int) int {
	n := def
	if v, ok := input[key].(float64); ok && v >= 1 {
		n = int(v)
	} else if e, err := strconv.Atoi(strings.TrimSpace(env)); err == nil && e >= 1 {
		n = e
	}
	if ceiling > 0 && n > ceiling {
		n = ceiling
	}
	return n
}

func stringSetting(input map[string]any, key string) string {
	s, _ := input[key].(string)
	return s
}

func listSetting(input map[string]any, key string) []string {
	var out []string
	switch v := input[key].(type) {
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case string:
		for _, part := range strings.Split(v, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func severityRankByName(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func severityRank(s pluginv1.Severity) int {
	switch s {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return 4
	case pluginv1.Severity_SEVERITY_HIGH:
		return 3
	case pluginv1.Severity_SEVERITY_MEDIUM:
		return 2
	case pluginv1.Severity_SEVERITY_LOW:
		return 1
	default:
		return 0
	}
}

// ruleMatches reports whether ruleID matches pattern: a trailing "*" is a prefix
// match, otherwise a glob or exact compare. A malformed pattern degrades to an
// exact compare rather than failing the run.
func ruleMatches(ruleID, pattern string) bool {
	if pattern == "" {
		return false
	}
	if p, ok := strings.CutSuffix(pattern, "*"); ok && strings.HasPrefix(ruleID, p) {
		return true
	}
	if ok, err := filepath.Match(pattern, ruleID); err == nil && ok {
		return true
	}
	return ruleID == pattern
}

func matchesAny(ruleID string, patterns []string) bool {
	for _, p := range patterns {
		if ruleMatches(ruleID, p) {
			return true
		}
	}
	return false
}

// shouldTriage applies the routing gates to one finding. Exclusions win over
// inclusions.
func shouldTriage(f *pluginv1.Finding, g triageGates) bool {
	if severityRank(f.GetSeverity()) < g.MinSeverity {
		return false
	}
	if g.SkipHighConfidence && f.GetConfidence() == pluginv1.Confidence_CONFIDENCE_HIGH {
		return false
	}
	id := f.GetRuleId()
	if len(g.OnlyRules) > 0 && !matchesAny(id, g.OnlyRules) {
		return false
	}
	return !matchesAny(id, g.SkipRules)
}

// dedupeFindings collapses findings that would ask the model the same question
// twice: same fingerprint, or, lacking one, same rule and location. First-seen
// order is kept and the input is not mutated.
func dedupeFindings(findings []*pluginv1.Finding) []*pluginv1.Finding {
	seen := make(map[string]struct{}, len(findings))
	out := make([]*pluginv1.Finding, 0, len(findings))
	for _, f := range findings {
		key := f.GetFingerprint()
		if key == "" {
			loc := f.GetLocation()
			key = fmt.Sprintf("%s\x00%s\x00%d", f.GetRuleId(), loc.GetFilePath(), loc.GetStartLine())
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, f)
	}
	return out
}
