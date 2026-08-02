package main

import (
	"fmt"
	"path"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// priority is the review queue a finding belongs in.
type priority string

const (
	priorityImmediate     priority = "immediate"
	priorityScheduled     priority = "scheduled"
	priorityBacklog       priority = "backlog"
	priorityInformational priority = "informational"
)

// order lists priorities most to least urgent. Used for ranking and for the
// one-step demotions below, so "less urgent" is defined in exactly one place.
var order = []priority{priorityImmediate, priorityScheduled, priorityBacklog, priorityInformational}

// verdict is the triage result for a single finding.
type verdict struct {
	priority  priority
	rationale string
}

func (v verdict) rank() int {
	for i, p := range order {
		if p == v.priority {
			return i
		}
	}
	return len(order)
}

func (v verdict) title() string {
	return fmt.Sprintf("Triage: %s", v.priority)
}

func (v verdict) body(f *pluginv1.Finding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "**Priority: %s**\n\n%s\n", v.priority, v.rationale)
	if loc := f.GetLocation(); loc.GetFilePath() != "" {
		fmt.Fprintf(&sb, "\n`%s:%d`\n", loc.GetFilePath(), loc.GetStartLine())
	}
	return sb.String()
}

// demote moves a verdict one step down the queue, stopping at the bottom.
func (v verdict) demote(why string) verdict {
	r := v.rank()
	if r < len(order)-1 {
		v.priority = order[r+1]
	}
	v.rationale = v.rationale + " " + why
	return v
}

// classify assigns a review priority to a finding from the completed scan.
//
// Severity alone is not triage. Severity says how bad the class of bug is;
// triage has to say what to look at first, which also depends on how sure the
// scanner is and on whether the code can actually be reached in production. A
// high-severity finding the engine is unsure about, sitting in a test fixture,
// is not the first thing anyone should read.
func classify(f *pluginv1.Finding) verdict {
	v := baseline(f.GetSeverity(), f.GetConfidence())

	// Low confidence is the scanner saying it might be wrong. That belongs
	// behind the findings it is sure about, whatever the severity class.
	if f.GetConfidence() == pluginv1.Confidence_CONFIDENCE_LOW && v.priority == priorityImmediate {
		v = v.demote("Confidence is low, so this needs confirming before it displaces work that is certain.")
	}

	// Test and fixture code is not reachable in production. It is still worth
	// fixing — a vulnerable test helper can mislead, and fixtures get copied —
	// but it does not compete with live code for attention.
	if isNonProduction(f.GetLocation().GetFilePath()) {
		v = v.demote("The location is test or fixture code, which does not run in production.")
	}

	return v
}

// baseline maps severity and confidence to a starting queue, before the
// location and confidence adjustments above.
func baseline(sev pluginv1.Severity, conf pluginv1.Confidence) verdict {
	switch sev {
	case pluginv1.Severity_SEVERITY_CRITICAL:
		return verdict{priorityImmediate, "Critical severity: exploitable consequences, so it leads the queue."}
	case pluginv1.Severity_SEVERITY_HIGH:
		if conf == pluginv1.Confidence_CONFIDENCE_LOW {
			return verdict{priorityScheduled, "High severity, but the scanner is not confident."}
		}
		return verdict{priorityImmediate, "High severity with the scanner confident in the match."}
	case pluginv1.Severity_SEVERITY_MEDIUM:
		if conf == pluginv1.Confidence_CONFIDENCE_HIGH {
			return verdict{priorityScheduled, "Medium severity, confidently matched: worth a planned fix."}
		}
		return verdict{priorityBacklog, "Medium severity without high confidence."}
	case pluginv1.Severity_SEVERITY_LOW:
		return verdict{priorityBacklog, "Low severity: worth fixing, not worth interrupting for."}
	case pluginv1.Severity_SEVERITY_INFO:
		return verdict{priorityInformational, "Informational: context for a reviewer, not a defect to fix."}
	default:
		// An unspecified severity is a gap in the producing rule, not a
		// judgement that the finding is unimportant. Backlog rather than
		// informational, so it stays visible enough to be noticed and fixed.
		return verdict{priorityBacklog, "Severity was not specified by the rule that produced this finding."}
	}
}

// nonProductionDirs are path segments whose contents do not run in production.
var nonProductionDirs = map[string]bool{
	"test":        true,
	"tests":       true,
	"testdata":    true,
	"__tests__":   true,
	"spec":        true,
	"specs":       true,
	"fixtures":    true,
	"e2e":         true,
	"mocks":       true,
	"__mocks__":   true,
	"examples":    true,
	"example":     true,
	"benchmarks":  true,
	"integration": true,
}

// nonProductionSuffixes are filename endings that mark a test across the
// languages nox scans.
var nonProductionSuffixes = []string{
	"_test.go",
	"_test.py",
	"_spec.rb",
	".test.js", ".test.ts", ".test.jsx", ".test.tsx",
	".spec.js", ".spec.ts", ".spec.jsx", ".spec.tsx",
	"Test.java", "Tests.cs",
}

// isNonProduction reports whether a path is test, fixture or example code.
//
// Matching is on whole path segments rather than substrings: a directory called
// "latest" or a package named "contest" contains neither tests nor fixtures, and
// a substring check would quietly demote real production findings in them.
func isNonProduction(filePath string) bool {
	if filePath == "" {
		return false
	}
	clean := path.Clean(strings.ReplaceAll(filePath, "\\", "/"))

	base := path.Base(clean)
	for _, suffix := range nonProductionSuffixes {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	// test_foo.py is the other common Python convention.
	if strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") {
		return true
	}

	for _, seg := range strings.Split(path.Dir(clean), "/") {
		if nonProductionDirs[strings.ToLower(seg)] {
			return true
		}
	}
	return false
}
