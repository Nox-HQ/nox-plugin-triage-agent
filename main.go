// Command nox-plugin-triage-agent prioritises the findings a nox scan already
// produced.
//
// It used to run its own regex sweep over the source tree and emit TRIAGE-001..004
// findings of its own. That was the wrong shape twice over. It duplicated
// detection nox core already does — badly, since a handful of regexes cannot
// match a real taint engine — and every improvement to the core scanner made the
// duplication worse rather than better. It also meant the plugin's output had to
// be de-duplicated against core findings that described the same code.
//
// The plugin now runs post-scan: nox hands it the findings, and it answers the
// question detection cannot, which is what to look at first. Output is
// enrichments keyed by finding fingerprint, not new findings, so triage annotates
// the queue instead of lengthening it.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/triage-agent", version).
		Capability("triage-agent", "Prioritises findings a scan has already produced").
		ToolWithContext("triage", "Assign a review priority to each finding from the completed scan", true).
		Done().
		Safety(sdk.WithRiskClass(sdk.RiskPassive)).
		Build()

	return sdk.NewPluginServer(manifest).
		HandleTool("triage", handleTriage)
}

// handleTriage classifies every finding the core scan produced.
//
// It emits no findings at all. A triage verdict is a statement ABOUT a finding,
// so it travels as an enrichment keyed by that finding's fingerprint; emitting a
// parallel finding would double-count the same defect and make the count of
// findings depend on whether triage happened to be installed.
func handleTriage(ctx context.Context, req sdk.ToolRequest) (*pluginv1.InvokeToolResponse, error) {
	findings := req.Findings()
	resp := sdk.NewResponse()

	if len(findings) == 0 {
		// Nothing to triage is a success, not an error: a clean scan is the
		// outcome the whole pipeline is aiming for.
		return resp.Build(), nil
	}

	// AI triage is an opt-in refinement layered ON TOP of the deterministic
	// classification below, never a replacement for it. If the provider is
	// unreachable or answers with nonsense, every finding still carries the
	// rule-based priority it would have had anyway.
	if aiTriage, _ := req.Input["ai_triage"].(bool); aiTriage {
		provider, model, err := resolveProvider()
		if err != nil {
			markTriageError(findings, err.Error())
		} else {
			aiTriageFindings(ctx, provider, model, findings)
		}
	}

	for _, f := range findings {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		p := classify(f)
		resp.Enrichment(f.GetFingerprint(), "triage", p.title()).
			Body(p.body(f)).
			WithMetadata("priority", string(p.priority)).
			WithMetadata("rank", fmt.Sprintf("%d", p.rank())).
			WithMetadata("rationale", p.rationale).
			WithConfidence(f.GetConfidence()).
			Source("nox/triage-agent").
			Done()
	}

	return resp.Build(), nil
}

func main() {
	os.Exit(run())
}

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	srv := buildServer()
	if err := srv.Serve(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "nox-plugin-triage-agent: %v\n", err)
		return 1
	}
	return 0
}
