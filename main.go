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
	"strconv"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
)

var version = "dev"

// aiNetworkHosts are the hosted-provider endpoints the AI pass may contact.
var aiNetworkHosts = []string{"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"}

func buildServer() *sdk.PluginServer {
	manifest := sdk.NewManifest("nox/triage-agent", version).
		Capability("triage-agent", "Prioritises findings a scan has already produced").
		ToolWithContext("triage", "Assign a review priority to each finding from the completed scan", true).
		Done().
		// Passive: the plugin never mutates anything and never contacts a scan
		// target. The hosts are what the opt-in AI pass (ai_triage) may reach
		// when it sends redacted snippets to a hosted provider; they are checked
		// against the host policy at registration. Other providers
		// (ollama, bedrock, cohere, a custom NOX_AI_BASE_URL) are not declared
		// here, so nox's policy allow-list cannot vouch for them.
		Safety(sdk.WithRiskClass(sdk.RiskPassive), sdk.WithNetworkHosts(aiNetworkHosts...)).
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
	// classification below, never a replacement for it. It only adds a second
	// enrichment per judged finding; if it cannot run, every finding still
	// carries the rule-based priority it would have had anyway.
	var ai []aiVerdict
	var j *judge
	cfg := loadAIConfig(req.Input, os.Getenv)
	if cfg.Enabled {
		var diag string
		if j, diag = newJudge(req.WorkspaceRoot, &cfg); j == nil {
			resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_WARNING, diag, "nox/triage-agent")
		}
	}
	if j != nil {
		aiCtx, cancel := boundedContext(ctx, deadlineMargin)
		ai = j.run(aiCtx, selectCandidates(findings, &cfg))
		cancel()
		resp.Diagnostic(pluginv1.DiagnosticSeverity_DIAGNOSTIC_SEVERITY_INFO, summarize(ai), "nox/triage-agent")
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

	if j != nil {
		emitVerdicts(resp, j, ai)
	}
	return resp.Build(), nil
}

// providerFactory builds the LLM provider; tests replace it to avoid the network.
var providerFactory = resolveProvider

// newJudge builds the AI judge from the environment. On failure it returns nil
// and a diagnostic that names the problem, never a credential.
func newJudge(workspaceRoot string, cfg *aiConfig) (j *judge, diag string) {
	provider, model, err := providerFactory()
	if err != nil {
		return nil, "ai triage skipped: " + err.Error()
	}
	pack, err := loadPack()
	if err != nil {
		return nil, "ai triage skipped: " + err.Error()
	}
	j = &judge{provider: provider, providerName: providerName(), model: model, pack: pack, root: workspaceRoot, cfg: *cfg}
	if cfg.UseCache {
		if dir, derr := defaultCacheDir(); derr == nil {
			j.cache = &verdictCache{dir: dir}
		}
	}
	return j, ""
}

// emitVerdicts attaches one "ai-triage" enrichment to each judged finding. The
// verdict is an annotation: nothing here touches a finding.
func emitVerdicts(resp *sdk.ResponseBuilder, j *judge, verdicts []aiVerdict) {
	for _, v := range verdicts {
		conf := sdk.ConfidenceMedium
		if v.verdict == verdictUncertain {
			conf = sdk.ConfidenceLow
		}
		resp.Enrichment(v.fingerprint, "ai-triage", "AI triage: "+v.verdict).
			Body(verdictBody(v)).
			WithMetadata("ai_verdict", v.verdict).
			WithMetadata("ai_rationale", v.rationale).
			WithMetadata("ai_provider", j.providerName).
			WithMetadata("ai_model", j.model).
			WithMetadata("pack_version", j.pack.version).
			WithMetadata("cached", strconv.FormatBool(v.cached)).
			WithConfidence(conf).
			Source("nox/triage-agent").
			Done()
	}
}

func verdictBody(v aiVerdict) string {
	if v.rationale == "" {
		return "AI verdict: **" + v.verdict + "** (advisory; the finding is unchanged)"
	}
	return "AI verdict: **" + v.verdict + "**: " + v.rationale + " (advisory; the finding is unchanged)"
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
