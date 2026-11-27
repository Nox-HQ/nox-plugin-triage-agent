package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	plannerllm "go.klarlabs.de/agent/contrib/planner-llm"
	"go.klarlabs.de/agent/contrib/planner-llm/providers"
)

// AI triage is a verdict ABOUT a finding. It never changes a finding's severity
// or confidence, never drops a finding, and never creates one: its only output
// is an enrichment keyed by the finding's fingerprint. A model that invents a
// file or line in its reply cannot move a finding, because the location is read
// from the input finding, never from the reply.

// Verdict values carried in the ai_verdict metadata field.
const (
	verdictTruePositive  = "true_positive"
	verdictFalsePositive = "false_positive"
	verdictUncertain     = "uncertain"
)

const maxRationaleRunes = 280

// Error classes reported in place of provider error text, which can carry a
// response body.
const (
	errClassTimeout     = "timeout"
	errClassRateLimited = "rate_limited"
	errClassAuth        = "auth"
	errClassConnection  = "connection"
	errClassBudget      = "budget_exhausted"
	errClassProvider    = "provider_error"
)

func validVerdict(v string) bool {
	switch v {
	case verdictTruePositive, verdictFalsePositive, verdictUncertain:
		return true
	}
	return false
}

// aiVerdict is one judged finding.
type aiVerdict struct {
	fingerprint string
	verdict     string
	rationale   string
	cached      bool
}

// judge holds everything one triage run needs. The provider is injected so
// tests run without a network.
type judge struct {
	provider     plannerllm.Provider
	providerName string
	model        string
	cache        *verdictCache
	pack         *triagePack
	root         string
	cfg          aiConfig
}

// selectCandidates dedupes, gates and orders the findings to judge. The most
// urgent come first so a cap or a deadline drops the least important ones, and
// the order is deterministic.
func selectCandidates(findings []*pluginv1.Finding, cfg *aiConfig) []*pluginv1.Finding {
	var out []*pluginv1.Finding
	for _, f := range dedupeFindings(findings) {
		if f.GetFingerprint() != "" && shouldTriage(f, cfg.Gates) {
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return classify(out[i]).rank() < classify(out[j]).rank()
	})
	if cfg.MaxFindings > 0 && len(out) > cfg.MaxFindings {
		out = out[:cfg.MaxFindings]
	}
	return out
}

// run judges every candidate with bounded concurrency and returns one verdict
// per candidate, in candidate order. It never returns an error: a failure on one
// finding is that finding's uncertain verdict.
func (j *judge) run(ctx context.Context, candidates []*pluginv1.Finding) []aiVerdict {
	verdicts := make([]aiVerdict, len(candidates))
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := max(1, min(j.cfg.Concurrency, len(candidates)))
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				verdicts[i] = j.judgeOne(ctx, candidates[i])
			}
		}()
	}
	for i := range candidates {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return verdicts
}

func uncertain(f *pluginv1.Finding, why string) aiVerdict {
	return aiVerdict{fingerprint: f.GetFingerprint(), verdict: verdictUncertain, rationale: why}
}

// judgeOne judges a single finding: read a confined snippet, redact it, answer
// from the cache or ask the model, and cache a parsed answer.
func (j *judge) judgeOne(ctx context.Context, f *pluginv1.Finding) aiVerdict {
	if ctx.Err() != nil {
		return uncertain(f, "no verdict: "+errClassBudget)
	}
	text, err := j.redactedSnippet(f)
	if err != nil {
		return uncertain(f, "no verdict: source snippet unavailable ("+snippetErrClass(err)+")")
	}
	key := cacheKey(f.GetFingerprint(), text, j.pack.version, j.providerName, j.model)
	if hit, ok := j.cache.get(key); ok {
		return aiVerdict{fingerprint: f.GetFingerprint(), verdict: hit.Verdict, rationale: hit.Rationale, cached: true}
	}

	callCtx, cancel := context.WithTimeout(ctx, j.cfg.Timeout)
	defer cancel()
	resp, err := j.provider.Complete(callCtx, plannerllm.CompletionRequest{
		Model: j.model,
		Messages: []plannerllm.Message{
			{Role: "system", Content: j.pack.systemPrompt(classForFinding(f))},
			{Role: "user", Content: userPrompt(f, redactText(f.GetMessage()), text)},
		},
		MaxTokens: 300,
	})
	if err != nil {
		return uncertain(f, "no verdict: provider call failed ("+providerErrClass(err)+")")
	}
	verdict, rationale := parseVerdict(resp.Message.Content)
	// A cache write failure costs a repeat call next run, nothing more.
	_ = j.cache.put(key, cachedVerdict{Verdict: verdict, Rationale: rationale})
	return aiVerdict{fingerprint: f.GetFingerprint(), verdict: verdict, rationale: rationale}
}

// redactedSnippet reads the finding's window from the workspace and returns it
// redacted and size-capped, ready to leave the process.
func (j *judge) redactedSnippet(f *pluginv1.Finding) (string, error) {
	loc := f.GetLocation()
	s, err := readSnippet(j.root, loc.GetFilePath(), int(loc.GetStartLine()), snippetRadius)
	if err != nil {
		return "", err
	}
	if end := int(loc.GetEndLine()); end > int(loc.GetStartLine()) {
		s.focusRange(int(loc.GetStartLine()), end)
	}
	redacted := redactSnippet(s.lines, s.focus, isSecretRule(f.GetRuleId()))
	return capSnippet(redacted, int(loc.GetStartLine())-s.first, snippetMaxBytes), nil
}

func snippetErrClass(err error) string {
	switch {
	case errors.Is(err, errOutsideWorkspace):
		return "outside_workspace"
	case errors.Is(err, errNoWorkspace):
		return "no_workspace"
	default:
		return "unreadable"
	}
}

var httpStatus = regexp.MustCompile(`status (\d{3})`)

// providerErrClass reduces a provider error to a class. The raw text is never
// used: provider errors can embed the response body.
func providerErrClass(err error) string {
	switch {
	case errors.Is(err, providers.ErrMissingAPIKey):
		return errClassAuth
	case errors.Is(err, providers.ErrRateLimited):
		return errClassRateLimited
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, providers.ErrContextCanceled), errors.Is(err, context.Canceled):
		return errClassTimeout
	case errors.Is(err, providers.ErrConnectionFailed):
		return errClassConnection
	}
	if m := httpStatus.FindStringSubmatch(err.Error()); m != nil {
		return "http_" + m[1]
	}
	return errClassProvider
}

// parseVerdict reads the verdict from the FIRST non-empty line of the reply and
// the rationale from the line after it. It never reads a location from the
// reply. A reply that names no verdict, or more than one, is uncertain: an
// unexpected shape must not become a confident label.
func parseVerdict(reply string) (verdict, rationale string) {
	lines := nonEmptyLines(reply)
	if len(lines) == 0 {
		return verdictUncertain, ""
	}
	verdict = verdictFromLine(lines[0])
	if len(lines) > 1 {
		rationale = shorten(lines[1])
	}
	return verdict, rationale
}

func verdictFromLine(line string) string {
	norm := strings.ToUpper(strings.NewReplacer("*", "", "`", "", " ", "_", "-", "_").Replace(line))
	tp := strings.Contains(norm, "TRUE_POSITIVE")
	fp := strings.Contains(norm, "FALSE_POSITIVE")
	switch {
	case tp && !fp:
		return verdictTruePositive
	case fp && !tp:
		return verdictFalsePositive
	default:
		return verdictUncertain
	}
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func shorten(s string) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) > maxRationaleRunes {
		return string(r[:maxRationaleRunes]) + "..."
	}
	return string(r)
}

// boundedContext returns a context for the whole AI phase. The host cancels a
// tool call at the plugin's invocation timeout; if that deadline arrives first
// the deterministic enrichments are lost too, so the AI phase stops a margin
// earlier and leaves time to answer.
func boundedContext(ctx context.Context, margin time.Duration) (context.Context, context.CancelFunc) {
	if dl, ok := ctx.Deadline(); ok {
		return context.WithDeadline(ctx, dl.Add(-margin))
	}
	return ctx, func() {}
}

// summarize renders a one-line diagnostic of the AI pass.
func summarize(verdicts []aiVerdict) string {
	var tp, fp, unc, cached int
	for _, v := range verdicts {
		switch v.verdict {
		case verdictTruePositive:
			tp++
		case verdictFalsePositive:
			fp++
		default:
			unc++
		}
		if v.cached {
			cached++
		}
	}
	return fmt.Sprintf("ai triage: %d judged (%d from cache): %d true_positive, %d false_positive, %d uncertain",
		len(verdicts), cached, tp, fp, unc)
}
