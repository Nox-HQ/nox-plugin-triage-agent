package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/sdk"
	plannerllm "go.klarlabs.de/agent/contrib/planner-llm"
	"go.klarlabs.de/agent/contrib/planner-llm/providers"
)

// fakeProvider is a plannerllm.Provider that never touches the network. It
// records every request so tests can assert what would have left the process.
type fakeProvider struct {
	mu       sync.Mutex
	calls    atomic.Int32
	requests []plannerllm.CompletionRequest
	reply    func(plannerllm.CompletionRequest) (string, error)
	active   atomic.Int32
	peak     atomic.Int32
}

//nolint:gocritic // signature fixed by plannerllm.Provider
func (p *fakeProvider) Complete(ctx context.Context, req plannerllm.CompletionRequest) (plannerllm.CompletionResponse, error) {
	p.calls.Add(1)
	cur := p.active.Add(1)
	defer p.active.Add(-1)
	for {
		old := p.peak.Load()
		if cur <= old || p.peak.CompareAndSwap(old, cur) {
			break
		}
	}
	p.mu.Lock()
	p.requests = append(p.requests, req)
	p.mu.Unlock()
	reply := func(plannerllm.CompletionRequest) (string, error) {
		return "FALSE_POSITIVE\nInput is parameterized.", nil
	}
	if p.reply != nil {
		reply = p.reply
	}
	out, err := reply(req)
	if err != nil {
		return plannerllm.CompletionResponse{}, err
	}
	return plannerllm.CompletionResponse{Message: plannerllm.Message{Role: "assistant", Content: out}}, nil
}

func (p *fakeProvider) Name() string { return "fake" }

func (p *fakeProvider) sent() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var b strings.Builder
	for _, r := range p.requests {
		for _, m := range r.Messages {
			b.WriteString(m.Content)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

func newTestJudge(t *testing.T, root string, p plannerllm.Provider, useCache bool) *judge {
	t.Helper()
	pack, err := loadPack()
	if err != nil {
		t.Fatal(err)
	}
	j := &judge{
		provider: p, providerName: "fake", model: "fake-model", pack: pack, root: root,
		cfg: aiConfig{Concurrency: 2, Timeout: 5 * time.Second, MaxFindings: 200},
	}
	if useCache {
		j.cache = &verdictCache{dir: t.TempDir()}
	}
	return j
}

func srcFinding(fp, rule string, line int32) *pluginv1.Finding {
	return &pluginv1.Finding{
		Id: fp, RuleId: rule, Fingerprint: fp,
		Severity:   sdk.SeverityHigh,
		Confidence: sdk.ConfidenceMedium,
		Message:    "example finding",
		Location:   &pluginv1.Location{FilePath: "src/app.go", StartLine: line},
		Metadata:   map[string]string{"cwe": "CWE-89"},
	}
}

func TestJudgeOne_VerdictAndPrompt(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	j := newTestJudge(t, root, fp, false)

	v := j.judgeOne(context.Background(), srcFinding("fp1", "TAINT-001", 50))
	if v.verdict != verdictFalsePositive || v.rationale != "Input is parameterized." || v.cached {
		t.Fatalf("verdict = %+v", v)
	}
	sent := fp.sent()
	for _, want := range []string{"TAINT-001", "CWE-89", "src/app.go:50", "inside line 50", "inside line 30", "inside line 70", "Class: injection"} {
		if !strings.Contains(sent, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if strings.Contains(sent, "inside line 29") || strings.Contains(sent, "inside line 71") {
		t.Error("snippet is wider than +/-20 lines")
	}
	if fp.requests[0].MaxTokens == 0 {
		t.Error("max tokens must be bounded")
	}
}

func TestJudgeOne_SendsNoSecretValue(t *testing.T) {
	root, _ := workspace(t)
	r := rand.New(rand.NewSource(11))
	short := token(r, "", 14, mixedAlnum)
	awsKey := token(r, "AKIA", 16, upperAlnum)
	src := strings.Join([]string{
		"package main",
		`const password = "` + short + `"`,
		`var aws = "` + awsKey + `"`,
		"func main() {}",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(root, "src", "creds.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &pluginv1.Finding{
		RuleId: "SEC-001", Fingerprint: "fp-sec", Severity: sdk.SeverityHigh,
		Message:  "hardcoded credential " + awsKey,
		Location: &pluginv1.Location{FilePath: "src/creds.go", StartLine: 2},
	}
	fp := &fakeProvider{}
	j := newTestJudge(t, root, fp, false)
	j.judgeOne(context.Background(), f)

	sent := fp.sent()
	for _, secret := range []string{short, awsKey} {
		if strings.Contains(sent, secret) {
			t.Errorf("secret %q reached the provider", secret)
		}
	}
	if !strings.Contains(sent, redactedMark) {
		t.Error("expected a redaction mark in the prompt")
	}
	if !strings.Contains(sent, "package main") {
		t.Error("surrounding code should still be sent")
	}
}

func TestJudgeOne_SnippetUnavailableNeverCallsProvider(t *testing.T) {
	root, outsideFile := workspace(t)
	tests := []struct {
		name string
		file string
		root string
		want string
	}{
		{"absolute path", outsideFile, root, "outside_workspace"},
		{"escape", "../outside/secret.txt", root, "outside_workspace"},
		{"no workspace root", "src/app.go", "", "no_workspace"},
		{"missing file", "src/missing.go", root, "unreadable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &fakeProvider{}
			j := newTestJudge(t, tt.root, fp, false)
			f := srcFinding("fp", "TAINT-001", 5)
			f.Location.FilePath = tt.file
			v := j.judgeOne(context.Background(), f)
			if v.verdict != verdictUncertain || !strings.Contains(v.rationale, tt.want) {
				t.Errorf("verdict = %+v, want uncertain mentioning %q", v, tt.want)
			}
			if fp.calls.Load() != 0 {
				t.Error("provider was called without a snippet")
			}
			if strings.Contains(v.rationale, outsideFile) {
				t.Errorf("rationale leaks a path: %q", v.rationale)
			}
		})
	}
}

func TestJudgeOne_CacheHitMakesNoCall(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	j := newTestJudge(t, root, fp, true)
	f := srcFinding("fp1", "TAINT-001", 50)

	first := j.judgeOne(context.Background(), f)
	second := j.judgeOne(context.Background(), f)
	if fp.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", fp.calls.Load())
	}
	if first.cached || !second.cached {
		t.Errorf("cached flags = %v, %v; want false, true", first.cached, second.cached)
	}
	if first.verdict != second.verdict || first.rationale != second.rationale {
		t.Errorf("cached answer differs: %+v vs %+v", first, second)
	}

	// A different model must not be served the old verdict.
	j.model = "other-model"
	j.judgeOne(context.Background(), f)
	if fp.calls.Load() != 2 {
		t.Errorf("model change should miss the cache; calls = %d", fp.calls.Load())
	}

	// Changed source must miss too.
	j.model = "fake-model"
	writeLines(t, filepath.Join(root, "src", "app.go"), 100, "edited")
	j.judgeOne(context.Background(), f)
	if fp.calls.Load() != 3 {
		t.Errorf("source change should miss the cache; calls = %d", fp.calls.Load())
	}
}

func TestJudgeOne_CacheDisabledAlwaysCalls(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	j := newTestJudge(t, root, fp, false)
	f := srcFinding("fp1", "TAINT-001", 50)
	j.judgeOne(context.Background(), f)
	j.judgeOne(context.Background(), f)
	if fp.calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", fp.calls.Load())
	}
}

func TestJudgeOne_ErrorsAreClassifiedAndNotCached(t *testing.T) {
	root, _ := workspace(t)
	const leaked = "SECRET-RESPONSE-BODY-do-not-echo"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"rate limited", providers.ErrRateLimited, errClassRateLimited},
		{"missing key", providers.ErrMissingAPIKey, errClassAuth},
		{"connection", fmt.Errorf("%w: dial tcp: %s", providers.ErrConnectionFailed, leaked), errClassConnection},
		{"deadline", context.DeadlineExceeded, errClassTimeout},
		{"canceled", providers.ErrContextCanceled, errClassTimeout},
		{"http 401", fmt.Errorf("API error (status 401): %s", leaked), "http_401"},
		{"http 500", fmt.Errorf("API error (status 500): %s", leaked), "http_500"},
		{"other", errors.New(leaked), errClassProvider},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &fakeProvider{reply: func(plannerllm.CompletionRequest) (string, error) { return "", tt.err }}
			j := newTestJudge(t, root, fp, true)
			v := j.judgeOne(context.Background(), srcFinding("fp", "TAINT-001", 50))
			if v.verdict != verdictUncertain || !strings.Contains(v.rationale, tt.want) {
				t.Fatalf("verdict = %+v, want uncertain with %q", v, tt.want)
			}
			if strings.Contains(v.rationale, leaked) {
				t.Errorf("rationale echoes provider text: %q", v.rationale)
			}
			entries, _ := os.ReadDir(j.cache.dir)
			if len(entries) != 0 {
				t.Errorf("an error was cached: %v", entries)
			}
		})
	}
}

func TestJudgeOne_PerCallTimeout(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{reply: func(plannerllm.CompletionRequest) (string, error) {
		time.Sleep(2 * time.Second)
		return "TRUE_POSITIVE", nil
	}}
	slow := &ctxProvider{inner: fp}
	j := newTestJudge(t, root, slow, false)
	j.cfg.Timeout = 50 * time.Millisecond
	start := time.Now()
	v := j.judgeOne(context.Background(), srcFinding("fp", "TAINT-001", 50))
	if time.Since(start) > time.Second {
		t.Error("per-call timeout was not applied")
	}
	if v.verdict != verdictUncertain || !strings.Contains(v.rationale, errClassTimeout) {
		t.Errorf("verdict = %+v", v)
	}
}

// ctxProvider honours context cancellation the way a real HTTP client does.
type ctxProvider struct{ inner *fakeProvider }

func (c *ctxProvider) Name() string { return "ctx" }

//nolint:gocritic // signature fixed by plannerllm.Provider
func (c *ctxProvider) Complete(ctx context.Context, req plannerllm.CompletionRequest) (plannerllm.CompletionResponse, error) {
	type result struct {
		resp plannerllm.CompletionResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		r, err := c.inner.Complete(ctx, req)
		ch <- result{r, err}
	}()
	select {
	case r := <-ch:
		return r.resp, r.err
	case <-ctx.Done():
		return plannerllm.CompletionResponse{}, ctx.Err()
	}
}

func TestParseVerdict(t *testing.T) {
	tests := []struct {
		name          string
		reply         string
		wantVerdict   string
		wantRationale string
	}{
		{"true positive", "TRUE_POSITIVE\nUser input reaches the query.", verdictTruePositive, "User input reaches the query."},
		{"false positive", "FALSE_POSITIVE\nConstant.", verdictFalsePositive, "Constant."},
		{"uncertain", "UNCERTAIN\nNot enough context.", verdictUncertain, "Not enough context."},
		{"spaced and bold", "**True Positive**\nreason", verdictTruePositive, "reason"},
		{"blank lines first", "\n\nFALSE POSITIVE\nreason", verdictFalsePositive, "reason"},
		{"both on first line", "TRUE_POSITIVE or FALSE_POSITIVE\nhm", verdictUncertain, "hm"},
		{"verdict only in prose", "I think this is fine.\nTRUE_POSITIVE", verdictUncertain, "TRUE_POSITIVE"},
		{"empty", "", verdictUncertain, ""},
		{"no rationale", "TRUE_POSITIVE", verdictTruePositive, ""},
		{"long rationale", "TRUE_POSITIVE\n" + strings.Repeat("a", 1000), verdictTruePositive, strings.Repeat("a", maxRationaleRunes) + "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, r := parseVerdict(tt.reply)
			if v != tt.wantVerdict || r != tt.wantRationale {
				t.Errorf("parseVerdict = (%q, %q), want (%q, %q)", v, r, tt.wantVerdict, tt.wantRationale)
			}
		})
	}
}

func TestSelectCandidates(t *testing.T) {
	mk := func(fp string, sev pluginv1.Severity, conf pluginv1.Confidence, rule string) *pluginv1.Finding {
		return &pluginv1.Finding{Fingerprint: fp, RuleId: rule, Severity: sev, Confidence: conf,
			Location: &pluginv1.Location{FilePath: "src/app.go", StartLine: 1}}
	}
	findings := []*pluginv1.Finding{
		mk("low", sdk.SeverityLow, sdk.ConfidenceHigh, "R-1"),
		mk("crit", sdk.SeverityCritical, sdk.ConfidenceHigh, "R-2"),
		mk("crit", sdk.SeverityCritical, sdk.ConfidenceHigh, "R-2"), // duplicate
		mk("", sdk.SeverityCritical, sdk.ConfidenceHigh, "R-3"),     // no fingerprint: cannot be anchored
		mk("high", sdk.SeverityHigh, sdk.ConfidenceHigh, "R-4"),
		mk("skipme", sdk.SeverityHigh, sdk.ConfidenceHigh, "NOISE-1"),
	}
	fps := func(fs []*pluginv1.Finding) string {
		var out []string
		for _, f := range fs {
			out = append(out, f.GetFingerprint())
		}
		return strings.Join(out, ",")
	}
	tests := []struct {
		name string
		cfg  aiConfig
		want string
	}{
		{"all, most urgent first, deduped", aiConfig{}, "crit,high,skipme,low"},
		{"capped keeps the most urgent", aiConfig{MaxFindings: 2}, "crit,high"},
		{"min severity", aiConfig{Gates: triageGates{MinSeverity: 3}}, "crit,high,skipme"},
		{"skip rules", aiConfig{Gates: triageGates{SkipRules: []string{"NOISE-*"}}}, "crit,high,low"},
		{"only rules", aiConfig{Gates: triageGates{OnlyRules: []string{"R-4"}}}, "high"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := fps(selectCandidates(findings, &tt.cfg)); got != tt.want {
				t.Errorf("selectCandidates = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRun_ConcurrencyIsBoundedAndOrderIsStable(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{reply: func(req plannerllm.CompletionRequest) (string, error) {
		time.Sleep(20 * time.Millisecond)
		return "TRUE_POSITIVE\nok", nil
	}}
	j := newTestJudge(t, root, fp, false)
	j.cfg.Concurrency = 3
	var findings []*pluginv1.Finding
	for i := range 12 {
		findings = append(findings, srcFinding(fmt.Sprintf("fp%02d", i), "TAINT-001", int32(10+i)))
	}
	got := j.run(context.Background(), findings)
	if len(got) != len(findings) {
		t.Fatalf("verdicts = %d, want %d", len(got), len(findings))
	}
	for i, v := range got {
		if v.fingerprint != findings[i].GetFingerprint() {
			t.Errorf("verdict %d fingerprint = %q, want %q", i, v.fingerprint, findings[i].GetFingerprint())
		}
	}
	if peak := fp.peak.Load(); peak > 3 {
		t.Errorf("peak concurrency = %d, want <= 3", peak)
	}
}

func TestRun_ExpiredBudgetStopsCallsAndContinues(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	j := newTestJudge(t, root, fp, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := j.run(ctx, []*pluginv1.Finding{srcFinding("a", "R", 5), srcFinding("b", "R", 6)})
	if fp.calls.Load() != 0 {
		t.Errorf("calls = %d after the budget expired", fp.calls.Load())
	}
	for _, v := range got {
		if v.verdict != verdictUncertain || !strings.Contains(v.rationale, errClassBudget) {
			t.Errorf("verdict = %+v", v)
		}
	}
}

func TestBoundedContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bounded, bcancel := boundedContext(ctx, 10*time.Second)
	defer bcancel()
	dl, _ := ctx.Deadline()
	bdl, ok := bounded.Deadline()
	if !ok || !bdl.Before(dl) {
		t.Errorf("bounded deadline %v is not earlier than %v", bdl, dl)
	}
	noDL, c := boundedContext(context.Background(), time.Second)
	defer c()
	if _, ok := noDL.Deadline(); ok {
		t.Error("a context without a deadline should stay without one")
	}
}

func TestLoadAIConfig(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	tests := []struct {
		name  string
		input map[string]any
		env   map[string]string
		check func(aiConfig) string
	}{
		{"defaults", nil, nil, func(c aiConfig) string {
			if c.Enabled || !c.UseCache || c.MaxFindings != 200 || c.Concurrency != 4 || c.Timeout != 60*time.Second {
				return fmt.Sprintf("%+v", c)
			}
			return ""
		}},
		{"input wins over env", map[string]any{"ai_triage": true, "ai_cache": false, "ai_max_findings": float64(5), "ai_concurrency": float64(2), "ai_timeout": float64(9)},
			map[string]string{"NOX_AI_TRIAGE": "false", "NOX_AI_CACHE": "true", "NOX_AI_MAX_FINDINGS": "77"},
			func(c aiConfig) string {
				if !c.Enabled || c.UseCache || c.MaxFindings != 5 || c.Concurrency != 2 || c.Timeout != 9*time.Second {
					return fmt.Sprintf("%+v", c)
				}
				return ""
			}},
		{"env only", nil, map[string]string{"NOX_AI_TRIAGE": "1", "NOX_AI_CACHE": "0", "NOX_AI_MAX_FINDINGS": "7", "NOX_AI_CONCURRENCY": "3", "NOX_AI_TIMEOUT": "30"},
			func(c aiConfig) string {
				if !c.Enabled || c.UseCache || c.MaxFindings != 7 || c.Concurrency != 3 || c.Timeout != 30*time.Second {
					return fmt.Sprintf("%+v", c)
				}
				return ""
			}},
		{"bad values fall back", map[string]any{"ai_max_findings": float64(-3), "ai_concurrency": float64(0)},
			map[string]string{"NOX_AI_TIMEOUT": "soon"},
			func(c aiConfig) string {
				if c.MaxFindings != 200 || c.Concurrency != 4 || c.Timeout != 60*time.Second {
					return fmt.Sprintf("%+v", c)
				}
				return ""
			}},
		{"concurrency is capped", map[string]any{"ai_concurrency": float64(5000)}, nil,
			func(c aiConfig) string {
				if c.Concurrency != maxConcurrency {
					return fmt.Sprintf("%+v", c)
				}
				return ""
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if bad := tt.check(loadAIConfig(tt.input, env(tt.env))); bad != "" {
				t.Errorf("unexpected config: %s", bad)
			}
		})
	}
}

func TestProviderErrClass_Unwrapped(t *testing.T) {
	if got := providerErrClass(fmt.Errorf("wrapped: %w", providers.ErrRateLimited)); got != errClassRateLimited {
		t.Errorf("got %q", got)
	}
}
