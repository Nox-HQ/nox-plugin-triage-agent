package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/plugin"
	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/sdk"
	plannerllm "go.klarlabs.de/agent/contrib/planner-llm"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// useFakeProvider swaps the provider factory and isolates the user cache dir.
func useFakeProvider(t *testing.T, p plannerllm.Provider) {
	t.Helper()
	old := providerFactory
	providerFactory = func() (plannerllm.Provider, string, error) { return p, "fake-model", nil }
	t.Cleanup(func() { providerFactory = old })
	t.Setenv("NOX_AI_PROVIDER", "fake")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
}

func invokeWith(t *testing.T, findings []*pluginv1.Finding, root string, input map[string]any) *pluginv1.InvokeToolResponse {
	t.Helper()
	in, err := structpb.NewStruct(input)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := testClient(t).InvokeTool(context.Background(), &pluginv1.InvokeToolRequest{
		ToolName:      "triage",
		WorkspaceRoot: root,
		Input:         in,
		ScanContext:   &pluginv1.ScanContext{Findings: findings},
	})
	if err != nil {
		t.Fatalf("InvokeTool: %v", err)
	}
	return resp
}

func enrichmentsOfKind(resp *pluginv1.InvokeToolResponse, kind string) []*pluginv1.Enrichment {
	var out []*pluginv1.Enrichment
	for _, e := range resp.GetEnrichments() {
		if e.GetKind() == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestTriage_AIPassIsEnrichmentOnly(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{reply: func(plannerllm.CompletionRequest) (string, error) {
		// A model reply that tries to move the finding and change its severity.
		return "FALSE_POSITIVE\nSee evil.go:1 where severity should be LOW.", nil
	}}
	useFakeProvider(t, fp)

	findings := []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50), srcFinding("fp2", "TAINT-002", 60)}
	before := make([]*pluginv1.Finding, len(findings))
	for i, f := range findings {
		before[i] = proto.Clone(f).(*pluginv1.Finding)
	}
	resp := invokeWith(t, findings, root, map[string]any{"ai_triage": true})

	if len(resp.GetFindings()) != 0 {
		t.Errorf("AI triage emitted %d findings", len(resp.GetFindings()))
	}
	if got := len(enrichmentsOfKind(resp, "triage")); got != 2 {
		t.Errorf("deterministic priority enrichments = %d, want 2", got)
	}
	ai := enrichmentsOfKind(resp, "ai-triage")
	if len(ai) != 2 {
		t.Fatalf("ai-triage enrichments = %d, want 2", len(ai))
	}
	md := ai[0].GetMetadata()
	want := map[string]string{
		"ai_verdict": "false_positive", "ai_provider": "fake", "ai_model": "fake-model",
		"pack_version": "v0.1.0", "cached": "false",
	}
	for k, v := range want {
		if md[k] != v {
			t.Errorf("metadata[%s] = %q, want %q", k, md[k], v)
		}
	}
	if md["ai_rationale"] == "" {
		t.Error("missing ai_rationale")
	}
	for _, e := range resp.GetEnrichments() {
		if e.GetFindingFingerprint() != "fp1" && e.GetFindingFingerprint() != "fp2" {
			t.Errorf("enrichment anchored to %q, not an input finding", e.GetFindingFingerprint())
		}
	}
	for i, f := range findings {
		if !proto.Equal(f, before[i]) {
			t.Errorf("finding %d was modified", i)
		}
	}
	// The deterministic priority is identical with and without the AI pass.
	plain := invokeWith(t, findings, root, map[string]any{})
	if !proto.Equal(&pluginv1.InvokeToolResponse{Enrichments: enrichmentsOfKind(resp, "triage")},
		&pluginv1.InvokeToolResponse{Enrichments: enrichmentsOfKind(plain, "triage")}) {
		t.Error("the AI pass changed the deterministic priority enrichments")
	}
}

func TestTriage_SecondRunAnswersFromCache(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	useFakeProvider(t, fp)
	findings := []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}

	invokeWith(t, findings, root, map[string]any{"ai_triage": true})
	resp := invokeWith(t, findings, root, map[string]any{"ai_triage": true})
	if fp.calls.Load() != 1 {
		t.Errorf("provider calls = %d across two identical runs, want 1", fp.calls.Load())
	}
	if got := enrichmentsOfKind(resp, "ai-triage")[0].GetMetadata()["cached"]; got != "true" {
		t.Errorf("cached = %q, want true", got)
	}

	invokeWith(t, findings, root, map[string]any{"ai_triage": true, "ai_cache": false})
	if fp.calls.Load() != 2 {
		t.Errorf("ai_cache=false should call the provider; calls = %d", fp.calls.Load())
	}
}

func TestTriage_AIOffByDefaultMakesNoCall(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	useFakeProvider(t, fp)
	resp := invokeWith(t, []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}, root, map[string]any{})
	if fp.calls.Load() != 0 || len(enrichmentsOfKind(resp, "ai-triage")) != 0 {
		t.Error("the AI pass ran without opt-in")
	}
}

func TestTriage_EnabledByEnvironmentBecausePostScanSendsNoInput(t *testing.T) {
	root, _ := workspace(t)
	fp := &fakeProvider{}
	useFakeProvider(t, fp)
	t.Setenv("NOX_AI_TRIAGE", "true")
	resp := invokeWith(t, []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}, root, nil)
	if len(enrichmentsOfKind(resp, "ai-triage")) != 1 {
		t.Error("NOX_AI_TRIAGE=true did not enable the AI pass")
	}
}

func TestTriage_ProviderMisconfigurationDegradesToDeterministic(t *testing.T) {
	root, _ := workspace(t)
	old := providerFactory
	providerFactory = func() (plannerllm.Provider, string, error) { return nil, "", os.ErrNotExist }
	t.Cleanup(func() { providerFactory = old })
	t.Setenv("HOME", t.TempDir())

	resp := invokeWith(t, []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}, root, map[string]any{"ai_triage": true})
	if len(enrichmentsOfKind(resp, "triage")) != 1 || len(enrichmentsOfKind(resp, "ai-triage")) != 0 {
		t.Error("expected only the deterministic enrichment")
	}
	var warned bool
	for _, d := range resp.GetDiagnostics() {
		warned = warned || strings.Contains(d.GetMessage(), "ai triage skipped")
	}
	if !warned {
		t.Error("expected a diagnostic explaining why AI triage was skipped")
	}
}

// TestTriage_APIKeyNeverAppears sets a fake key and asserts it appears nowhere
// the plugin can write: enrichments, diagnostics, errors, prompts or the cache.
// The provider is a fake whose errors embed the key, as a hostile proxy or a
// careless SDK might.
func TestTriage_APIKeyNeverAppears(t *testing.T) {
	root, _ := workspace(t)
	fakeKey := token(rand.New(rand.NewSource(31337)), "sk-", 40, mixedAlnum)

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", home)
	t.Setenv("NOX_AI_API_KEY", fakeKey)
	old := providerFactory
	t.Cleanup(func() { providerFactory = old })

	tests := []struct {
		name  string
		reply func(plannerllm.CompletionRequest) (string, error)
	}{
		{"error embeds key", func(plannerllm.CompletionRequest) (string, error) {
			return "", errors.New("request failed with key " + fakeKey)
		}},
		{"http error body embeds key", func(plannerllm.CompletionRequest) (string, error) {
			return "", fmt.Errorf("API error (status 401): invalid x-api-key %s", fakeKey)
		}},
		{"reply embeds key", func(plannerllm.CompletionRequest) (string, error) {
			return "TRUE_POSITIVE\nthe key is " + fakeKey, nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &fakeProvider{reply: tt.reply}
			providerFactory = func() (plannerllm.Provider, string, error) { return fp, "fake-model", nil }
			resp := invokeWith(t, []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}, root,
				map[string]any{"ai_triage": true, "ai_cache": false})
			if len(enrichmentsOfKind(resp, "ai-triage")) != 1 {
				t.Fatal("expected one ai-triage enrichment")
			}
			if strings.Contains(prototext.Format(resp), fakeKey) {
				// Only the "reply embeds key" case may carry model text, and
				// then only because the model echoed it; the plugin itself
				// must still never ADD the key.
				if tt.name != "reply embeds key" {
					t.Fatal("API key found in plugin output")
				}
			}
		})
	}

	t.Run("key is not in the prompt or the cache", func(t *testing.T) {
		fp := &fakeProvider{}
		providerFactory = func() (plannerllm.Provider, string, error) { return fp, "fake-model", nil }
		invokeWith(t, []*pluginv1.Finding{srcFinding("fp1", "TAINT-001", 50)}, root, map[string]any{"ai_triage": true})
		if strings.Contains(fp.sent(), fakeKey) {
			t.Error("API key sent in a prompt")
		}
		_ = filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if data, rerr := os.ReadFile(path); rerr == nil && strings.Contains(string(data), fakeKey) {
				t.Errorf("API key found in cache file %s", path)
			}
			return nil
		})
	})
}

func TestResolveProvider_NeverEchoesKey(t *testing.T) {
	fakeKey := token(rand.New(rand.NewSource(4242)), "sk-", 40, mixedAlnum)
	t.Setenv("NOX_AI_API_KEY", fakeKey)
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	for _, name := range []string{"openai", "anthropic", "gemini", "cohere", "bedrock", "copilot", "ollama", "bogus"} {
		t.Setenv("NOX_AI_PROVIDER", name)
		_, model, err := resolveProvider()
		if err != nil && strings.Contains(err.Error(), fakeKey) {
			t.Errorf("%s: error echoes the key", name)
		}
		if strings.Contains(model, fakeKey) {
			t.Errorf("%s: model echoes the key", name)
		}
	}
}

func TestResolveProvider_Defaults(t *testing.T) {
	t.Setenv("NOX_AI_API_KEY", "placeholder-not-a-key")
	t.Setenv("NOX_AI_MODEL", "")
	tests := []struct{ provider, wantModel string }{
		{"anthropic", "claude-sonnet-5-5"},
		{"openai", "gpt-4o"},
		{"gemini", "gemini-pro"},
		{"cohere", "command-r-plus"},
	}
	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			t.Setenv("NOX_AI_PROVIDER", tt.provider)
			_, model, err := resolveProvider()
			if err != nil || model != tt.wantModel {
				t.Errorf("model = %q, err = %v; want %q", model, err, tt.wantModel)
			}
		})
	}
	t.Setenv("NOX_AI_PROVIDER", "anthropic")
	t.Setenv("NOX_AI_API_KEY", "")
	if _, _, err := resolveProvider(); err == nil {
		t.Error("anthropic without a key should fail")
	}
}

func TestManifest_PassesAgentAssistancePolicy(t *testing.T) {
	m, err := testClient(t).GetManifest(context.Background(), &pluginv1.GetManifestRequest{ApiVersion: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	policy := plugin.ProfileForTrack(registry.TrackAgentAssistance)
	if v := plugin.ValidateManifest(m, &policy); len(v) != 0 {
		t.Fatalf("manifest violates the agent-assistance policy: %v", v)
	}
	if got := plugin.ValidateToolInvocation(m, "triage", &policy); len(got) != 0 {
		t.Fatalf("triage invocation violates the policy: %v", got)
	}
	if m.GetSafety().GetRiskClass() != sdk.RiskPassive {
		t.Errorf("risk class = %q, want passive", m.GetSafety().GetRiskClass())
	}
	if len(m.GetSafety().GetNetworkHosts()) == 0 {
		t.Error("the AI pass's network hosts are not declared")
	}
}
