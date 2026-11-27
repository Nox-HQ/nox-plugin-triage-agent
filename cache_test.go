package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCacheKey(t *testing.T) {
	base := cacheKey("fp", "snippet", "v0.1.0", "anthropic", "m1")
	if again := cacheKey("fp", "snippet", "v0.1.0", "anthropic", "m1"); again != base {
		t.Fatal("key is not deterministic")
	}
	variants := map[string]string{
		"fingerprint": cacheKey("fp2", "snippet", "v0.1.0", "anthropic", "m1"),
		"snippet":     cacheKey("fp", "snippet2", "v0.1.0", "anthropic", "m1"),
		"pack":        cacheKey("fp", "snippet", "v0.2.0", "anthropic", "m1"),
		"provider":    cacheKey("fp", "snippet", "v0.1.0", "openai", "m1"),
		"model":       cacheKey("fp", "snippet", "v0.1.0", "anthropic", "m2"),
		"boundary":    cacheKey("f", "psnippet", "v0.1.0", "anthropic", "m1"),
	}
	for field, k := range variants {
		if k == base {
			t.Errorf("changing %s did not change the key", field)
		}
	}
}

func TestVerdictCache_RoundTrip(t *testing.T) {
	c := &verdictCache{dir: filepath.Join(t.TempDir(), "nested")}
	if _, ok := c.get("k"); ok {
		t.Fatal("hit on empty cache")
	}
	want := cachedVerdict{Verdict: verdictFalsePositive, Rationale: "parameterized"}
	if err := c.put("k", want); err != nil {
		t.Fatal(err)
	}
	got, ok := c.get("k")
	if !ok || got != want {
		t.Fatalf("get = %+v, %v; want %+v", got, ok, want)
	}
	info, err := os.Stat(c.path("k"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("cache entry is readable by others: %v", perm)
	}
}

func TestVerdictCache_CorruptEntryIsAMiss(t *testing.T) {
	dir := t.TempDir()
	c := &verdictCache{dir: dir}
	for name, content := range map[string]string{
		"garbage": "not json",
		"unknown": `{"verdict":"maybe"}`,
		"empty":   ``,
	} {
		if err := os.WriteFile(c.path(name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, ok := c.get(name); ok {
			t.Errorf("%s entry was served", name)
		}
	}
}

func TestVerdictCache_NilIsDisabled(t *testing.T) {
	var c *verdictCache
	if _, ok := c.get("k"); ok {
		t.Error("nil cache hit")
	}
	if err := c.put("k", cachedVerdict{Verdict: verdictUncertain}); err != nil {
		t.Errorf("nil cache put: %v", err)
	}
}

func TestDefaultCacheDir(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", "")
	dir, err := defaultCacheDir()
	if err != nil {
		t.Skipf("no user cache dir here: %v", err)
	}
	if filepath.Base(dir) != "triage-agent" || filepath.Base(filepath.Dir(dir)) != "nox" {
		t.Errorf("dir = %q, want .../nox/triage-agent", dir)
	}
}
