package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// verdictCache stores judged verdicts on disk so a re-run with identical inputs
// answers without a model call. The key covers everything that can change the
// answer: the finding, the redacted code the model saw, the pack, the provider
// and the model. Only the redacted snippet's hash is part of the key, and only
// the verdict and a short rationale are stored; no source ever reaches the cache.
type verdictCache struct {
	dir string
}

// cachedVerdict is the stored form of a verdict.
type cachedVerdict struct {
	Verdict   string `json:"verdict"`
	Rationale string `json:"rationale"`
}

// defaultCacheDir is os.UserCacheDir()/nox/triage-agent.
func defaultCacheDir() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("locating user cache dir: %w", err)
	}
	return filepath.Join(base, "nox", "triage-agent"), nil
}

// cacheKey is sha256 over the fields that determine a verdict. Fields are
// NUL-separated so ("ab","c") and ("a","bc") cannot collide.
func cacheKey(fingerprint, redactedSnippet, packVersion, provider, model string) string {
	snippetSum := sha256.Sum256([]byte(redactedSnippet))
	h := sha256.New()
	for _, part := range []string{fingerprint, hex.EncodeToString(snippetSum[:]), packVersion, provider, model} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *verdictCache) path(key string) string {
	return filepath.Join(c.dir, key+".json")
}

// get returns a stored verdict. A missing, unreadable or malformed entry is a
// miss, never an error: the cache is an optimisation.
func (c *verdictCache) get(key string) (cachedVerdict, bool) {
	if c == nil {
		return cachedVerdict{}, false
	}
	data, err := os.ReadFile(c.path(key))
	if err != nil {
		return cachedVerdict{}, false
	}
	var v cachedVerdict
	if json.Unmarshal(data, &v) != nil || !validVerdict(v.Verdict) {
		return cachedVerdict{}, false
	}
	return v, true
}

// put stores a verdict atomically (write to a temp file, then rename) so a
// concurrent reader never sees a partial entry.
func (c *verdictCache) put(key string, v cachedVerdict) error {
	if c == nil {
		return nil
	}
	if err := os.MkdirAll(c.dir, 0o700); err != nil {
		return fmt.Errorf("creating cache dir: %w", err)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating cache entry: %w", err)
	}
	_, werr := tmp.Write(data)
	cerr := tmp.Close()
	if err := errors.Join(werr, cerr); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("writing cache entry: %w", err)
	}
	if err := os.Rename(tmp.Name(), c.path(key)); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("committing cache entry: %w", err)
	}
	return nil
}
