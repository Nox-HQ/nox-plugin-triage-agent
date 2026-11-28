package main

import (
	"math/rand"
	"strings"
	"testing"
)

const (
	upperAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	mixedAlnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b64Chars   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

// token builds a deterministic pseudo-random token. Seeded so a failure
// reproduces and so no real-looking credential is ever typed by hand.
func token(r *rand.Rand, prefix string, n int, alphabet string) string {
	var b strings.Builder
	b.WriteString(prefix)
	for range n {
		b.WriteByte(alphabet[r.Intn(len(alphabet))])
	}
	return b.String()
}

func TestRedactText_MasksCredentialShapes(t *testing.T) {
	r := rand.New(rand.NewSource(20260801))
	tests := []struct {
		name string
		line string
	}{
		{"aws access key", "aws_key = " + token(r, "AKIA", 16, upperAlnum)},
		{"github pat", "token: " + token(r, "ghp_", 36, mixedAlnum)},
		{"github fine-grained", "token: " + token(r, "github_pat_", 40, mixedAlnum)},
		{"slack bot", "SLACK=" + token(r, "xoxb-", 30, mixedAlnum)},
		{"slack app", "SLACK=" + token(r, "xoxa-", 30, mixedAlnum)},
		{"slack user", "SLACK=" + token(r, "xoxp-", 30, mixedAlnum)},
		{"sk key", "OPENAI=" + token(r, "sk-", 40, mixedAlnum)},
		{"jwt", "auth = " + token(r, "eyJ", 20, mixedAlnum) + "." + token(r, "", 20, mixedAlnum) + "." + token(r, "", 20, mixedAlnum)},
		{"bearer header", "Authorization: Bearer " + token(r, "", 40, mixedAlnum)},
		{"url credentials", "dsn = postgres://admin:" + token(r, "", 18, mixedAlnum) + "@db.internal/app"},
		{"quoted high entropy", `secretValue := "` + token(r, "", 32, mixedAlnum) + `"`},
		{"quoted base64", `blob = '` + token(r, "", 44, b64Chars) + `'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redactText(tt.line)
			if !strings.Contains(got, redactedMark) {
				t.Fatalf("nothing redacted in %q -> %q", tt.line, got)
			}
			secret := secretPart(tt.line)
			if secret != "" && strings.Contains(got, secret) {
				t.Fatalf("secret %q survived in %q", secret, got)
			}
		})
	}
}

// secretPart returns the longest alphanumeric run of the line, the generated token.
func secretPart(line string) string {
	best, cur := "", ""
	for _, c := range line + " " {
		if strings.ContainsRune(mixedAlnum+"_-+/", c) {
			cur += string(c)
			continue
		}
		if len(cur) > len(best) {
			best = cur
		}
		cur = ""
	}
	if len(best) < 20 {
		return ""
	}
	return best
}

func TestRedactText_PrivateKeyBlock(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	body1, body2 := token(r, "", 64, b64Chars), token(r, "", 64, b64Chars)
	lines := []string{
		"before()",
		"-----BEGIN RSA PRIVATE KEY-----",
		body1,
		body2,
		"-----END RSA PRIVATE KEY-----",
		"after()",
	}
	got := redactLines(lines)
	if len(got) != len(lines) {
		t.Fatalf("line count changed: %d -> %d", len(lines), len(got))
	}
	joined := strings.Join(got, "\n")
	for _, secret := range []string{body1, body2, "PRIVATE KEY"} {
		if strings.Contains(joined, secret) {
			t.Errorf("%q survived: %q", secret, joined)
		}
	}
	if got[0] != "before()" || got[5] != "after()" {
		t.Errorf("surrounding code was altered: %q", got)
	}
}

func TestRedactLines_KeyBodyWithoutBeginIsMasked(t *testing.T) {
	r := rand.New(rand.NewSource(8))
	body := token(r, "", 64, b64Chars)
	got := redactLines([]string{"x := 1", body, "y := 2"})
	if strings.Contains(strings.Join(got, "\n"), body) {
		t.Fatalf("base64 body survived: %q", got)
	}
}

func TestRedactText_LeavesOrdinaryCodeAlone(t *testing.T) {
	code := []string{
		`query := "SELECT id FROM users WHERE name = ?"`,
		`path := filepath.Join(root, "internal", "handlers")`,
		`const message = "the quick brown fox jumps over the lazy dog"`,
		`return fmt.Sprintf("%s:%d", host, port)`,
		`longIdentifierNameThatIsJustCamelCaseWithoutDigits := 1`,
		// What a triage verdict depends on must survive: sinks, sources,
		// routes, annotations and module paths, including ones with digits.
		`rows, err := db.Query("SELECT * FROM users WHERE id = " + r.URL.Query().Get("id"))`,
		`@GetMapping("/api/v2/accounts/{accountId}/transactions")`,
		`import "github.com/nox-hq/nox-core/evidence/v2"`,
		`handler := "processPaymentRequestHandlerV2"`,
		`lookup := "findUserIDByEmailAddressV2"`,
		`codec := "base64EncodeResponseBody"`,
		`cfg.Set("user_profile_settings_cache_ttl_2", 300)`,
		`@PreAuthorize("hasRole('ADMIN') and #userId == authentication.principal.id")`,
		`app.post('/users/:id/reset-password', requireAuth, resetPassword)`,
		`subprocess.run(["git", "clone", repo_url], check=True)`,
	}
	for _, line := range code {
		if got := redactText(line); got != line {
			t.Errorf("benign line changed:\n  in:  %q\n  out: %q", line, got)
		}
	}
}

func TestMaskValueLine(t *testing.T) {
	r := rand.New(rand.NewSource(99))
	v := token(r, "", 18, mixedAlnum) // short, low-risk-looking: only the secret-rule path catches it
	tests := []struct {
		name string
		line string
	}{
		{"double quoted", `password = "` + v + `"`},
		{"single quoted", `PASSWORD = '` + v + `'`},
		{"go define", `apiSecret := "` + v + `"`},
		{"yaml", `db_password: ` + v},
		{"env file", `DB_PASSWORD=` + v},
		{"unquoted long token", `export TOKEN ` + token(r, "", 30, mixedAlnum)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskValueLine(tt.line)
			if !strings.Contains(got, redactedMark) {
				t.Fatalf("not masked: %q", got)
			}
			if run := secretPart(strings.Replace(tt.line, "export", "", 1)); run != "" && strings.Contains(got, run) {
				t.Fatalf("value survived: %q", got)
			}
			if strings.Contains(got, v) {
				t.Fatalf("value survived: %q", got)
			}
		})
	}
}

func TestRedactSnippet_SecretRuleMasksFocusLineOnly(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	v := token(r, "", 16, mixedAlnum)
	lines := []string{`const retries = "3"`, `pw := "` + v + `"`, `name := "bob"`}
	got := redactSnippet(lines, map[int]bool{1: true}, true)
	if strings.Contains(strings.Join(got, "\n"), v) {
		t.Fatalf("secret survived: %q", got)
	}
	if got[0] != lines[0] || got[2] != lines[2] {
		t.Errorf("non-focus lines were changed: %q", got)
	}

	plain := redactSnippet(lines, map[int]bool{1: true}, false)
	if plain[1] != lines[1] {
		t.Errorf("non-secret rule should not value-mask a low-entropy line, got %q", plain[1])
	}
}

func TestIsSecretRule(t *testing.T) {
	for id, want := range map[string]bool{"SEC-001": true, "SEC-661": true, "TAINT-014": false, "": false, "xSEC-1": false} {
		if got := isSecretRule(id); got != want {
			t.Errorf("isSecretRule(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestRedactText_RandomQuotedTokensStayMasked falsifies the identifier
// exemption in looksHighEntropy: seeded random base62 tokens of credential
// length, in every alphabet mix a generator uses, must all still be masked.
func TestRedactText_RandomQuotedTokensStayMasked(t *testing.T) {
	alphabets := []string{
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"abcdefghijklmnopqrstuvwxyz0123456789",
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
		"0123456789abcdef",
		"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-",
	}
	r := rand.New(rand.NewSource(20261128))
	for _, alphabet := range alphabets {
		for i := 0; i < 2000; i++ {
			n := 24 + r.Intn(41)
			b := make([]byte, n)
			for j := range b {
				b[j] = alphabet[r.Intn(len(alphabet))]
			}
			tok := string(b)
			if !strings.ContainsAny(tok, "0123456789") || strings.Trim(tok, "0123456789_-") == "" {
				continue // no letters or no digits: not what the entropy pass targets
			}
			line := `key := "` + tok + `"`
			if got := redactText(line); !strings.Contains(got, redactedMark) {
				t.Fatalf("random token survived redaction: %q", tok)
			}
		}
	}
}

// TestRedactText_WitnessTokensStayMasked pins random tokens that a 1.6M-token
// seeded probe found leaking through one guard of looksHighEntropy each, so
// removing any guard fails here even when the smaller seeded sample misses it.
func TestRedactText_WitnessTokensStayMasked(t *testing.T) {
	witnesses := map[string]string{
		"camelCase word shape":   "bRouSgOOusCpkovkkdeZc49XAKfbepNvPZrhlVRSXdqpINAME9Fri",
		"word length":            "zasw43kgbhnefbaavhrokyhrbrmo4iz",
		"digit inside a word":    "tvusryp5mxgbw5542sdegddc",
		"capitals against digit": "UXEX73THMSIAOZXSZYTQUNZQEN6I",
		"hex":                    "f4253a7e32c4e9fe9073c401",
		"short-part cap":         "gjaHvhOedpmxkNZGATWPIEihXj0U42Lwxj",
		"digit-part cap":         "RFYIZ1BSXAI4BBZK5ADP6ZDRL6",
		"vowelless part":         "QshhiweeymUvCmzjRvnb3Y86xIuvPizYHPY",
		"average word length":    "lTjyBANZuro8L93NgZeqBjohUAFQ",
		"entropy floor":          "NVDPOLYSSSONDDID3SDPOM22H8PS",
	}
	for guard, tok := range witnesses {
		if got := redactText(`key := "` + tok + `"`); !strings.Contains(got, redactedMark) {
			t.Errorf("%s: token survived redaction: %q", guard, tok)
		}
	}
}
