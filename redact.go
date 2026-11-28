package main

import (
	"math"
	"regexp"
	"strings"
)

// Redaction runs on every snippet BEFORE it leaves the process. It is
// deliberately over-eager: a masked benign string costs the model a little
// context, while an unmasked credential is disclosed to a third party.
//
// nox core's plugin Redactor is not reused: it redacts plugin OUTPUT with a
// short pattern list, its string method is unexported, and the patterns here
// must also cover quoted high-entropy values and whole PEM blocks.

const redactedMark = "[REDACTED]"

// credentialPatterns match well-known token shapes anywhere in a line.
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b`),
	regexp.MustCompile(`\bgh[opsur]_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{30,}`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
	regexp.MustCompile(`(?i)(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{20,}`),
	regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s/:@'"]+:[^\s/@'"]+@`),
}

// A PEM private-key block is masked line by line so line numbers survive: the
// BEGIN line and everything up to and including the END line become the mark. A
// snippet window can cut a key in half; the half it shows is still key
// material, so an unterminated block runs to the end of the snippet.
var (
	pemBegin = regexp.MustCompile(`-{5}BEGIN [A-Z ]*PRIVATE KEY-{5}`)
	pemEnd   = regexp.MustCompile(`-{5}END [A-Z ]*PRIVATE KEY-{5}`)
)

var (
	quotedLiteral = regexp.MustCompile("(\"(?:[^\"\\\\\\n]|\\\\.)*\"|'(?:[^'\\\\\\n]|\\\\.)*'|`[^`\\n]*`)")
	quotedToken   = regexp.MustCompile("[\"'`]([A-Za-z0-9+/=_-]{24,})[\"'`]")
	// keyValue splits `name = value`, `name: value` and `NAME=value`.
	keyValue = regexp.MustCompile(`^(\s*[A-Za-z0-9_.\-\[\]"']+\s*(?::=|[:=])\s*)(\S.*)$`)
	// base64Line is a line that is only base64: the body of a PEM block whose
	// BEGIN line fell outside the snippet window.
	base64Line = regexp.MustCompile(`^\s*[A-Za-z0-9+/]{40,}={0,2}\s*$`)
	longToken  = regexp.MustCompile(`[A-Za-z0-9+/=_-]{20,}`)
)

// minEntropyBitsPerChar is the floor for a quoted token to count as random. A
// 24-character token from a 36-symbol alphabet lands near 3.5 often enough
// that 3.5 let about 1 in 4,000 through; strings that read as identifiers are
// exempted before this test, so a lower floor costs little benign context.
const minEntropyBitsPerChar = 3.25

// redactText masks credential shapes in free text (a message). It does not
// know which line a finding is on.
func redactText(s string) string {
	return strings.Join(redactLines(strings.Split(s, "\n")), "\n")
}

// redactLines masks credential shapes in each line, preserving the line count.
func redactLines(lines []string) []string {
	out := make([]string, len(lines))
	inKey := false
	for i, l := range lines {
		if inKey {
			out[i] = redactedMark
			inKey = !pemEnd.MatchString(l)
			continue
		}
		if loc := pemBegin.FindStringIndex(l); loc != nil {
			out[i] = l[:loc[0]] + redactedMark
			inKey = !pemEnd.MatchString(l[loc[1]:])
			continue
		}
		out[i] = redactLine(l)
	}
	return out
}

func redactLine(l string) string {
	for _, p := range credentialPatterns {
		l = p.ReplaceAllString(l, redactedMark)
	}
	l = quotedToken.ReplaceAllStringFunc(l, func(m string) string {
		if looksHighEntropy(m[1 : len(m)-1]) {
			return m[:1] + redactedMark + m[len(m)-1:]
		}
		return m
	})
	if base64Line.MatchString(l) {
		return redactedMark
	}
	return l
}

// maskValueLine is the stricter pass for the line a SECRET finding matched. It
// does not try to find the credential, because the scanner already decided that
// line holds one and a missed pattern is the failure to avoid. Every string
// literal and every assigned value is masked, and so is any long token left.
func maskValueLine(line string) string {
	line = quotedLiteral.ReplaceAllStringFunc(line, func(m string) string {
		return m[:1] + redactedMark + m[len(m)-1:]
	})
	if m := keyValue.FindStringSubmatch(line); len(m) == 3 && !strings.Contains(m[2], redactedMark) {
		line = m[1] + redactedMark
	}
	return longToken.ReplaceAllString(line, redactedMark)
}

// redactSnippet redacts a snippet's lines for egress, preserving the line
// count. Lines in secretLines (0-based) are the ones the finding points at; they
// are value-masked first when isSecret is set.
func redactSnippet(lines []string, secretLines map[int]bool, isSecret bool) []string {
	pre := make([]string, len(lines))
	for i, l := range lines {
		if isSecret && secretLines[i] {
			l = maskValueLine(l)
		}
		pre[i] = l
	}
	return redactLines(pre)
}

// isSecretRule reports whether a rule ID belongs to nox's secrets family.
func isSecretRule(ruleID string) bool {
	return strings.HasPrefix(ruleID, "SEC-")
}

// looksHighEntropy reports whether s reads like a random token rather than an
// identifier or word: it mixes letters and digits and its character
// distribution is flat.
func looksHighEntropy(s string) bool {
	var hasDigit, hasLetter bool
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
			hasLetter = true
		}
	}
	if !hasDigit || !hasLetter {
		return false
	}
	// Hex carries at most 4 bits a character, so a 24-character hex key often
	// falls under the entropy threshold. Mixed hex of credential length is
	// masked outright; a commit hash or checksum goes with it.
	if hexToken.MatchString(s) {
		return true
	}
	return !looksIdentifier(s) && shannonEntropy(s) >= minEntropyBitsPerChar
}

var hexToken = regexp.MustCompile(`^(?:[0-9a-f]+|[0-9A-F]+)$`)

// identifierShape is a name built from word parts: letters and digits joined by
// '_', '-' or '.', starting with a letter. Base64 characters ('+', '/', '=')
// rule it out.
var identifierShape = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[_.-][A-Za-z0-9]+)*$`)

// looksIdentifier reports whether s reads as a name a person wrote, such as
// processPaymentRequestHandlerV2 or user_profile_settings_cache_ttl_2, rather
// than a generated token. Split into camelCase words (each lower, Capitalised
// or an ACRONYM, by construction of identifierParts), a name is words mostly
// three letters or
// longer (ID, By and V in findUserIDByEmailAddressV2 are the most it has), plus
// at most a couple of short numbers. A random token breaks into many one- and
// two-letter fragments.
func looksIdentifier(s string) bool {
	if !identifierShape.MatchString(s) || digitInsideWord.MatchString(s) || capsAgainstDigit.MatchString(s) {
		return false
	}
	var words, short, digitParts, letters int
	for _, part := range identifierParts(s) {
		if part[0] >= '0' && part[0] <= '9' {
			digitParts++
			continue
		}
		if !wordLike(part) {
			return false
		}
		words++
		letters += len(part)
		if len(part) <= 2 || !hasVowel(part) {
			short++ // fragments, and vowelless runs such as ctx or a random "Gsml"
		}
	}
	// Names average 3.6 letters a word or more (findUserIDByEmailAddressV2 is
	// the low end); random mixed case fragments to about 2.8.
	return words > 0 && digitParts <= 2 && short <= 3 && 2*letters >= 7*words
}

// digitInsideWord is a number with a lowercase letter on both sides. In a name
// a number ends a word (V2, ttl_2, base64Encode); inside a word it is a token.
var digitInsideWord = regexp.MustCompile(`[a-z]\d+[a-z]`)

// capsAgainstDigit is six or more capitals touching a number. An acronym next to
// a number is short (V2, SHA256, HTTP2); a long capital run there is a token.
var capsAgainstDigit = regexp.MustCompile(`\d[A-Z]{6,}|[A-Z]{6,}\d`)

// wordLike rejects letter runs no one writes: longer than any word, or long and
// short of vowels (written words are about two-fifths vowels, random letters
// under a fifth). It errs toward masking, so a rare consonant-heavy word such
// as "strengths" next to a digit is masked; that costs the model context, not
// a disclosure.
func wordLike(w string) bool {
	if len(w) > 20 {
		return false
	}
	if len(w) < 5 {
		return true // abbreviations: ttl, ctx, cfg, src
	}
	vowels := 0
	for _, r := range strings.ToLower(w) {
		if strings.ContainsRune("aeiouy", r) {
			vowels++
		}
	}
	return vowels*4 >= len(w)
}

func hasVowel(w string) bool {
	return strings.ContainsAny(strings.ToLower(w), "aeiouy")
}

// identifierParts splits s at '_', '-', '.', at a lower-to-upper case change
// and at every letter/digit boundary.
func identifierParts(s string) []string {
	var parts []string
	start := 0
	isDigit := func(c byte) bool { return c >= '0' && c <= '9' }
	isLower := func(c byte) bool { return c >= 'a' && c <= 'z' }
	isUpper := func(c byte) bool { return c >= 'A' && c <= 'Z' }
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '_' || c == '-' || c == '.' {
			if i > start {
				parts = append(parts, s[start:i])
			}
			start = i + 1
			continue
		}
		if i > start {
			p := s[i-1]
			// The acronym rule splits "IDFor" before the F: an upper run
			// followed by a lower letter ends one letter early.
			acronymEnd := isUpper(p) && isUpper(c) && i+1 < len(s) && isLower(s[i+1])
			if isDigit(p) != isDigit(c) || (isLower(p) && isUpper(c)) || acronymEnd {
				parts = append(parts, s[start:i])
				start = i
			}
		}
	}
	if start < len(s) {
		parts = append(parts, s[start:])
	}
	return parts
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	return h
}
