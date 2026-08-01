package main

import (
	"os"
	"regexp"
	"strings"
)

// These guards exist because a line-level regex cannot tell code from text
// about code, nor "reads user input" from "reads user input without checking
// it". Both were measured against nox's precision corpus, whose clean_*
// fixtures are curated to produce zero findings.

// commentPrefixes are line-comment markers per extension. Block comments are
// deliberately not tracked: that needs a lexer, and the dominant case is a
// single-line note quoting a dangerous call.
var commentPrefixes = map[string][]string{
	".go": {"//"},
	".js": {"//"},
	".ts": {"//"},
	".py": {"#"},
}

// isCommentLine reports whether the whole line is a line comment.
//
// TRIAGE-001 fired on `os.system(user_cmd)` quoted inside a `#` comment
// explaining what an earlier version used to do. Prose describing a dangerous
// call is not a dangerous call.
func isCommentLine(line, ext string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	for _, p := range commentPrefixes[ext] {
		if strings.HasPrefix(trimmed, p) {
			return true
		}
	}
	return false
}

// sanitizers recognise validation or canonicalisation applied to the value on
// the same line. TRIAGE-002 claims "missing input validation on external data";
// when a recognised validator wraps the read, that claim is simply false.
//
// It fired on `strconv.Atoi(r.FormValue("count"))` — a coercion to int, which
// cannot carry injection metacharacters — and on
// `filepath.Base(filepath.Clean(r.URL.Query().Get("path")))`, which cannot
// traverse. Both are the textbook safe forms.
var sanitizers = map[string]*regexp.Regexp{
	".go": regexp.MustCompile(`(?i)(strconv\.(Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)|filepath\.(Clean|Base)|path\.(Clean|Base)|url\.Parse|uuid\.Parse|html\.EscapeString|template\.HTMLEscape)`),
	".py": regexp.MustCompile(`(?i)(\bint\(|\bfloat\(|\bbool\(|os\.path\.(basename|normpath)|shlex\.quote|html\.escape|urllib\.parse\.quote)`),
	".js": regexp.MustCompile(`(?i)(parseInt\(|parseFloat\(|Number\(|encodeURIComponent\(|path\.(basename|normalize)\()`),
	".ts": regexp.MustCompile(`(?i)(parseInt\(|parseFloat\(|Number\(|encodeURIComponent\(|path\.(basename|normalize)\()`),
}

// isSanitized reports whether a recognised validator appears on the line.
func isSanitized(line, ext string) bool {
	re, ok := sanitizers[ext]
	return ok && re.MatchString(line)
}

// autoescapedRE detects a Go file that renders through html/template, whose
// contextual auto-escaping neutralises whatever the request supplied.
var autoescapedRE = regexp.MustCompile(`"html/template"`)

// escapeBypassRE detects the constructs that opt OUT of that escaping. If any
// appear, the file gets no benefit of the doubt.
var escapeBypassRE = regexp.MustCompile(`(template\.HTML\(|template\.JS\(|template\.URL\(|"text/template")`)

// fileIsAutoescaped reports whether a Go file renders exclusively through
// html/template.
//
// This is the one cross-line judgement here, and it is deliberately narrow.
// TRIAGE-002 fired on `Name: r.URL.Query().Get("name")` assigned into a struct
// that is then executed by an html/template — safe because of where the value
// GOES, which a line-level rule cannot see. Reading the file once for the
// import, and refusing the exemption when any escape-bypass construct is
// present, keeps the heuristic honest: a file that opts out of escaping
// anywhere loses it everywhere.
func fileIsAutoescaped(filePath, ext string) bool {
	if ext != ".go" {
		return false
	}
	data, err := os.ReadFile(filePath) //nolint:gosec // path comes from the scan target
	if err != nil {
		return false
	}
	return autoescapedRE.Match(data) && !escapeBypassRE.Match(data)
}
