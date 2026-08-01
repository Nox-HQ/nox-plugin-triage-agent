package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Every line here is real, taken from nox's precision corpus. The clean_*
// fixtures are curated to produce zero findings, so each was a measured false
// positive.
func TestIsCommentLine(t *testing.T) {
	// clean_prose_comments.py:2 — a dangerous call quoted as prose.
	if !isCommentLine("# and called os.system(user_cmd) directly. Both are quoted", ".py") {
		t.Error("python comment not recognised")
	}
	if !isCommentLine("\t// exec.Command(userInput) would be unsafe here", ".go") {
		t.Error("go comment not recognised")
	}
	// Code must never be mistaken for prose about code.
	if isCommentLine("os.system(user_cmd)", ".py") {
		t.Error("executable code treated as a comment")
	}
	if isCommentLine("out, _ := exec.Command(c).Output() // note", ".go") {
		t.Error("code with a trailing comment is still code")
	}
}

func TestIsSanitized(t *testing.T) {
	sanitized := []string{
		`	count, err := strconv.Atoi(r.FormValue("count"))`,                     // clean_field_safe.go:27
		`	safePath := filepath.Base(filepath.Clean(r.URL.Query().Get("path")))`, // clean_field_safe.go:32
	}
	for _, line := range sanitized {
		if !isSanitized(line, ".go") {
			t.Errorf("recognised sanitizer missed: %s", line)
		}
	}

	// A raw read with nothing applied must still be reported — the rule's whole
	// purpose. Suppressing this would trade false positives for a blind spot.
	raw := `	name := r.URL.Query().Get("name")`
	if isSanitized(raw, ".go") {
		t.Errorf("an unvalidated read was treated as sanitized: %s", raw)
	}
}

func TestFileIsAutoescaped(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		return p
	}

	// clean_html_autoescape.go: renders through html/template, which escapes.
	safe := write("safe.go", "package w\n\nimport \"html/template\"\n\nvar page = template.Must(template.New(\"p\").Parse(\"{{.Name}}\"))\n")
	if !fileIsAutoescaped(safe, ".go") {
		t.Error("html/template file not recognised as auto-escaped")
	}

	// A file that opts out of escaping anywhere loses the exemption everywhere.
	for name, body := range map[string]string{
		"bypass.go": "package w\n\nimport \"html/template\"\n\nvar x = template.HTML(userInput)\n",
		"text.go":   "package w\n\nimport \"text/template\"\n",
	} {
		if fileIsAutoescaped(write(name, body), ".go") {
			t.Errorf("%s: escape bypass did not revoke the exemption", name)
		}
	}

	// Non-Go files never qualify.
	if fileIsAutoescaped(write("x.py", "import html"), ".py") {
		t.Error("non-Go file wrongly exempted")
	}
}
