package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// workspace builds a temp workspace and a sibling "outside" directory holding a
// file that must never be readable through the workspace.
func workspace(t *testing.T) (root, outsideFile string) {
	t.Helper()
	base := t.TempDir()
	root = filepath.Join(base, "ws")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(root, "src"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outsideFile = filepath.Join(outside, "secret.txt")
	writeLines(t, outsideFile, 5, "outside")
	writeLines(t, filepath.Join(root, "src", "app.go"), 100, "inside")
	return root, outsideFile
}

func writeLines(t *testing.T, path string, n int, tag string) {
	t.Helper()
	var b strings.Builder
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, "%s line %d\n", tag, i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestConfinePath_Escapes(t *testing.T) {
	root, outsideFile := workspace(t)
	if err := os.Symlink(outsideFile, filepath.Join(root, "src", "link-file")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Dir(outsideFile), filepath.Join(root, "src", "link-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("app.go", filepath.Join(root, "src", "link-inside")); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		file    string
		wantErr bool
	}{
		{"plain relative", "src/app.go", false},
		{"dot segments inside", "src/../src/app.go", false},
		{"symlink to a file inside", "src/link-inside", false},
		{"absolute path", outsideFile, true},
		{"absolute path to workspace file", filepath.Join(root, "src", "app.go"), true},
		{"leading slash", "/etc/passwd", true},
		{"backslash root", `\windows\system32`, true},
		{"parent escape", "../outside/secret.txt", true},
		{"bare dotdot", "..", true},
		{"deep parent escape", "src/../../outside/secret.txt", true},
		{"symlinked file leaving root", "src/link-file", true},
		{"file through symlinked dir leaving root", "src/link-dir/secret.txt", true},
		{"empty", "", true},
		{"nul byte", "src/app.go\x00.txt", true},
		{"missing file", "src/nope.go", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := confinePath(root, tt.file)
			if (err != nil) != tt.wantErr {
				t.Fatalf("confinePath(%q) err = %v, wantErr %v", tt.file, err, tt.wantErr)
			}
			if err == nil {
				realRoot, _ := filepath.EvalSymlinks(root)
				if !strings.HasPrefix(got, realRoot+string(filepath.Separator)) {
					t.Errorf("resolved path %q is not under %q", got, realRoot)
				}
			}
		})
	}
}

func TestConfinePath_EscapeErrorsAreClassified(t *testing.T) {
	root, outsideFile := workspace(t)
	for _, file := range []string{outsideFile, "../outside/secret.txt"} {
		if _, err := confinePath(root, file); !errors.Is(err, errOutsideWorkspace) {
			t.Errorf("confinePath(%q) = %v, want errOutsideWorkspace", file, err)
		}
	}
	if _, err := confinePath("", "src/app.go"); !errors.Is(err, errNoWorkspace) {
		t.Errorf("empty root: %v, want errNoWorkspace", err)
	}
}

func TestReadSnippet_Window(t *testing.T) {
	root, _ := workspace(t)
	tests := []struct {
		name      string
		line      int
		wantFirst int
		wantLines int
	}{
		{"middle", 50, 30, 41},
		{"near top", 3, 1, 23},
		{"near end", 98, 78, 23},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := readSnippet(root, "src/app.go", tt.line, 20)
			if err != nil {
				t.Fatal(err)
			}
			if s.first != tt.wantFirst || len(s.lines) != tt.wantLines {
				t.Errorf("first=%d lines=%d, want %d/%d", s.first, len(s.lines), tt.wantFirst, tt.wantLines)
			}
			want := fmt.Sprintf("inside line %d", tt.line)
			if got := s.lines[tt.line-s.first]; got != want {
				t.Errorf("focus line = %q, want %q", got, want)
			}
		})
	}
}

func TestReadSnippet_Rejects(t *testing.T) {
	root, outsideFile := workspace(t)
	tests := []struct {
		name string
		file string
		line int
	}{
		{"outside", "../outside/secret.txt", 2},
		{"absolute", outsideFile, 2},
		{"zero line", "src/app.go", 0},
		{"past end", "src/app.go", 500},
		{"directory", "src", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readSnippet(root, tt.file, tt.line, 20); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestCapSnippet(t *testing.T) {
	lines := make([]string, 41)
	for i := range lines {
		lines[i] = strings.Repeat("x", 99)
	}
	lines[20] = "FOCUS"
	got := capSnippet(lines, 20, 1000)
	if len(got) > 1000 {
		t.Errorf("len = %d, want <= 1000", len(got))
	}
	if !strings.Contains(got, "FOCUS") {
		t.Error("focus line was dropped")
	}

	long := []string{strings.Repeat("y", 5000)}
	if got := capSnippet(long, 0, 6000); len(got) > maxLineBytes+10 {
		t.Errorf("long line not shortened: %d bytes", len(got))
	}
}
