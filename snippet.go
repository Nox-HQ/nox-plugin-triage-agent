package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	snippetRadius   = 20
	snippetMaxBytes = 6 * 1024
	// maxLineBytes bounds one line so a minified file cannot dominate a prompt.
	maxLineBytes = 400
	// maxFileScanBytes bounds how much of a file is read looking for the window.
	maxFileScanBytes = 8 * 1024 * 1024
)

var (
	errOutsideWorkspace = errors.New("path is outside the workspace")
	errNoWorkspace      = errors.New("no workspace root")
	errNotRegular       = errors.New("not a regular file")
)

// snippet is a window of source lines. first is the 1-based number of lines[0]
// and focus the 0-based index of the finding's line within lines.
type snippet struct {
	lines []string
	first int
	focus map[int]bool
}

// confinePath resolves file against root and returns the real path, or an error
// when the file is not strictly inside the workspace. It rejects absolute paths
// and ".." escapes lexically, then resolves symlinks on both sides so a link
// inside the workspace cannot lead out of it.
func confinePath(root, file string) (string, error) {
	if root == "" {
		return "", errNoWorkspace
	}
	if file == "" || strings.ContainsRune(file, 0) {
		return "", errOutsideWorkspace
	}
	if filepath.IsAbs(file) || filepath.VolumeName(file) != "" ||
		strings.HasPrefix(file, "/") || strings.HasPrefix(file, `\`) {
		return "", errOutsideWorkspace
	}
	clean := filepath.Clean(filepath.FromSlash(file))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errOutsideWorkspace
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolving workspace: %w", err)
	}
	realRoot, err := filepath.EvalSymlinks(absRoot)
	if err != nil {
		return "", fmt.Errorf("resolving workspace: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.Join(realRoot, clean))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(realRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", errOutsideWorkspace
	}
	return resolved, nil
}

// readSnippet reads up to radius lines either side of line from a file confined
// to root. The raw lines are returned: redaction must see whole lines, and the
// byte cap is applied afterwards by capSnippet.
func readSnippet(root, file string, line, radius int) (snippet, error) {
	if line <= 0 {
		return snippet{}, errors.New("no line number")
	}
	path, err := confinePath(root, file)
	if err != nil {
		return snippet{}, err
	}
	f, err := os.Open(path) //nolint:gosec // path was confined to the workspace by confinePath
	if err != nil {
		return snippet{}, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return snippet{}, err
	}
	if !info.Mode().IsRegular() {
		return snippet{}, errNotRegular
	}

	start := max(line-radius, 1)
	end := line + radius
	br := bufio.NewReader(io.LimitReader(f, maxFileScanBytes))
	var lines []string
	for n := 1; n <= end; n++ {
		text, rerr := readBoundedLine(br)
		if n >= start && (text != "" || rerr == nil) {
			lines = append(lines, text)
		}
		if rerr != nil {
			break
		}
	}
	if len(lines) == 0 || start+len(lines)-1 < line {
		return snippet{}, errors.New("line is past the end of the file")
	}
	return snippet{lines: lines, first: start, focus: map[int]bool{line - start: true}}, nil
}

// readBoundedLine reads one line, discarding anything past 1 MiB so a hostile
// file cannot exhaust memory, and returns io.EOF after the final line.
func readBoundedLine(br *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		chunk, isPrefix, err := br.ReadLine()
		if err != nil {
			return b.String(), err
		}
		if b.Len() < 1<<20 {
			b.Write(chunk)
		}
		if !isPrefix {
			return b.String(), nil
		}
	}
}

// focusRange widens the focus to the finding's full line span.
func (s *snippet) focusRange(startLine, endLine int) {
	for l := startLine; l <= endLine; l++ {
		if i := l - s.first; i >= 0 && i < len(s.lines) {
			s.focus[i] = true
		}
	}
}

// capSnippet limits redacted text to maxBytes by shortening long lines and then
// dropping the lines farthest from the focus. It runs AFTER redaction because a
// token cut in half by truncation would no longer match a credential pattern.
func capSnippet(lines []string, focus, maxBytes int) string {
	shortened := make([]string, len(lines))
	for i, l := range lines {
		if len(l) > maxLineBytes {
			l = l[:maxLineBytes] + " ..."
		}
		shortened[i] = l
	}
	lo, hi := 0, len(shortened)
	size := func() int {
		n := 0
		for _, l := range shortened[lo:hi] {
			n += len(l) + 1
		}
		return n
	}
	for size() > maxBytes && hi-lo > 1 {
		if focus-lo >= hi-1-focus {
			lo++
		} else {
			hi--
		}
	}
	return strings.Join(shortened[lo:hi], "\n")
}
