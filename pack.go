package main

import (
	"embed"
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
)

// The triage pack is the versioned prompt material: a base system prompt,
// per-class instructions and an optional examples hook. It is embedded so a
// verdict is reproducible from the plugin binary alone, and its version is part
// of every cache key so a pack change never serves stale verdicts.
//
//go:embed all:pack
var packFS embed.FS

// vulnClass groups CWEs that call for the same reasoning.
type vulnClass string

const (
	classInjection       vulnClass = "injection"
	classCryptoSecrets   vulnClass = "crypto_secrets_config"
	classAuthentication  vulnClass = "authentication_session"
	classAuthorization   vulnClass = "authorization"
	classInfoExposure    vulnClass = "information_exposure"
	classMassAssignment  vulnClass = "mass_assignment"
	classOther           vulnClass = "other"
	snippetCloseTag                = "</code_snippet>"
	snippetCloseTagSplit           = "</ code_snippet>"
)

var cweClasses = map[int]vulnClass{
	89: classInjection, 78: classInjection, 79: classInjection, 22: classInjection,
	918: classInjection, 94: classInjection, 502: classInjection, 611: classInjection, 601: classInjection,
	798: classCryptoSecrets, 327: classCryptoSecrets, 328: classCryptoSecrets,
	330: classCryptoSecrets, 916: classCryptoSecrets,
	639: classAuthorization, 862: classAuthorization, 863: classAuthorization,
	284: classAuthorization, 285: classAuthorization,
	200: classInfoExposure, 209: classInfoExposure, 532: classInfoExposure, 215: classInfoExposure,
	307: classAuthentication, 287: classAuthentication, 306: classAuthentication,
	352: classAuthentication, 384: classAuthentication,
	915: classMassAssignment,
}

var cweNumber = regexp.MustCompile(`(?i)(?:cwe[-_ ]?)?(\d{1,5})`)

// classForFinding selects the instruction class from the finding's CWE
// metadata. The first CWE that maps to a class wins; no CWE means "other".
func classForFinding(f *pluginv1.Finding) vulnClass {
	raw := f.GetMetadata()["cwe"]
	for _, m := range cweNumber.FindAllStringSubmatch(raw, -1) {
		var n int
		if _, err := fmt.Sscanf(m[1], "%d", &n); err != nil {
			continue
		}
		if c, ok := cweClasses[n]; ok {
			return c
		}
	}
	return classOther
}

// triagePack is the loaded, versioned prompt material.
type triagePack struct {
	version string
	system  string
	fsys    fs.FS
}

// loadPack reads the embedded pack. It fails loudly on a missing file, since a
// pack without its version or system prompt would make cached verdicts
// meaningless.
func loadPack() (*triagePack, error) {
	return loadPackFrom(packFS, "pack")
}

func loadPackFrom(fsys fs.FS, dir string) (*triagePack, error) {
	sub, err := fs.Sub(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("triage pack: %w", err)
	}
	version, err := fs.ReadFile(sub, "VERSION")
	if err != nil {
		return nil, fmt.Errorf("triage pack: reading VERSION: %w", err)
	}
	system, err := fs.ReadFile(sub, "system.md")
	if err != nil {
		return nil, fmt.Errorf("triage pack: reading system.md: %w", err)
	}
	return &triagePack{
		version: strings.TrimSpace(string(version)),
		system:  strings.TrimSpace(string(system)),
		fsys:    sub,
	}, nil
}

// systemPrompt returns the system prompt for a class: the base prompt, the
// class instructions, and the class's worked examples when the examples/ hook
// holds any. A missing class or examples file is not an error; the base prompt
// alone is a valid prompt.
func (p *triagePack) systemPrompt(c vulnClass) string {
	var b strings.Builder
	b.WriteString(p.system)
	if s := p.read("classes/" + string(c) + ".md"); s != "" {
		b.WriteString("\n\n")
		b.WriteString(s)
	}
	if s := p.read("examples/" + string(c) + ".md"); s != "" {
		b.WriteString("\n\nWorked examples:\n")
		b.WriteString(s)
	}
	return b.String()
}

func (p *triagePack) read(name string) string {
	data, err := fs.ReadFile(p.fsys, name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// userPrompt renders the per-finding message. The snippet must already be
// redacted. Rule, message and location are immutable context; nothing the model
// answers is ever used to derive a location.
func userPrompt(f *pluginv1.Finding, redactedMessage, redactedSnippet string) string {
	var b strings.Builder
	b.WriteString("Finding under review (immutable):\n")
	fmt.Fprintf(&b, "Rule: %s\n", f.GetRuleId())
	if cwe := f.GetMetadata()["cwe"]; cwe != "" {
		fmt.Fprintf(&b, "CWE: %s\n", cwe)
	}
	fmt.Fprintf(&b, "Severity: %s\n", f.GetSeverity().String())
	fmt.Fprintf(&b, "Message: %s\n", redactedMessage)
	if loc := f.GetLocation(); loc != nil {
		fmt.Fprintf(&b, "Location: %s:%d\n", loc.GetFilePath(), loc.GetStartLine())
	}
	b.WriteString("\nCode context (untrusted data):\n<code_snippet>\n")
	b.WriteString(strings.ReplaceAll(redactedSnippet, snippetCloseTag, snippetCloseTagSplit))
	b.WriteString("\n</code_snippet>\n")
	return b.String()
}
