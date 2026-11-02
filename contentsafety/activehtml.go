package contentsafety

import (
	"html"
	"path"
	"regexp"
	"strings"
)

// activeHTMLRuleID is the ActiveHTML family's one rule.
const activeHTMLRuleID = "INF-SEC-023"

const activeHTMLDescription = "Active HTML in markdown — script, frame, event handler or javascript: URL that runs in the reader's browser"

// scriptScheme is a URL scheme that runs script when followed.
const scriptScheme = `(?:javascript|vbscript|data:text/html)`

// activeHTMLPatterns match a line, or a tag joined onto one line, after code
// is blanked. Each is also tried on the text with HTML entities decoded and
// the characters a browser ignores in a URL removed, so
// `<iframe srcdoc="&lt;script&gt;…">` and `jav&#x0A;ascript:` are both seen.
var activeHTMLPatterns = compilePatterns(
	`(?i)<\s*/?\s*(?:script|iframe|frame|frameset|object|embed|applet|base|portal|style)\b`,
	`(?i)<\s*meta\b[^>]*\bhttp-equiv`,
	`(?i)\bsrcdoc\s*=`,
	// An event handler attribute inside a tag: <img src=x onerror=…>.
	`(?i)<[a-z][^>]*?[\s/"']on[a-z]+\s*=`,
	// A form that posts to another origin.
	`(?i)<\s*form\b[^>]*\baction\s*=\s*["']?\s*(?:[a-z][a-z0-9+.-]*:)?//`,
	// A script URL in an attribute, a markdown link, a reference
	// definition ([1]: javascript:…) or an autolink (<javascript:…>).
	`(?i)(?:href|src|action|formaction|data|xlink:href|poster|background)\s*=\s*["']?\s*`+scriptScheme,
	`(?i)\]\(\s*<?\s*`+scriptScheme,
	`(?i)^\s{0,3}\[[^\]]+\]:\s*<?\s*`+scriptScheme,
	`(?i)<\s*(?:javascript:|vbscript:|data:text/html)`,
)

// urlIgnored is what a browser strips from a URL before reading its scheme:
// tab, line feed, carriage return (and NUL).
var urlIgnored = strings.NewReplacer("\t", "", "\n", "", "\r", "", "\x00", "")

// tagSpan is one tag, which may run over several lines.
var tagSpan = regexp.MustCompile(`<[A-Za-z!/][^<>]*>`)

// contentKind is how a file reaches a reader's browser.
type contentKind int

const (
	notRendered     contentKind = iota
	markdownContent             // rendered as markdown: code is text
	htmlContent                 // markup as written: nothing is masked
)

func kindOf(p string) contentKind {
	if p == "" {
		return markdownContent
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".md", ".markdown", ".mdx":
		return markdownContent
	case ".html", ".htm", ".svg", "":
		return htmlContent
	}
	return notRendered
}

func detectActiveHTML(result *Result, filePath, content string) {
	kind := kindOf(filePath)
	if kind == notRendered {
		return
	}
	lines := strings.Split(content, "\n")
	if kind == markdownContent {
		lines = maskMarkdownCode(lines)
	}
	flagged := map[int]bool{}
	report := func(lineNum int, match string) {
		if flagged[lineNum] {
			return
		}
		flagged[lineNum] = true
		result.Findings = append(result.Findings, Finding{
			RuleID:      activeHTMLRuleID,
			Severity:    SeverityCritical,
			Description: activeHTMLDescription,
			File:        filePath,
			Line:        lineNum + 1,
			Match:       truncateMatch(match),
		})
		if severityRank(SeverityCritical) > severityRank(result.Severity) {
			result.Severity = SeverityCritical
		}
	}

	for lineNum, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if m, ok := matchActiveHTML(line); ok {
			report(lineNum, m)
		}
	}

	// A tag broken over lines (<img src=x\nonerror=…>, href="java\nscript:")
	// is not on any one line: match each multi-line tag joined up, once with
	// its line breaks as spaces (attributes) and once with them removed
	// (a URL, where the browser drops them).
	masked := strings.Join(lines, "\n")
	for _, loc := range tagSpan.FindAllStringIndex(masked, -1) {
		tag := masked[loc[0]:loc[1]]
		if !strings.ContainsAny(tag, "\r\n") {
			continue
		}
		lineNum := strings.Count(masked[:loc[0]], "\n")
		spaced := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(tag)
		for _, variant := range []string{spaced, urlIgnored.Replace(tag)} {
			if m, ok := matchActiveHTML(variant); ok {
				report(lineNum, m)
				break
			}
		}
	}
}

// matchActiveHTML tries every pattern on text as written and on text with
// entities decoded and URL-ignored characters removed.
func matchActiveHTML(text string) (string, bool) {
	decoded := urlIgnored.Replace(html.UnescapeString(text))
	for _, p := range activeHTMLPatterns {
		for _, candidate := range []string{text, decoded} {
			if loc := p.FindStringIndex(candidate); loc != nil {
				return candidate[loc[0]:loc[1]], true
			}
		}
	}
	return "", false
}

// fence opens or closes a fenced code block: up to three spaces of indent,
// then three or more backticks or tildes, then the info string.
var fence = regexp.MustCompile("^ {0,3}(`{3,}|~{3,})(.*)$")

// maskMarkdownCode blanks fenced code blocks and inline code spans, which
// markdown renders as text, keeping the line count so findings keep their
// line numbers. Where CommonMark is subtle it errs toward scanning: a span
// or fence that does not close on its own terms is left in.
func maskMarkdownCode(lines []string) []string {
	out := make([]string, len(lines))
	open := ""
	for i, line := range lines {
		if m := fence.FindStringSubmatch(line); m != nil {
			marker, rest := m[1], m[2]
			switch {
			case open == "":
				// A backtick fence's info string may not contain a
				// backtick (CommonMark): "```foo`" is inline code.
				if marker[0] == '`' && strings.Contains(rest, "`") {
					break
				}
				open = marker
				continue
			case marker[0] == open[0] && len(marker) >= len(open) && strings.TrimSpace(rest) == "":
				open = ""
				continue
			}
		}
		if open != "" {
			continue
		}
		out[i] = maskCodeSpans(line)
	}
	return out
}

// maskCodeSpans blanks inline code on one line: a run of n backticks closed
// by the next run of exactly n. An unclosed run is literal backticks.
func maskCodeSpans(line string) string {
	b := []byte(line)
	for i := 0; i < len(b); {
		if b[i] != '`' {
			i++
			continue
		}
		n := runLen(b, i)
		closeAt := -1
		for j := i + n; j < len(b); {
			if b[j] != '`' {
				j++
				continue
			}
			m := runLen(b, j)
			if m == n {
				closeAt = j
				break
			}
			j += m
		}
		if closeAt < 0 {
			i += n
			continue
		}
		for k := i; k < closeAt+n; k++ {
			b[k] = ' '
		}
		i = closeAt + n
	}
	return string(b)
}

func runLen(b []byte, i int) int {
	n := 0
	for i+n < len(b) && b[i+n] == '`' {
		n++
	}
	return n
}
