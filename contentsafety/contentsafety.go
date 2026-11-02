// Package contentsafety inspects and sanitizes untrusted content.
//
// It covers two threats that share one rule corpus:
//
//   - secrets leaking outward — credentials that ended up in content we serve;
//   - instructions leaking inward — prompt injection aimed at an agent that
//     reads the content.
//
// Two verbs apply the same rules for different purposes. Detect reports
// findings without modifying anything, for a publish or upload gate where a
// human sees the result. Clean rewrites matches in place, for content served
// straight to an agent where nobody reviews the outcome.
//
// Those verbs have opposite tolerances for a false positive: a noisy Detect
// costs someone a triage, while a noisy Clean silently corrupts a document. So
// every rule declares which verbs it is precise enough for, and Clean only ever
// applies rules marked CleanSafe.
package contentsafety

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"

	"github.com/inference-sh/goutils/internal/escmask"
)

// RuleSet selects which families of rules to apply. Values are bit flags, so a
// caller composes exactly the coverage it wants.
type RuleSet uint16

const (
	// Credentials matches API keys, tokens, private keys, and connection
	// strings — including belt's own key format.
	Credentials RuleSet = 1 << iota

	// Injection matches attempts to override an agent's instructions.
	Injection

	// SpecialTokens matches chat-template delimiters that could forge a role
	// boundary in a model's context.
	SpecialTokens

	// HiddenContent matches text concealed from human review: zero-width
	// characters, direction overrides, script in non-visible areas.
	HiddenContent

	// Exfiltration matches commands that pipe secrets to a network endpoint.
	Exfiltration

	// Destructive matches destructive shell operations.
	Destructive

	// MeetingSecrets matches passcodes embedded in conference join URLs.
	MeetingSecrets

	// Malicious matches other hostile behaviour in executable content:
	// obfuscated payloads, dependency confusion, reconnaissance, path
	// traversal, and suspicious downloads.
	Malicious

	// ActiveHTML matches markup in markdown that runs in a reader's browser
	// when the markdown is rendered with raw HTML: script, frames, event
	// handlers, javascript: URLs. Code spans and fenced blocks are skipped:
	// markup shown as code is text.
	ActiveHTML

	// AllRules selects every behavioural family. ActiveHTML is not in it:
	// it judges how a page renders markdown, not what the text tells an
	// agent to do, and the gates that scan with AllRules (resolve, store)
	// predate it. A caller that renders the content opts in by name.
	AllRules = Credentials | Injection | SpecialTokens | HiddenContent |
		Exfiltration | Destructive | MeetingSecrets | Malicious
)

// Verb records which operations a rule is precise enough to drive.
type Verb uint8

const (
	// DetectOnly rules may report a finding but must never rewrite content.
	// Heuristic phrase matches belong here: redacting the sentence "ignore all
	// previous instructions" out of a document *about* prompt injection would
	// itself be a defect.
	DetectOnly Verb = 1 << iota

	// CleanSafe rules match a structured, unambiguous format and may rewrite
	// content. A literal "<|im_start|>" or a key with a registered prefix
	// qualifies; a bare 32-character hex string does not.
	CleanSafe
)

// Severity levels, ordered clean < warning < critical.
const (
	SeverityCritical = ScanSeverityCritical
	SeverityWarning  = ScanSeverityWarning
	SeverityClean    = ScanSeverityClean
)

// Finding is one rule match.
type Finding = ScanFinding

// Result aggregates findings and the highest severity among them.
type Result = ScanResult

// Detect reports every rule in sets that matches content, without modifying it.
// Both DetectOnly and CleanSafe rules participate.
//
// Content is scanned twice: once as written, and once normalized to defeat
// evasion via confusable characters, zero-width joiners, and spaced-out text.
func Detect(content string, sets RuleSet) Result {
	result := Result{Severity: SeverityClean}
	detectInto(&result, "", content, sets)
	return result
}

// DetectFile is Detect with a path recorded on each finding, for callers
// scanning several files into one result.
func DetectFile(result *Result, path, content string, sets RuleSet) {
	detectInto(result, path, content, sets)
}

func detectInto(result *Result, path, content string, sets RuleSet) {
	if result.Severity == "" {
		result.Severity = SeverityClean
	}
	scanContentRules(result, path, content, func(r *rule) bool {
		return r.Sets&sets != 0
	})
	if sets&ActiveHTML != 0 {
		detectActiveHTML(result, path, content)
	}
}

// Clean rewrites every CleanSafe match in sets to a placeholder and reports
// what it replaced. DetectOnly rules are skipped: they are not precise enough
// to mutate content nobody will review.
//
// Clean operates on plain text. Never call it on serialized JSON — a pattern
// matching across a string boundary consumes the closing quote and corrupts the
// document. Use CleanJSON, which walks decoded string values individually.
func Clean(content string, sets RuleSet) (string, []Finding) {
	// Rewriting means one full scan per pattern, and there are ~30 CleanSafe
	// patterns. Content with no credential in it — which is almost all content —
	// paid for all of them: scrubbing ran at ~0.6 MB/s, so a 16 MB body took 14
	// seconds. One combined alternation decides in a single pass whether any
	// pattern can match, and only then is the per-pattern loop worth running to
	// attribute matches accurately.
	var findings []Finding
	corpus := allRules()
	lower := ""
	for i := range corpus {
		r := &corpus[i]
		if r.Sets&sets == 0 || r.Verbs&CleanSafe == 0 {
			continue
		}
		for _, pattern := range r.Patterns {
			if lit := patternAnchor(pattern); lit != "" {
				if strings.Contains(content, lit) {
					// present, fall through and match properly
				} else if hasUpper(lit) {
					continue // case-sensitive literal, definitively absent
				} else {
					if lower == "" {
						lower = strings.ToLower(content)
					}
					if !strings.Contains(lower, lit) {
						continue
					}
				}
			}
			content = replaceReporting(content, pattern, r, &findings)
		}
	}
	return content, findings
}

func replaceReporting(content string, pattern *regexp.Regexp, r *rule, findings *[]Finding) string {
	return escmask.ReplaceAll(pattern, content, func(s string, loc []int) string {
		*findings = append(*findings, Finding{
			RuleID:      r.ID,
			Severity:    r.Severity,
			Description: r.Description,
			Match:       truncateMatch(s[loc[0]:loc[1]]),
		})
		return r.Placeholder
	})
}

// MarshalFindings renders findings as JSON for logging. Returns "" for none.
func MarshalFindings(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	data, err := json.Marshal(findings)
	if err != nil {
		return `[{"error":"marshal failed"}]`
	}
	return string(data)
}

// HasCritical reports whether any finding is critical.
func HasCritical(findings []Finding) bool {
	for _, f := range findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// Normalize folds confusable characters, strips zero-width codepoints, and
// collapses spaced-out text. Exported so callers can compare a normalized form
// against the original when reporting evasion.
func Normalize(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = normalizeLine(line)
	}
	return strings.Join(lines, "\n")
}

// patternAnchor returns a literal substring every match of a pattern must
// contain, or "" when none can be derived.
//
// Matching costs ~30 MB/s per pattern because of the \b boundaries, and there
// are ~30 rewritable patterns, so content with no credential in it — nearly all
// content — was paying ~1 s per megabyte for thirty scans that could not match.
// Every pattern in these families is anchored on a distinctive literal, which is
// the same property that makes it safe to rewrite at all, so a substring search
// rules most of them out at memchr speed.
//
// Derived from the pattern rather than declared alongside it: a hand-maintained
// literal can drift from the regex it is meant to describe, and a wrong one here
// would silently stop scrubbing.
func patternAnchor(p *regexp.Regexp) string {
	if got, ok := anchors.Load(p); ok {
		return got.(string)
	}
	a := literalAnchor(p.String())
	anchors.Store(p, a)
	return a
}

var anchors sync.Map // *regexp.Regexp -> string

// literalAnchor reads the leading run of plain characters of a regex source,
// stopping at the first metacharacter, so `\b1nfsh-[0-9a-z]{26}\b` yields
// "1nfsh-". Returns "" when the pattern opens with an alternation or a class,
// in which case that pattern is always matched.
func literalAnchor(expr string) string {
	expr = strings.TrimPrefix(expr, "(?i)")
	expr = strings.TrimPrefix(expr, `\b`)
	var b []byte
	for i := 0; i < len(expr); i++ {
		c := expr[i]

		// A quantifier that permits zero repetitions makes the character before
		// it optional, so that character cannot be required in a match. Keeping
		// it produced an anchor no match contains, and since a missing anchor
		// skips the rule outright, the pattern stopped matching anything at all:
		// `<</?SYS>>` anchored on "<</" and stopped stripping "<<SYS>>".
		if c == '?' || c == '*' || c == '{' {
			if len(b) > 0 {
				b = b[:len(b)-1]
			}
			break
		}
		if c == '\\' {
			// An escaped punctuation character is a literal — `\|` is a pipe. An
			// escaped letter or digit is a character class (\w, \d, \b) and is
			// not, so the literal run ends there.
			if i+1 >= len(expr) {
				break
			}
			n := expr[i+1]
			if (n >= 'a' && n <= 'z') || (n >= 'A' && n <= 'Z') || (n >= '0' && n <= '9') {
				break
			}
			// A quantifier may follow the escaped literal too: `\|?`.
			if i+2 < len(expr) && (expr[i+2] == '?' || expr[i+2] == '*' || expr[i+2] == '{') {
				break
			}
			b = append(b, n)
			i++
			continue
		}
		if strings.IndexByte("[](){}.+|^$", c) >= 0 {
			break
		}
		b = append(b, c)
	}
	// Fewer than three characters is too weak to rule anything out.
	if len(b) < 3 {
		return ""
	}
	return string(b)
}

func hasUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 'A' && s[i] <= 'Z' {
			return true
		}
	}
	return false
}
