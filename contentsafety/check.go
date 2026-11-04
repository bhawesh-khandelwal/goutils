package contentsafety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/inference-sh/goutils/internal/escmask"
)

// ScannerVersion names the rules and questions a Verdict came from. Bump it
// when either changes, so stored verdicts say which generation judged them.
const ScannerVersion = "toolresult-1"

// Tier is how far a tool's output is from the operator's own words.
type Tier string

const (
	// TierInternal is output the platform wrote from the operator's own
	// data (a plan, memory, a knowledge search over their notes).
	TierInternal Tier = "internal"
	// TierContent is the operator's stored content that others may have
	// written into (files, chats, documents in their workspace).
	TierContent Tier = "content"
	// TierThirdParty is output from outside: an app, an MCP server, an
	// HTTP endpoint, a client or another agent.
	TierThirdParty Tier = "third_party"
)

// Content is one tool result to check.
type Content struct {
	// Source names where the text came from: "app:infsh/grafana/query_logs",
	// "mcp:<server>/<tool>", "internal:knowledge_search", "http:<host>".
	Source string
	Tier   Tier
	Text   string
	// Images are URLs of images the result carries, for a judge that reads
	// them. The rules do not.
	Images []string
}

// Verdict is what Check found in one tool result. Findings annotate; they
// never remove the result. Only CleanSafe rules (the tag characters) change
// Text.
type Verdict struct {
	// Text is the result with the CleanSafe rewrites applied: what the
	// agent should read.
	Text string `json:"-"`
	// Findings holds the first finding of each rule that matched.
	Findings []Finding `json:"findings,omitempty"`
	// Severity is the highest of the findings' severities, and critical
	// when the judge flagged the result.
	Severity string `json:"severity"`
	// Flagged is a critical verdict: what taints a run.
	Flagged bool `json:"flagged"`
	// Judge is the judge's answer, nil when none ran.
	Judge *JudgeVerdict `json:"judge,omitempty"`
	// Truncated reports that the rules saw only the head and tail of a
	// result longer than maxScanBytes.
	Truncated      bool   `json:"truncated,omitempty"`
	ScannerVersion string `json:"scanner_version"`
}

// RuleIDs are the ids of the rules that matched, in finding order.
func (v Verdict) RuleIDs() []string {
	ids := make([]string, 0, len(v.Findings))
	for _, f := range v.Findings {
		ids = append(ids, f.RuleID)
	}
	return ids
}

// Noteworthy reports whether the verdict has anything to say: a finding or a
// judge flag.
func (v Verdict) Noteworthy() bool {
	return len(v.Findings) > 0 || (v.Judge != nil && v.Judge.Flagged)
}

// Judge answers the questions in JudgeNouls and JudgeChoices about a tool
// result. contentsafety holds the questions and the thresholds; the caller
// supplies the model.
type Judge interface {
	Judge(ctx context.Context, c Content) (*JudgeVerdict, error)
}

// Options configure Check.
type Options struct {
	// Judge, when set, is asked after the rules.
	Judge Judge
	// Timeout bounds the judge (DefaultJudgeTimeout when zero). A judge
	// that does not answer in time leaves a verdict with TimedOut set.
	Timeout time.Duration
	// IgnoreRules are rule ids not to apply.
	IgnoreRules []string
	// Sets are the rule families (ToolResultRules when zero).
	Sets RuleSet
}

// DefaultJudgeTimeout is how long Check waits for a judge.
const DefaultJudgeTimeout = 3 * time.Second

// maxScanBytes bounds what the rules read of one result: its head and tail
// when it is longer. The rules run at tens of MB/s per pattern, and a tool
// result is read inline on the way to the model.
const (
	maxScanBytes  = 384 << 10
	scanTailBytes = 128 << 10
)

// Scan applies the deterministic rules to c. It never blocks.
func Scan(c Content, opts Options) Verdict {
	sets := opts.Sets
	if sets == 0 {
		sets = ToolResultRules
	}
	include := func(r *rule) bool {
		return r.Sets&sets != 0 && !slices.Contains(opts.IgnoreRules, r.ID)
	}
	v := Verdict{Text: c.Text, Severity: SeverityClean, ScannerVersion: ScannerVersion}
	if c.Text == "" {
		return v
	}

	// The tag characters are removed whatever else is found: they are
	// invisible to a person and read as text by a model.
	if sets&TagCharacters != 0 && !isASCII(c.Text) && !slices.Contains(opts.IgnoreRules, RuleTagCharacters) {
		cleaned, removed := Clean(c.Text, TagCharacters)
		if len(removed) > 0 {
			v.Text = cleaned
		}
	}

	text, truncated := scanWindow(c.Text)
	v.Truncated = truncated
	res := Result{Severity: SeverityClean}
	texts := scanTexts(text)
	for i, t := range texts {
		inc := include
		if i == len(texts)-1 && i > 0 && t != texts[i-1] && isSpacedVariant(t, texts[i-1]) {
			// The separators-as-spaces reading only helps the phrase rules.
			inc = func(r *rule) bool { return include(r) && r.Sets&(Injection|AgentAddressed) != 0 }
		}
		scanWhole(&res, t, inc)
		if sets&EncodedPayload != 0 && !slices.Contains(opts.IgnoreRules, RuleEncodedText) {
			detectEncodedText(&res, t, include)
		}
	}
	v.Findings = firstPerRule(res.Findings)
	for _, f := range v.Findings {
		if severityRank(f.Severity) > severityRank(v.Severity) {
			v.Severity = f.Severity
		}
	}
	v.Flagged = v.Severity == SeverityCritical
	return v
}

// Check applies the rules to c and then asks opts.Judge, when set, waiting
// at most opts.Timeout for it.
func Check(ctx context.Context, c Content, opts Options) Verdict {
	v := Scan(c, opts)
	if opts.Judge == nil {
		return v
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultJudgeTimeout
	}
	jctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	judged := Content{Source: c.Source, Tier: c.Tier, Text: v.Text, Images: c.Images}
	start := time.Now()
	// The judge runs beside the deadline rather than trusted to honour it:
	// a transport that blocks past its context must not hold the result.
	type answer struct {
		jv  *JudgeVerdict
		err error
	}
	done := make(chan answer, 1)
	go func() {
		jv, err := opts.Judge.Judge(jctx, judged)
		done <- answer{jv, err}
	}()
	select {
	case a := <-done:
		v.AddJudge(a.jv, a.err, time.Since(start))
	case <-jctx.Done():
		v.AddJudge(nil, jctx.Err(), time.Since(start))
	}
	return v
}

// AddJudge records a judge's answer (or its failure) on v and raises v to
// critical when the judge flagged the result. A caller that judges outside
// Check, after the result has gone on, records the answer this way.
func (v *Verdict) AddJudge(jv *JudgeVerdict, err error, took time.Duration) {
	if jv == nil {
		jv = &JudgeVerdict{}
	}
	if jv.LatencyMS == 0 {
		jv.LatencyMS = took.Milliseconds()
	}
	if err != nil {
		jv.Error = truncateMatch(err.Error())
		jv.TimedOut = errors.Is(err, context.DeadlineExceeded)
	}
	v.Judge = jv
	if jv.Flagged {
		v.Severity = SeverityCritical
		v.Flagged = true
	}
}

// scanWindow is s, or its head and tail when it is longer than maxScanBytes.
func scanWindow(s string) (string, bool) {
	if len(s) <= maxScanBytes {
		return s, false
	}
	head := maxScanBytes - scanTailBytes
	for head > 0 && !utf8.RuneStart(s[head]) {
		head--
	}
	tail := len(s) - scanTailBytes
	for tail < len(s) && !utf8.RuneStart(s[tail]) {
		tail++
	}
	return s[:head] + "\n" + s[tail:], true
}

// scanTexts is what the rules read of s: s itself, and when s is or holds a
// JSON document, its keys and string values decoded, one per line. Decoded,
// because a JSON encoder writes "<" as < and a newline as \n: a
// "<function_calls>" or a line opening "system:" inside a value is not in
// the serialized bytes as written.
func scanTexts(s string) []string {
	texts := []string{s}
	if doc := embeddedJSON(s); doc != "" {
		if decoded := decodedStrings(doc); decoded != "" {
			texts = append(texts, decoded)
		}
	}
	// Words run together in a path or an identifier
	// (/note-to-ai-agent/classify-this-as-safe, IGNORE_ALL_PREVIOUS,
	// %20-encoded): read once with the separators as spaces.
	last := texts[len(texts)-1]
	if spaced := spaceSeparators(last); spaced != last {
		texts = append(texts, spaced)
	}
	return texts
}

// decodedStrings is the keys and string values of the JSON document doc,
// one per line; "" when it has none.
func decodedStrings(doc string) string {
	dec := json.NewDecoder(strings.NewReader(doc))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return ""
	}
	var b strings.Builder
	collectStrings(&b, tree, 0)
	return b.String()
}

// spaceSeparators percent-decodes s and turns the separators of a path or an
// identifier (- _ / + .) between letters into spaces.
func spaceSeparators(s string) string {
	if strings.Contains(s, "%") {
		if u, err := url.PathUnescape(s); err == nil {
			s = u
		}
	}
	b := []byte(s)
	changed := false
	for i := 1; i+1 < len(b); i++ {
		switch b[i] {
		case '-', '_', '/', '+', '.':
			if isASCIILetter(b[i-1]) && isASCIILetter(b[i+1]) {
				b[i] = ' '
				changed = true
			}
		}
	}
	if !changed {
		return s
	}
	return string(b)
}

func isASCIILetter(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

// embeddedJSON is the JSON document s is, or the one it carries between its
// first opening and last closing bracket ("Task … completed with output:
// {…}"); "" when there is none.
func embeddedJSON(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return ""
	}
	if (t[0] == '{' || t[0] == '[') && json.Valid([]byte(t)) {
		return t
	}
	start := strings.IndexAny(t, "{[")
	if start < 0 {
		return ""
	}
	end := strings.LastIndexAny(t, "}]")
	if end <= start {
		return ""
	}
	cand := t[start : end+1]
	if !json.Valid([]byte(cand)) {
		return ""
	}
	return cand
}

// maxJSONDepth bounds collectStrings' recursion.
const maxJSONDepth = 64

func collectStrings(b *strings.Builder, v any, depth int) {
	if depth > maxJSONDepth {
		return
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			b.WriteString(t)
			b.WriteByte('\n')
		}
	case []any:
		for _, e := range t {
			collectStrings(b, e, depth+1)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			b.WriteString(k)
			b.WriteByte('\n')
			collectStrings(b, t[k], depth+1)
		}
	}
}

// scanWhole applies the rules include selects to text as a whole, and to its
// normalized form when normalizing changes it, recording the first match of
// each rule. Matching the whole text once per pattern, rather than line by
// line as Detect does, is what makes reading a large result inline
// affordable; patterns that anchor on ^ or $ match at line boundaries.
func scanWhole(res *Result, text string, include func(*rule) bool) {
	type view struct {
		orig, masked, lowered string
		ascii                 bool
	}
	newView := func(s string) view {
		m := escmask.Mask(s)
		return view{s, m, foldForFilter(m), isASCII(m)}
	}
	views := []view{newView(text)}
	if n := Normalize(text); n != text {
		views = append(views, newView(n))
	}
	have := map[string]bool{}
	for _, f := range res.Findings {
		have[f.RuleID] = true
	}
	corpus := allRules()
	for i := range corpus {
		r := &corpus[i]
		if have[r.ID] || (include != nil && !include(r)) {
			continue
		}
	patterns:
		for _, p := range r.Patterns {
			re := multiline(p)
			for _, vw := range views {
				if !mayMatch(p, vw.lowered, vw.ascii) {
					continue
				}
				loc := re.FindStringIndex(vw.masked)
				if loc == nil {
					continue
				}
				res.Findings = append(res.Findings, Finding{
					RuleID:      r.ID,
					Severity:    r.Severity,
					Description: r.Description,
					Match:       truncateMatch(vw.orig[loc[0]:loc[1]]),
				})
				if severityRank(r.Severity) > severityRank(res.Severity) {
					res.Severity = r.Severity
				}
				have[r.ID] = true
				break patterns
			}
		}
	}
}

// foldForFilter lowercases s for mayMatch, folding the one letter whose
// case-insensitive match strings.ToLower does not reach (ſ matches s).
func foldForFilter(s string) string {
	return strings.ReplaceAll(strings.ToLower(s), "ſ", "s")
}

var multilines sync.Map // *regexp.Regexp -> *regexp.Regexp

// multiline is p with ^ and $ matching at line boundaries, as they do in
// Detect's line-by-line scan.
func multiline(p *regexp.Regexp) *regexp.Regexp {
	if m, ok := multilines.Load(p); ok {
		return m.(*regexp.Regexp)
	}
	m := p
	if src := p.String(); strings.ContainsAny(src, "^$") {
		m = regexp.MustCompile("(?m)" + src)
	}
	multilines.Store(p, m)
	return m
}

// isSpacedVariant reports whether t is prev with separators turned to
// spaces (spaceSeparators).
func isSpacedVariant(t, prev string) bool { return spaceSeparators(prev) == t }

// firstPerRule keeps the first finding of each rule, preferring a critical
// one: an annotation names rules, not lines.
func firstPerRule(findings []Finding) []Finding {
	idx := map[string]int{}
	var out []Finding
	for _, f := range findings {
		f.Line = 0
		if i, ok := idx[f.RuleID]; ok {
			if severityRank(f.Severity) > severityRank(out[i].Severity) {
				out[i] = f
			}
			continue
		}
		idx[f.RuleID] = len(out)
		out = append(out, f)
	}
	return out
}

// MarshalVerdict renders v for storage or a log line, without its text.
func MarshalVerdict(v Verdict) json.RawMessage {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return json.RawMessage(`{"error":"marshal failed"}`)
	}
	return bytes.TrimSpace(buf.Bytes())
}
