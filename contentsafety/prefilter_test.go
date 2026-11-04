package contentsafety

import (
	"strings"
	"testing"
)

// The prefilter disables a pattern on text without one of its words, so a
// wrong word set is a rule that stops matching. Every tool-result pattern
// is checked against the corpus: whatever the pattern matches must hold one
// of its words.
func TestRequiredLiterals_neverExcludeAMatch(t *testing.T) {
	var texts []string
	for _, name := range []string{"positives.jsonl", "negatives.jsonl"} {
		for _, c := range loadCorpus(t, name) {
			texts = append(texts, c.Text, Normalize(c.Text))
			for _, s := range scanTexts(c.Text) {
				texts = append(texts, s)
			}
		}
	}
	checked := 0
	for _, r := range allRules() {
		if r.Sets&ToolResultRules == 0 {
			continue
		}
		for _, p := range r.Patterns {
			lits := requiredLiterals(p)
			re := multiline(p)
			for _, s := range texts {
				for _, m := range re.FindAllString(s, -1) {
					checked++
					if !mayMatch(p, foldForFilter(m), isASCII(m)) {
						t.Errorf("%s: %q matches %q but holds none of %q", r.ID, m, p, lits)
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no matches checked")
	}
}

func TestRequiredLiterals(t *testing.T) {
	r := allRules()
	byID := map[string][]string{}
	for _, ru := range r {
		for _, p := range ru.Patterns {
			if l := requiredLiterals(p); l != nil {
				byID[ru.ID] = append(byID[ru.ID], strings.Join(l[0], "|"))
			}
		}
	}
	for _, id := range []string{RuleToolCallSyntax, RuleMention, RuleAgentAddressed, "INF-SEC-007", "INF-TOK-001"} {
		if len(byID[id]) == 0 {
			t.Errorf("%s: no pattern has a word to filter on", id)
		}
	}
}
