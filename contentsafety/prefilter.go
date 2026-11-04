package contentsafety

import (
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"
)

// requiredLiterals returns sets of words such that every match of p
// contains, lowercased, one word of each set; none when nothing can be
// derived. Check reads a tool result inline
// with ~70 patterns, and Go's regexp runs each at a few MB/s, so a 400 KB
// log page cost over a second. Almost every pattern needs a word ("ignore",
// "function_calls", "channel") that ordinary text does not have, and a
// substring search for it runs at memory speed.
//
// Derived from the pattern's syntax tree, not declared beside it, for the
// reason patternAnchor gives: a hand-kept word list drifts from its regex,
// and a wrong one silently disables the rule.
func requiredLiterals(p *regexp.Regexp) [][]string {
	return filterOf(p).sets
}

// patternFilter is what text must have for a pattern to match it.
type patternFilter struct {
	// sets: one word of each set, lowercased.
	sets [][]string
	// nonASCII: a character outside ASCII.
	nonASCII bool
}

func filterOf(p *regexp.Regexp) patternFilter {
	if got, ok := filters.Load(p); ok {
		return got.(patternFilter)
	}
	var f patternFilter
	if re, err := syntax.Parse(p.String(), syntax.Perl); err == nil {
		re = re.Simplify()
		for _, set := range requiredSets(re) {
			if minLen(set) >= 3 {
				f.sets = append(f.sets, set)
			}
		}
		f.nonASCII = requiresNonASCII(re)
	}
	filters.Store(p, f)
	return f
}

var filters sync.Map // *regexp.Regexp -> patternFilter

// maxLiteralSet bounds the alternatives a set may hold before it stops being
// worth checking one by one.
const maxLiteralSet = 24

// requiredSets are sets of strings, lowercased, such that every match of re
// contains one string of each set. None when nothing can be said.
func requiredSets(re *syntax.Regexp) [][]string {
	switch re.Op {
	case syntax.OpLiteral:
		return [][]string{{strings.ToLower(string(re.Rune))}}
	case syntax.OpCapture, syntax.OpPlus:
		return requiredSets(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredSets(re.Sub[0])
		}
		return nil
	case syntax.OpConcat:
		// Each child's requirements hold for the whole; adjacent
		// literals join into one longer word.
		var out [][]string
		var run []rune
		flush := func() {
			if len(run) > 0 {
				out = append(out, []string{strings.ToLower(string(run))})
				run = nil
			}
		}
		for _, sub := range re.Sub {
			if sub.Op == syntax.OpLiteral {
				run = append(run, sub.Rune...)
				continue
			}
			flush()
			out = append(out, requiredSets(sub)...)
		}
		flush()
		return out
	case syntax.OpAlternate:
		// One alternative matches: the union of each alternative's best
		// set.
		var out []string
		for _, sub := range re.Sub {
			best := bestSet(requiredSets(sub))
			if best == nil {
				return nil
			}
			out = append(out, best...)
			if len(out) > maxLiteralSet {
				return nil
			}
		}
		return [][]string{out}
	}
	return nil
}

func bestSet(sets [][]string) []string {
	var best []string
	for _, s := range sets {
		if best == nil || minLen(s) > minLen(best) {
			best = s
		}
	}
	return best
}

// requiresNonASCII reports whether every match of re holds a character
// outside ASCII: the zero-width, tag, Cyrillic and fullwidth classes.
func requiresNonASCII(re *syntax.Regexp) bool {
	switch re.Op {
	case syntax.OpLiteral:
		for _, r := range re.Rune {
			if r >= 0x80 {
				return true
			}
		}
		return false
	case syntax.OpCharClass:
		for i := 0; i < len(re.Rune); i += 2 {
			if re.Rune[i] < 0x80 {
				return false
			}
		}
		return len(re.Rune) > 0
	case syntax.OpCapture, syntax.OpPlus:
		return requiresNonASCII(re.Sub[0])
	case syntax.OpRepeat:
		return re.Min >= 1 && requiresNonASCII(re.Sub[0])
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			if requiresNonASCII(sub) {
				return true
			}
		}
		return false
	case syntax.OpAlternate:
		for _, sub := range re.Sub {
			if !requiresNonASCII(sub) {
				return false
			}
		}
		return len(re.Sub) > 0
	}
	return false
}

func minLen(set []string) int {
	if len(set) == 0 {
		return 0
	}
	m := len(set[0])
	for _, s := range set[1:] {
		m = min(m, len(s))
	}
	return m
}

// mayMatch reports whether lowered, a lowercased text (ascii: whether it
// is all ASCII), has what p needs to match.
func mayMatch(p *regexp.Regexp, lowered string, ascii bool) bool {
	f := filterOf(p)
	if f.nonASCII && ascii {
		return false
	}
	for _, set := range f.sets {
		found := false
		for _, l := range set {
			if strings.Contains(lowered, l) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// isASCII reports whether s has only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
