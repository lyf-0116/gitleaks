package detect

import (
	"regexp/syntax"
	"sort"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
)

const (
	maxLiteralAlternatives = 64
	maxCoveringLiterals    = 256
)

// literalInfo describes literals that are guaranteed to be present in every
// match of a regular expression.
type literalInfo struct {
	// covering contains literals such that every match contains at least one of
	// them.
	covering []string
	// best is the most selective covering set found.
	best []string
	// whole is true when the expression matches exactly one of the literals.
	whole bool
}

// effectiveRuleKeywords returns the keywords that can safely be used to
// prefilter a rule.
//
// Keywords are only a valid prefilter when every string matched by the rule's
// regex contains at least one of them. Rules that put a vendor name in
// |keywords| while matching a self-signaling token elsewhere in the regex can
// never satisfy that requirement. For those rules we derive keywords from
// literals that the regex guarantees, or disable keyword filtering when no
// useful literal exists.
func effectiveRuleKeywords(rule config.Rule) []string {
	if len(rule.Keywords) == 0 || rule.Regex == nil {
		return rule.Keywords
	}

	re, err := syntax.Parse(rule.Regex.String(), syntax.Perl)
	if err != nil {
		return rule.Keywords
	}

	info := literalInfoFor(re)
	if keywordsCoverLiterals(rule.Keywords, info.covering) {
		return rule.Keywords
	}

	keywords := make([]string, 0, len(info.best))
	seen := make(map[string]struct{}, len(info.best))
	for _, literal := range info.best {
		keyword := strings.ToLower(literal)
		if keyword == "" {
			continue
		}
		if _, ok := seen[keyword]; ok {
			continue
		}
		seen[keyword] = struct{}{}
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	return keywords
}

// keywordsCoverLiterals reports whether the configured keywords are related to
// a literal that every match is guaranteed to contain. If a keyword is a
// substring of such a literal, every match necessarily contains the keyword.
// The reverse relationship is also accepted to avoid changing keywords that
// deliberately include surrounding context from the regex.
func keywordsCoverLiterals(keywords, literals []string) bool {
	for _, literal := range literals {
		literal = strings.ToLower(literal)
		if literal == "" {
			continue
		}
		for _, keyword := range keywords {
			keyword = strings.ToLower(keyword)
			if keyword == "" {
				return true
			}
			if strings.Contains(literal, keyword) || strings.Contains(keyword, literal) {
				return true
			}
		}
	}
	return false
}

func literalInfoFor(re *syntax.Regexp) literalInfo {
	switch re.Op {
	case syntax.OpLiteral:
		if len(re.Rune) == 0 {
			return literalInfo{whole: true}
		}
		literals := []string{string(re.Rune)}
		return literalInfo{covering: literals, best: literals, whole: true}
	case syntax.OpCharClass:
		if len(re.Rune) == 2 && re.Rune[0] == re.Rune[1] {
			literals := []string{string(re.Rune[0])}
			return literalInfo{covering: literals, best: literals, whole: true}
		}
		return literalInfo{}
	case syntax.OpCapture:
		if len(re.Sub) == 0 {
			return literalInfo{}
		}
		return literalInfoFor(re.Sub[0])
	case syntax.OpConcat:
		return concatLiteralInfo(re.Sub)
	case syntax.OpAlternate:
		var covering, best []string
		allWhole := true
		for _, sub := range re.Sub {
			info := literalInfoFor(sub)
			if len(info.covering) == 0 {
				return literalInfo{}
			}
			covering = mergeLiterals(covering, info.covering)
			best = mergeLiterals(best, info.covering)
			if len(covering) > maxCoveringLiterals {
				return literalInfo{}
			}
			allWhole = allWhole && info.whole
		}
		return literalInfo{covering: covering, best: best, whole: allWhole}
	case syntax.OpPlus:
		if len(re.Sub) == 0 {
			return literalInfo{}
		}
		info := literalInfoFor(re.Sub[0])
		return literalInfo{covering: info.covering, best: info.best}
	case syntax.OpRepeat:
		if re.Min < 1 || len(re.Sub) == 0 {
			return literalInfo{}
		}
		info := literalInfoFor(re.Sub[0])
		return literalInfo{covering: info.covering, best: info.best}
	default:
		return literalInfo{}
	}
}

func concatLiteralInfo(sub []*syntax.Regexp) literalInfo {
	infos := make([]literalInfo, len(sub))
	allWhole := true
	for i, re := range sub {
		infos[i] = literalInfoFor(re)
		allWhole = allWhole && infos[i].whole
	}

	if allWhole {
		literals := []string{""}
		for _, info := range infos {
			literals = crossLiterals(literals, info.covering)
			if literals == nil {
				allWhole = false
				break
			}
		}
		if allWhole {
			literals = dedupeLiterals(literals)
			return literalInfo{covering: literals, best: literals, whole: true}
		}
	}

	var covering, best, run []string
	flushRun := func() {
		if len(run) == 0 {
			return
		}
		covering = mergeLiterals(covering, run)
		if betterLiterals(run, best) {
			best = run
		}
		run = nil
	}

	for _, info := range infos {
		if !info.whole {
			flushRun()
			covering = mergeLiterals(covering, info.covering)
			if betterLiterals(info.best, best) {
				best = info.best
			}
			if len(covering) > maxCoveringLiterals {
				return literalInfo{best: best}
			}
			continue
		}

		if run == nil {
			run = []string{""}
		}
		next := crossLiterals(run, info.covering)
		if next == nil {
			flushRun()
			continue
		}
		run = next
	}
	flushRun()

	return literalInfo{covering: covering, best: best}
}

func crossLiterals(a, b []string) []string {
	if len(a) == 0 || len(b) == 0 || len(a)*len(b) > maxLiteralAlternatives {
		return nil
	}
	literals := make([]string, 0, len(a)*len(b))
	for _, left := range a {
		for _, right := range b {
			literals = append(literals, left+right)
		}
	}
	return literals
}

func mergeLiterals(a, b []string) []string {
	if len(a) == 0 {
		return dedupeLiterals(b)
	}
	if len(b) == 0 {
		return dedupeLiterals(a)
	}
	literals := make([]string, 0, len(a)+len(b))
	literals = append(literals, a...)
	literals = append(literals, b...)
	return dedupeLiterals(literals)
}

func dedupeLiterals(literals []string) []string {
	seen := make(map[string]struct{}, len(literals))
	result := make([]string, 0, len(literals))
	for _, literal := range literals {
		if literal == "" {
			continue
		}
		if _, ok := seen[literal]; ok {
			continue
		}
		seen[literal] = struct{}{}
		result = append(result, literal)
	}
	sort.Strings(result)
	return result
}

func betterLiterals(a, b []string) bool {
	return literalScore(a) > literalScore(b)
}

func literalScore(literals []string) int {
	minLength := -1
	totalLength := 0
	for _, literal := range literals {
		if literal == "" {
			continue
		}
		if minLength < 0 || len(literal) < minLength {
			minLength = len(literal)
		}
		totalLength += len(literal)
	}
	if minLength < 0 {
		return -1
	}
	return minLength*1000 + totalLength
}
