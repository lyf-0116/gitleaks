package detect

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestEffectiveRuleKeywords(t *testing.T) {
	tests := []struct {
		name     string
		rule     config.Rule
		expected []string
	}{
		{
			name: "vendor keyword with token prefix in regex",
			rule: config.Rule{
				RuleID:   "airtable-personal-access-token",
				Regex:    regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
				Keywords: []string{"airtable"},
			},
			expected: []string{"pat"},
		},
		{
			name: "vendor keyword without a guaranteed literal",
			rule: config.Rule{
				RuleID:   "facebook-access-token",
				Regex:    regexp.MustCompile(`\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})\b`),
				Keywords: []string{"facebook"},
			},
			expected: []string{},
		},
		{
			name: "vendor keyword present in regex",
			rule: config.Rule{
				RuleID:   "acme-api-key",
				Regex:    regexp.MustCompile(`(?i)\bacme(?:_api_key)?\s*=\s*([a-z0-9]{16})\b`),
				Keywords: []string{"acme"},
			},
			expected: []string{"acme"},
		},
		{
			name: "alternation keywords remain unchanged",
			rule: config.Rule{
				RuleID:   "github-app-token",
				Regex:    regexp.MustCompile(`\b(?:ghu|ghs)_[0-9a-zA-Z]{36}\b`),
				Keywords: []string{"ghu_", "ghs_"},
			},
			expected: []string{"ghu_", "ghs_"},
		},
		{
			name: "keyword with regex context remains unchanged",
			rule: config.Rule{
				RuleID:   "slack-config-access-token",
				Regex:    regexp.MustCompile(`(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`),
				Keywords: []string{"xoxe.xoxb-", "xoxe.xoxp-"},
			},
			expected: []string{"xoxe.xoxb-", "xoxe.xoxp-"},
		},
		{
			name: "reachable keyword in mixed list keeps the list unchanged",
			rule: config.Rule{
				RuleID:   "cloudflare-origin-ca-key",
				Regex:    regexp.MustCompile(`\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})\b`),
				Keywords: []string{"cloudflare", "v1.0-"},
			},
			expected: []string{"cloudflare", "v1.0-"},
		},
		{
			name: "rule without keywords",
			rule: config.Rule{
				RuleID: "no-keywords",
				Regex:  regexp.MustCompile(`[a-z0-9]{16}`),
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, effectiveRuleKeywords(tt.rule))
		})
	}
}

func TestDetectWithUnreachableRuleKeywords(t *testing.T) {
	airtablePAT := "patZx9Kq2mNvB7LcD." + strings.Repeat("0123456789abcdef", 4)
	facebookToken := "123456789012345|" + strings.Repeat("a", 27)

	tests := []struct {
		name     string
		rule     config.Rule
		content  string
		expected string
	}{
		{
			name: "derives keyword from token prefix",
			rule: config.Rule{
				RuleID:   "airtable-personal-access-token",
				Regex:    regexp.MustCompile(`\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`),
				Keywords: []string{"airtable"},
			},
			content:  airtablePAT,
			expected: airtablePAT,
		},
		{
			name: "disables keyword filtering when no keyword is guaranteed",
			rule: config.Rule{
				RuleID:   "facebook-access-token",
				Regex:    regexp.MustCompile(`(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$)`),
				Keywords: []string{"facebook"},
			},
			content:  facebookToken,
			expected: "123456789012345|" + strings.Repeat("a", 27),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.Config{
				Rules: map[string]config.Rule{tt.rule.RuleID: tt.rule},
				Keywords: map[string]struct{}{
					strings.ToLower(tt.rule.Keywords[0]): {},
				},
			}
			detector := NewDetector(cfg)

			findings := detector.DetectString(tt.content)

			require.Len(t, findings, 1)
			assert.Equal(t, tt.rule.RuleID, findings[0].RuleID)
			assert.Equal(t, tt.expected, findings[0].Secret)
		})
	}
}

func TestDefaultConfigDetectsBareTokensWithUnreachableKeywords(t *testing.T) {
	detector, err := NewDetectorDefaultConfig()
	require.NoError(t, err)

	tests := []struct {
		name     string
		content  string
		expected string
	}{
		{
			name:     "airtable personal access token",
			content:  "patZx9Kq2mNvB7LcD." + strings.Repeat("0123456789abcdef", 4),
			expected: "airtable-personnal-access-token",
		},
		{
			name:     "facebook access token",
			content:  "123456789012345|aB3dE6gH9jK2mN5pQ8sT1vW4xZ7",
			expected: "facebook-access-token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := detector.DetectString(tt.content)

			require.Len(t, findings, 1)
			assert.Equal(t, tt.expected, findings[0].RuleID)
		})
	}
}
