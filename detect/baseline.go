package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/zricethezav/gitleaks/v8/report"
)

func IsNew(finding report.Finding, redact uint, baseline []report.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintenance if/when the Finding struct changes
	for _, b := range baseline {
		if sameContentIdentity(finding, b, redact) &&
			finding.RuleID == b.RuleID &&
			finding.File == b.File &&
			finding.Commit == b.Commit {
			return false
		}

		if finding.RuleID == b.RuleID &&
			finding.Description == b.Description &&
			finding.StartLine == b.StartLine &&
			finding.EndLine == b.EndLine &&
			finding.StartColumn == b.StartColumn &&
			finding.EndColumn == b.EndColumn &&
			sameFindingContent(finding, b, redact) &&
			finding.File == b.File &&
			finding.Commit == b.Commit &&
			finding.Author == b.Author &&
			finding.Email == b.Email &&
			finding.Date == b.Date &&
			finding.Message == b.Message &&
			// Omit checking finding.Fingerprint - if the format of the fingerprint changes, the users will see unexpected behaviour
			finding.Entropy == b.Entropy {
			return false
		}
	}
	return true
}

func sameContentIdentity(finding, baseline report.Finding, redact uint) bool {
	findingIdentity := finding.FingerprintV2
	if !report.IsValidFingerprintV2(findingIdentity) {
		// Direct callers may still pass an unredacted finding without a
		// precomputed token. Redacted values cannot recover the original
		// identity, so leave the decision to the legacy field comparison.
		if redact > 0 && isRedactedSecret(finding.Secret) {
			return false
		}
		findingIdentity = finding.NewFingerprintV2()
	}

	baselineIdentity := baseline.FingerprintV2
	if !report.IsValidFingerprintV2(baselineIdentity) {
		if isRedactedSecret(baseline.Secret) || baseline.Secret == "" {
			return false
		}
		baselineIdentity = baseline.NewFingerprintV2()
	}

	return findingIdentity == baselineIdentity
}

func sameFindingContent(finding, baseline report.Finding, redact uint) bool {
	if redact == 0 {
		return finding.Match == baseline.Match && finding.Secret == baseline.Secret
	}

	// Preserve the historical positional fallback for direct callers that pass
	// a redacted finding without a content identity. The detector itself always
	// populates FingerprintV2 before redaction, so CLI scans use the stronger
	// comparison below.
	if !report.IsValidFingerprintV2(finding.FingerprintV2) && isRedactedSecret(finding.Secret) {
		return true
	}

	return sameContentIdentity(finding, baseline, redact)
}

func isRedactedSecret(secret string) bool {
	return secret == "REDACTED" || strings.HasSuffix(secret, "...")
}

func LoadBaseline(baselinePath string) ([]report.Finding, error) {
	bytes, err := os.ReadFile(baselinePath)
	if err != nil {
		return nil, fmt.Errorf("could not open %s", baselinePath)
	}

	var previousFindings []report.Finding
	err = json.Unmarshal(bytes, &previousFindings)
	if err != nil {
		return nil, fmt.Errorf("the format of the file %s is not supported", baselinePath)
	}

	return previousFindings, nil
}

func (d *Detector) AddBaseline(baselinePath string, source string) error {
	if baselinePath != "" {
		absoluteSource, err := filepath.Abs(source)
		if err != nil {
			return err
		}

		absoluteBaseline, err := filepath.Abs(baselinePath)
		if err != nil {
			return err
		}

		relativeBaseline, err := filepath.Rel(absoluteSource, absoluteBaseline)
		if err != nil {
			return err
		}

		baseline, err := LoadBaseline(baselinePath)
		if err != nil {
			return err
		}

		d.baseline = baseline
		baselinePath = relativeBaseline

	}

	d.baselinePath = baselinePath
	return nil
}
