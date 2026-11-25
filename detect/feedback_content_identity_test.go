package detect

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/report"
)

func writeFeedbackIgnoreFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".gitleaksignore")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestFeedbackContentIdentityTracksSecretAndLineDrift(t *testing.T) {
	original := report.Finding{
		File:          "config.py",
		RuleID:        "aws-access-token",
		StartLine:     1,
		Secret:        "AKIALALEMEL33243OLIA",
		FingerprintV2: report.NewFingerprintV2("config.py", "aws-access-token", "AKIALALEMEL33243OLIA"),
	}

	d := newFeedbackIdentityDetector(t)
	d.UseFingerprintV2 = true
	require.NoError(t, d.AddGitleaksIgnore(writeFeedbackIgnoreFile(t, original.FingerprintV2+"\n")))

	shifted := original
	shifted.StartLine = 4
	shifted.EndLine = 4
	d.AddFinding(shifted)
	assert.Empty(t, d.Findings())

	rotated := original
	rotated.StartLine = 1
	rotated.Secret = "AKIALALEMEL33243OLIB"
	rotated.FingerprintV2 = ""
	d.AddFinding(rotated)

	findings := d.Findings()
	require.Len(t, findings, 1)
	assert.Equal(t, "AKIALALEMEL33243OLIB", findings[0].Secret)
	assert.NotEqual(t, original.FingerprintV2, findings[0].FingerprintV2)
}

func TestFeedbackLegacyIgnoreEntriesPendingInV2Mode(t *testing.T) {
	ignorePath := writeFeedbackIgnoreFile(t, "config.py:aws-access-token:1\n")

	strict := newFeedbackIdentityDetector(t)
	require.NoError(t, strict.AddGitleaksIgnore(ignorePath))
	assert.Equal(t, []string{"config.py:aws-access-token:1"}, strict.PendingGitleaksIgnoreEntries())

	strict.AddFinding(report.Finding{File: "config.py", RuleID: "aws-access-token", StartLine: 1, Secret: "new-secret"})
	require.Len(t, strict.Findings(), 1)

	legacy := &Detector{}
	require.NoError(t, legacy.AddGitleaksIgnore(ignorePath))
	legacy.AddFinding(report.Finding{File: "config.py", RuleID: "aws-access-token", StartLine: 1, Secret: "new-secret"})
	assert.Empty(t, legacy.Findings())

	allowed := newFeedbackIdentityDetector(t)
	allowed.AllowLegacyFingerprints = true
	require.NoError(t, allowed.AddGitleaksIgnore(ignorePath))
	allowed.AddFinding(report.Finding{File: "config.py", RuleID: "aws-access-token", StartLine: 1, Secret: "new-secret"})
	assert.Empty(t, allowed.Findings())
}

func TestFeedbackV2IgnoreEntryCoordinatesAreAuxiliary(t *testing.T) {
	token := report.NewFingerprintV2("config.py", "rule", "same-secret")
	ignorePath := writeFeedbackIgnoreFile(t, "config.py:rule:1:"+token+"\n")

	d := newFeedbackIdentityDetector(t)
	d.UseFingerprintV2 = true
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))
	d.AddFinding(report.Finding{File: "config.py", RuleID: "rule", StartLine: 8, Secret: "same-secret"})
	assert.Empty(t, d.Findings())
}

func TestFeedbackCommitScopedV2IgnoreEntryDoesNotBecomeGlobal(t *testing.T) {
	token := report.NewFingerprintV2("config.py", "rule", "same-secret")
	commit := "0123456789abcdef0123456789abcdef01234567"
	ignorePath := writeFeedbackIgnoreFile(t, commit+":config.py:rule:1:"+token+"\n")

	d := newFeedbackIdentityDetector(t)
	d.UseFingerprintV2 = true
	require.NoError(t, d.AddGitleaksIgnore(ignorePath))

	d.AddFinding(report.Finding{Commit: "different-commit", File: "config.py", RuleID: "rule", StartLine: 9, Secret: "same-secret"})
	require.Len(t, d.Findings(), 1)

	d.AddFinding(report.Finding{Commit: commit, File: "config.py", RuleID: "rule", StartLine: 12, Secret: "same-secret"})
	assert.Empty(t, d.Findings()[1:])
	require.Len(t, d.Findings(), 1)
}

func TestFeedbackRedactedBaselineUsesContentIdentity(t *testing.T) {
	secret := "AKIALALEMEL33243OLIA"
	token := report.NewFingerprintV2("config.py", "aws-access-token", secret)
	baseline := []report.Finding{{
		File:          "config.py",
		RuleID:        "aws-access-token",
		Commit:        "",
		StartLine:     1,
		Secret:        "REDACTED",
		FingerprintV2: token,
	}}

	same := report.Finding{
		File:          "config.py",
		RuleID:        "aws-access-token",
		StartLine:     3,
		Secret:        "REDACTED",
		FingerprintV2: token,
	}
	assert.False(t, IsNew(same, 100, baseline))

	rotated := same
	rotated.FingerprintV2 = report.NewFingerprintV2("config.py", "aws-access-token", "AKIALALEMEL33243OLIB")
	assert.True(t, IsNew(rotated, 100, baseline))

	rawLegacyBaseline := []report.Finding{{
		File:      "config.py",
		RuleID:    "aws-access-token",
		StartLine: 1,
		Secret:    secret,
	}}
	liveWithShift := report.Finding{
		File:          "config.py",
		RuleID:        "aws-access-token",
		StartLine:     5,
		Secret:        secret,
		FingerprintV2: token,
	}
	assert.False(t, IsNew(liveWithShift, 0, rawLegacyBaseline))
}

func newFeedbackIdentityDetector(t *testing.T) *Detector {
	t.Helper()
	d, err := NewDetectorDefaultConfig()
	require.NoError(t, err)
	return d
}
