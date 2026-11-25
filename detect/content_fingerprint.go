package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const contentFingerprintPrefix = "sha256:"

// contentFingerprint identifies a finding by rule and secret only. It is an
// additive escape hatch for suppressing one known secret across files and
// line movements. The primary migration format is FingerprintV2, which also
// keeps the file path as a scope.
func contentFingerprint(ruleID, secret string) string {
	input := fmt.Sprintf("%d:%s|%d:%s", len(ruleID), ruleID, len(secret), secret)
	sum := sha256.Sum256([]byte(input))
	return contentFingerprintPrefix + hex.EncodeToString(sum[:])[:32]
}
