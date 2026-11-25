package report

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Finding contains a whole bunch of information about a secret finding.
// Plenty of real estate in this bad boy so fillerup as needed.
type Finding struct {
	// Rule is the name of the rule that was matched
	RuleID      string
	Description string

	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int

	Line string `json:"-"`

	Match string

	// Captured secret
	Secret string

	// File is the name of the file containing the finding
	File        string
	SymlinkFile string
	Commit      string
	Link        string `json:",omitempty"`

	// Entropy is the shannon entropy of Value
	Entropy float32

	Author  string
	Email   string
	Date    string
	Message string
	Tags    []string

	// unique identifier
	Fingerprint string

	// FingerprintV2 is a content-specific identity token. Unlike Fingerprint,
	// it does not depend on the line number, so inserting code above a finding
	// does not invalidate an ignore entry.
	FingerprintV2 string `json:"FingerprintV2,omitempty"`

	// ContentFingerprint is an optional rule-plus-secret identity independent
	// of file, commit, and line coordinates.
	ContentFingerprint string `json:"ContentFingerprint,omitempty"`

	// Fragment used for multi-part rule checking, CEL filtering,
	// and eventually ML validation
	Fragment *sources.Fragment `json:",omitempty"`

	// TODO keeping private for now to during experimental phase
	requiredFindings []*RequiredFinding
}

// FingerprintV2Prefix marks a versioned content fingerprint.
const FingerprintV2Prefix = "v2:"

// NewFingerprintV2 returns the content-specific identity for a finding.
//
// The file path and rule ID keep the identity scoped to the same kind of
// finding. The secret and matched line content prevent a rotated secret from
// matching an old ignore entry and distinguish nearby occurrences. The line
// number itself is intentionally omitted; Fingerprint remains the coordinate
// hint and is allowed to drift when code is inserted above a finding.
func (f Finding) NewFingerprintV2() string {
	return newFingerprintV2(f.File, f.RuleID, f.Secret, f.Match, strings.TrimSpace(f.Line))
}

// NewFingerprintV2 builds a versioned content identity from its scoping and
// secret fields. Inputs are length-prefixed to avoid canonicalization
// collisions between arbitrary secret values.
func NewFingerprintV2(file, ruleID, secret string) string {
	return newFingerprintV2(file, ruleID, secret, "", "")
}

func newFingerprintV2(file, ruleID, secret string, context ...string) string {
	hash := sha256.New()
	_, _ = io.WriteString(hash, "gitleaks-fingerprint-v2\n")
	writeFingerprintField := func(value string) {
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))
		_, _ = hash.Write(length[:])
		_, _ = io.WriteString(hash, value)
	}

	writeFingerprintField(filepath.ToSlash(file))
	writeFingerprintField(ruleID)
	writeFingerprintField(secret)
	for _, value := range context {
		writeFingerprintField(value)
	}

	return FingerprintV2Prefix + hex.EncodeToString(hash.Sum(nil))
}

// IsValidFingerprintV2 reports whether token is a syntactically valid V2
// fingerprint.
func IsValidFingerprintV2(token string) bool {
	if !strings.HasPrefix(token, FingerprintV2Prefix) {
		return false
	}

	digest := strings.TrimPrefix(token, FingerprintV2Prefix)
	if len(digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

type RequiredFinding struct {
	// contains a subset of the Finding fields
	// only used for reporting
	RuleID      string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
}

func (f *Finding) AddRequiredFindings(afs []*RequiredFinding) {
	if f.requiredFindings == nil {
		f.requiredFindings = make([]*RequiredFinding, 0)
	}
	f.requiredFindings = append(f.requiredFindings, afs...)
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact(percent uint) {
	if f.FingerprintV2 == "" {
		f.FingerprintV2 = f.NewFingerprintV2()
	}

	secret := maskSecret(f.Secret, percent)
	if percent >= 100 {
		secret = "REDACTED"
	}
	f.Line = strings.ReplaceAll(f.Line, f.Secret, secret)
	f.Match = strings.ReplaceAll(f.Match, f.Secret, secret)
	f.Secret = secret
}

func maskSecret(secret string, percent uint) string {
	if percent > 100 {
		percent = 100
	}
	len := float64(len(secret))
	if len <= 0 {
		return secret
	}
	prc := float64(100 - percent)
	lth := int64(math.RoundToEven(len * prc / float64(100)))

	return secret[:lth] + "..."
}

func (f *Finding) PrintRequiredFindings() {
	if len(f.requiredFindings) == 0 {
		return
	}

	fmt.Printf("%-12s ", "Required:")

	// Create orange style for secrets
	orangeStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("#bf9478"))

	for i, aux := range f.requiredFindings {
		auxSecret := strings.TrimSpace(aux.Secret)
		// Truncate long secrets for readability
		if len(auxSecret) > 40 {
			auxSecret = auxSecret[:37] + "..."
		}

		// Format: rule-id:line:secret
		if i == 0 {
			fmt.Printf("%s:%d:%s\n", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		} else {
			fmt.Printf("%-12s %s:%d:%s\n", "", aux.RuleID, aux.StartLine, orangeStyle.Render(auxSecret))
		}
	}
}
