package sources

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/regexp"
)

func TestPathCandidates(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	absArchive := filepath.Join(cwd, "sub", "archive.tar")

	tests := []struct {
		name     string
		path     string
		expected []string
	}{
		{
			name:     "empty path",
			path:     "",
			expected: nil,
		},
		{
			name:     "plain relative path",
			path:     "dir/file.txt",
			expected: []string{"dir/file.txt"},
		},
		{
			name: "composite archive path",
			path: "archive.tar!dir/file.txt",
			expected: []string{
				// Legacy form.
				"archive.tar!dir/file.txt",
				// Archive-inner relative form.
				"dir/file.txt",
			},
		},
		{
			name: "nested composite archive path",
			path: "nested.tar.gz!archives/files.tar!files/api.go",
			expected: []string{
				"nested.tar.gz!archives/files.tar!files/api.go",
				"files/api.go",
			},
		},
		{
			name: "absolute path",
			path: absArchive,
			expected: []string{
				absArchive,
				"sub/archive.tar",
			},
		},
		{
			name: "absolute composite archive path",
			path: absArchive + InnerPathSeparator + "dir/file.txt",
			expected: []string{
				absArchive + InnerPathSeparator + "dir/file.txt",
				"sub/archive.tar" + InnerPathSeparator + "dir/file.txt",
				"dir/file.txt",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, PathCandidates(tt.path))
		})
	}
}

func TestPathAllowed(t *testing.T) {
	allowlist := &config.Allowlist{
		Paths: []*regexp.Regexp{regexp.MustCompile(`(^|/)ignoreme(/.*)?$`)},
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "legacy composite form matches",
			path:     "ignoreme/archive.tar!dir/file.txt",
			expected: true,
		},
		{
			name:     "archive-inner relative form matches",
			path:     "archive.tar!ignoreme/file.txt",
			expected: true,
		},
		{
			name:     "no match",
			path:     "archive.tar!dir/file.txt",
			expected: false,
		},
		{
			name:     "empty path",
			path:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, PathAllowed(allowlist, tt.path))
		})
	}
}

// TestFileFragments_NestedArchiveAllowlist confirms that the global allowlist
// is applied at every archive depth, not just the first one.
func TestFileFragments_NestedArchiveAllowlist(t *testing.T) {
	cfg := &config.Config{
		Allowlists: []*config.Allowlist{
			{Paths: []*regexp.Regexp{regexp.MustCompile(`(^|/)api\.go$`)}},
		},
	}

	f, err := os.Open("../testdata/archives/nested.tar.gz")
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	file := File{
		Content:         f,
		Path:            "../testdata/archives/nested.tar.gz",
		Config:          cfg,
		MaxArchiveDepth: 5,
	}

	var paths []string
	err = file.Fragments(context.Background(), func(fragment Fragment, err error) error {
		require.NoError(t, err)
		paths = append(paths, fragment.FilePath)
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	for _, path := range paths {
		assert.NotEqualf(t, "api.go", filepath.Base(path), "allowlisted file was not skipped: %s", path)
	}

	// Sanity check: non-allowlisted files are still yielded from nested
	// archives.
	foundMain := false
	for _, path := range paths {
		if strings.HasSuffix(path, "files.tar"+InnerPathSeparator+"files/main.go") {
			foundMain = true
			break
		}
	}
	assert.True(t, foundMain, "expected fragments from nested archive, got: %v", paths)
}
