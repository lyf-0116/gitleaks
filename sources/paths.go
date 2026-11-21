package sources

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/zricethezav/gitleaks/v8/config"
)

var cwdOnce = sync.OnceValues(os.Getwd)

// PathCandidates returns the deduplicated set of path forms that should be
// considered when matching |path| against allowlists, ignore entries, and
// well-known files (e.g. the gitleaks config or baseline).
//
// |path| may be a plain filesystem path or a composite archive path using
// InnerPathSeparator (e.g. "archive.tar!dir/file.txt"). The returned forms
// always include the path exactly as provided so that existing
// configurations keep matching the same way they always have.
func PathCandidates(path string) []string {
	if path == "" {
		return nil
	}

	var (
		candidates []string
		seen       = make(map[string]struct{})
	)
	add := func(p string) {
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		candidates = append(candidates, p)
	}

	// Legacy form: the path exactly as provided. This may be a composite
	// archive path joined with InnerPathSeparator and may use
	// platform-specific separators.
	add(path)

	// Platform-normalized form.
	// TODO: Make this the only form in v9.
	// (https://github.com/gitleaks/gitleaks/issues/1641)
	slashPath := filepath.ToSlash(path)
	add(slashPath)

	// The outermost container is the only part that exists on the filesystem.
	outerPath, innerPath, hasInnerPath := strings.Cut(slashPath, InnerPathSeparator)

	// Repo-relative form: the path relative to the current working directory.
	// Gitleaks is typically invoked from the root of the scanned repository,
	// so this lets anchored allowlist patterns (e.g. `^dir/`) match absolute
	// fragment paths.
	if filepath.IsAbs(outerPath) {
		if cwd, err := cwdOnce(); err == nil {
			if rel, err := filepath.Rel(cwd, outerPath); err == nil {
				relPath := filepath.ToSlash(rel)
				if hasInnerPath {
					relPath += InnerPathSeparator + innerPath
				}
				add(relPath)
			}
		}
	}

	// Archive-inner relative form: the path of the innermost entry within its
	// container (e.g. "dir/file.txt" for "archive.tar!dir/file.txt"). This
	// lets allowlist patterns match entries regardless of how the outer
	// archive was referenced.
	if hasInnerPath {
		add(slashPath[strings.LastIndex(slashPath, InnerPathSeparator)+1:])
	}

	return candidates
}

// PathAllowed reports whether any normalized form of |path| is allowed by
// the allowlist.
func PathAllowed(a *config.Allowlist, path string) bool {
	for _, candidate := range PathCandidates(path) {
		if a.PathAllowed(candidate) {
			return true
		}
	}
	return false
}
