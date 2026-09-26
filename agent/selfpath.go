package agent

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	selfPathsOnce sync.Once
	selfPathsList []string
)

// selfPaths returns the set of path forms under which the agent's own
// executable may be reported by Sysmon. When the agent is launched from a
// mapped network drive (e.g. Z:\whids.exe where Z: is \\vbox\test), Sysmon
// reports the canonical UNC path (\\vbox\test\whids.exe), so both the
// original and the resolved UNC form are included. On non-Windows platforms
// (or when no mapped-drive mapping applies) only the original path is
// returned, so existing behaviour is unchanged.
func selfPaths() []string {
	selfPathsOnce.Do(func() {
		exe := os.Args[0]
		if e, err := os.Executable(); err == nil && e != "" {
			exe = e
		}
		selfPathsList = uniquePaths(
			selfPath,
			cleanAbs(exe),
			mapDriveLetterToUNC(selfPath),
			mapDriveLetterToUNC(cleanAbs(exe)),
		)
	})
	return selfPathsList
}

func cleanAbs(p string) string {
	if p == "" {
		return ""
	}
	if a, err := filepath.Abs(p); err == nil {
		return a
	}
	return p
}

func uniquePaths(paths ...string) []string {
	out := make([]string, 0, len(paths))
	for _, s := range paths {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		dup := false
		for _, p := range out {
			if strings.EqualFold(p, s) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}

// selfPathMatch reports whether image (as reported by Sysmon) matches any of
// the agent's own executable path forms. Comparison is case-insensitive, as
// Windows paths are.
func selfPathMatch(image string) bool {
	if image == "" {
		return false
	}
	for _, p := range selfPaths() {
		if strings.EqualFold(p, image) {
			return true
		}
	}
	return false
}
