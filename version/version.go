package version

import (
	"runtime/debug"
	"strings"
)

var (
	Version   = "" // overridden by GoReleaser ldflags at build time
	Commit    = "dev"
	BuildDate = "unknown"
)

func init() {
	if Version != "" {
		return
	}
	// Fallback when built via `go install` (no ldflags): read module version.
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = strings.TrimPrefix(info.Main.Version, "v")
		return
	}
	Version = "dev"
}
