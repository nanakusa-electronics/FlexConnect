package buildinfo

var Version = "1.3.3"

// UpdateRepo is the GitHub "owner/name" used for online update checks.
// It is overridable at build time via ldflags and at runtime via the
// FLEXCONNECT_UPDATE_REPO environment variable. An empty value disables
// update checks silently.
var UpdateRepo = ""

const LocalAPIVersion = "2"
const LocalAPIMajor = 2

var LocalAPICapabilities = []string{
	"component-health",
	"machine-mode",
	"operations",
	"profile-scope",
	"structured-errors",
	"watch-replay",
}
