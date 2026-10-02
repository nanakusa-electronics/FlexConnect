package buildinfo

var Version = "2.0.0-dev"

// UpdateRepo is the GitHub "owner/name" used for online update checks.
// It is overridable at build time via ldflags and at runtime via the
// FLEXCONNECT_UPDATE_REPO environment variable. An empty value disables
// update checks silently.
var UpdateRepo = ""

const LocalAPIVersion = "3"
const LocalAPIMajor = 3

var LocalAPICapabilities = []string{
	"authentication",
	"component-health",
	"machine-mode",
	"operations",
	"profile-scope",
	"vpn-providers",
	"structured-errors",
	"watch-replay",
}
