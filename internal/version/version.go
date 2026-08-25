package version

var (
	Version = "0.0.1-dev"
	Commit  = "unknown"
)

func String() string {
	return Version + " (" + Commit + ")"
}
