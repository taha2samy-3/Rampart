package domain

// AdvisoryMode defines how vulnerability advisories and reports are served and synchronized:
// - "hybrid": Checks local database first; if missing or empty, fetches live from upstream advisory APIs and stores it locally like a feed.
// - "live": Always fetches live from upstream advisory APIs on demand and updates the local database.
// - "stored": Serves only locally stored/synced advisory records (offline / airgap mode).
type AdvisoryMode string

const (
	AdvisoryModeHybrid AdvisoryMode = "hybrid"
	AdvisoryModeLive   AdvisoryMode = "live"
	AdvisoryModeStored AdvisoryMode = "stored"
)

// AdvisorySourceSpec is the specification of a ClusterAdvisorySource resource (docs/43, D141).
type AdvisorySourceSpec struct {
	Enabled         bool              `json:"enabled"`
	Mode            AdvisoryMode      `json:"mode"`
	LiveFetch       bool              `json:"liveFetch"`
	PersistReports  bool              `json:"persistReports"`
	RefreshInterval string            `json:"refreshInterval,omitempty"`
	Sources         AdvisoryProviders `json:"sources"`
}

// AdvisoryProviders groups upstream intelligence and advisory sources.
type AdvisoryProviders struct {
	OSV       *AdvisoryOSVSpec      `json:"osv,omitempty"`
	NVD       *AdvisoryNVDSpec      `json:"nvd,omitempty"`
	Sonatype  *AdvisorySonatypeSpec `json:"sonatype,omitempty"`
	Snyk      *AdvisorySnykSpec     `json:"snyk,omitempty"`
	VulnCheck *AdvisoryTokenSpec    `json:"vulncheck,omitempty"`
	DepsDev   *AdvisoryBaseSpec     `json:"depsdev,omitempty"`
	Custom    []AdvisoryCustomSpec  `json:"custom,omitempty"`
}

type AdvisoryBaseSpec struct {
	Enabled *bool  `json:"enabled,omitempty"`
	URL     string `json:"url,omitempty"`
}

type AdvisoryTokenSpec struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
}

type AdvisoryOSVSpec struct {
	Enabled    *bool    `json:"enabled,omitempty"`
	URL        string   `json:"url,omitempty"`
	Ecosystems []string `json:"ecosystems,omitempty"`
}

type AdvisoryNVDSpec struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	URL       string `json:"url,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
}

type AdvisorySonatypeSpec struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	URL       string `json:"url,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
}

type AdvisorySnykSpec struct {
	Enabled   *bool  `json:"enabled,omitempty"`
	URL       string `json:"url,omitempty"`
	OrgID     string `json:"orgId,omitempty"`
	TokenFile string `json:"tokenFile,omitempty"`
}

type AdvisoryCustomSpec struct {
	Name      string `json:"name"`
	Enabled   *bool  `json:"enabled,omitempty"`
	Format    string `json:"format"`
	URL       string `json:"url"`
	TokenFile string `json:"tokenFile,omitempty"`
}
