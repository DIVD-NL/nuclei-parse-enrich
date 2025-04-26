package enricher

import (
	"regexp"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ipinfo"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ripestat"
)

// Using a simpler regex pattern for email extraction
// This pattern is less complex but still effective for most cases
// and much less vulnerable to ReDoS attacks
var whoisRegexp = regexp.MustCompile("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")

const (
	// RipeStatSourceApp is the application identifier sent to RIPE Stat API
	RipeStatSourceApp = "AS50559-DIVD_NL"
)

// Enricher contains clients for enrichment data sources
type Enricher struct {
	ripeClient   *ripestat.Client
	ipinfoClient *ipinfo.Client
}
