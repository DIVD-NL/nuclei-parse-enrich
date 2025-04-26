package types

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

// MergeResultsMap defines a map from IP addresses to their merged enrichment results
type MergeResultsMap map[string]*MergeResult

// MergeResult combines enrichment data with the original Nuclei scan record
type MergeResult struct {
	EnrichInfo
	NucleiJsonRecord
}

// SimpleIPRecord represents a basic IP record for simple IP list processing
type SimpleIPRecord struct {
	Ip string
}

// NucleiJsonRecord represents the structure of vulnerability findings from Nuclei scanner
// It captures the essential fields from Nuclei output needed for enrichment
type NucleiJsonRecord struct {
	TemplateId string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Author         []string `json:"author"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Severity       string   `json:"severity"`
		Classification struct {
			CveId       []string `json:"cve-id"`
			CweId       []string `json:"cwe-id"`
			CvssMetrics string   `json:"cvss-metrics"`
			CvssScore   float32  `json:"cvss-score"`
		} `json:"classification"`
		Description string `json:"description"`
	} `json:"info"`
	Type             string   `json:"type"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Ip               string   `json:"ip"`
	Timestamp        string   `json:"timestamp"`
	CurlCommand      string   `json:"curl-command"`
	MatcherStatus    bool     `json:"matcher-status"`
	MatchedLine      string   `json:"matched-line"`
}

// EnrichInfo contains additional information about an IP address gathered from external sources
type EnrichInfo struct {
	// IP address this enrichment data belongs to
	Ip string
	// Source of the abuse contact information (e.g., "RipeSTAT", "whois", "ipinfo")
	AbuseSource string
	// Email address(es) for reporting abuse, semicolon-separated if multiple
	Abuse string
	// Network prefix/CIDR block the IP belongs to
	Prefix string
	// Autonomous System Number
	Asn string
	// Organization name that owns the ASN
	Holder string
	// Country code where the IP is located
	Country string
	// City where the IP is located
	City string
}
