package types

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

type (
	MergeResultsMap map[string]*MergeResult

	MergeResult struct {
		EnrichInfo
		NucleiJsonRecord
	}

	// NucleiJsonRecord TODO: there is more nuclei data than this, but this is the minimum we need to enrich
	NucleiJsonRecord struct {
		TemplateId string `json:"template-id"`
		Info       struct {
			Name        string   `json:"name"`
			Author      []string `json:"author"`
			Tags        []string `json:"tags"`
			Reference   []string `json:"reference"`
			Severity    string   `json:"severity"`
			Description string   `json:"description"`
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

	EnrichInfo struct {
		Ip          string
		AbuseSource string
		Abuse       string
		Prefix      string
		Asn         string
		Holder      string
		Country     string
		City        string
	}
)
