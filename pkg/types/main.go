package types

/*
* https://www.DIVD.nl
* written by Pepijn van der Stap
 */

type MergeResults []*MergeResult

type MergeResult struct {
	EnrichInfo
	NucleiJsonRecord
}

type NucleiJsonRecord struct {
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

type EnrichInfo struct {
	Ip           string
	Abuse_source string
	Abuse        string
	Prefix       string
	Asn          string
	Holder       string
	Country      string
	City         string
}
