package ripestat

type ResponseBase struct {
	Messages       []string `json:"messages"`
	SeeAlso        []string `json:"see_also"`
	DataCallName   string   `json:"data_call_name"`
	DataCallStatus string   `json:"data_call_status"`
	Cached         bool     `json:"cached"`
	QueryID        string   `json:"query_id"`
	ProcessTime    int      `json:"process_time"`
	ServerID       string   `json:"server_id"`
	BuildVersion   string   `json:"build_version"`
	Status         string   `json:"status"`
	StatusCode     int      `json:"status_code"`
	Time           string   `json:"time"`
}

type ParameterBase struct {
	Resource string `json:"resource"`
}

type AbuseContactFinderBase struct {
	ResponseBase
	Data AbuseContactFinder `json:"data"`
}

type AbuseContactFinder struct {
	AbuseContacts    []string      `json:"abuse_contacts"`
	AuthoritativeRIR string        `json:"authoritative_rir"`
	LatestTime       string        `json:"latest_time"`
	EarliestTime     string        `json:"earliest_time"`
	Parameters       ParameterBase `json:"parameters"`
}

type NetworkInfoBase struct {
	ResponseBase
	Data NetworkInfo `json:"data"`
}

type NetworkInfo struct {
	ASNs   []string `json:"asns"`
	Prefix string   `json:"prefix"`
}

type ASOverviewBase struct {
	ResponseBase
	Data ASOverview `json:"data"`
}

type ASOverview struct {
	Type           string  `json:"type"`
	Resource       string  `json:"resource"`
	Block          ASBlock `json:"block"`
	Holder         string  `json:"holder"`
	Announced      bool    `json:"announced"`
	QueryStartTime string  `json:"query_starttime"`
	QueryEndTime   string  `json:"query_endtime"`
}

type ASBlock struct {
	Resource    string `json:"resource"`
	Description string `json:"desc"`
	Name        string `json:"name"`
}
