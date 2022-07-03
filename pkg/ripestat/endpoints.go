package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

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

type AbuseContactFinderBase struct {
	ResponseBase
	Data AbuseContactFinder `json:"data"`
}

type ParameterBase struct {
	Resource string `json:"resource"`
}

type AbuseContactFinder struct {
	AbuseContacts    []string      `json:"abuse_contacts"`
	AuthoritativeRIR string        `json:"authoritative_rir"`
	LatestTime       string        `json:"latest_time"`
	EarliestTime     string        `json:"earliest_time"`
	Parameters       ParameterBase `json:"parameters"`
}

type NetworkInfo struct {
	ASNs   []string `json:"asns"`
	Prefix string   `json:"prefix"`
}

type ASBlock struct {
	Resource    string `json:"resource"`
	Description string `json:"desc"`
	Name        string `json:"name"`
}

type UnknownPercentage struct {
	V4 float64 `json:"v4"`
	V6 float64 `json:"v6"`
}

type MaxmindParameters struct {
	ParameterBase
	Resolution string `json:"resolution"`
}

type NetworkInfoBase struct {
	ResponseBase
	Data NetworkInfo `json:"data"`
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

type MaxmindGeoLiteBase struct {
	ResponseBase
	Data MaxmindGeoLite
}

type MaxmindGeoLite struct {
	LocatedResources   []LocatedResource `json:"located_resources"`
	UnknownPercentages UnknownPercentage `json:"unknown_percentage"`
	Parameters         MaxmindParameters `json:"parameters"`
	ResultTime         string            `json:"result_time"`
	LatestTime         string            `json:"latest_time"`
	EarliestTime       string            `json:"earliest_time"`
}

type LocatedResource struct {
	Resource  string             `json:"resource"`
	Locations []ResourceLocation `json:"locations"`
}

type ResourceLocation struct {
	Country   string   `json:"country"`
	City      string   `json:"city"`
	Resources []string `json:"resources"`
	// Latitude          float64  `json:"latitude"`  // XXX: another data type?
	// Longitude         float64  `json:"longitude"` // XXX: another data type?
	CoveredPercentage float64 `json:"covered_percentage"`
	UnknownPercentage float64 `json:"unknown_percentage"`
}
