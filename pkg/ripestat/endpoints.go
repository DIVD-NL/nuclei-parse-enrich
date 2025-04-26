package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// ASN is a custom type that can handle both string and integer ASN values
type ASN int

// UnmarshalJSON implements custom unmarshaling for ASN values from RIPE Stat API
// RIPE API may return ASNs as strings or integers
func (a *ASN) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as an integer first
	var intValue int
	if err := json.Unmarshal(data, &intValue); err == nil {
		*a = ASN(intValue)
		return nil
	}

	// If that fails, try to unmarshal as a string
	var stringValue string
	if err := json.Unmarshal(data, &stringValue); err != nil {
		return err
	}

	// Remove any "AS" prefix if present
	stringValue = strings.TrimPrefix(stringValue, "AS")
	stringValue = strings.TrimSpace(stringValue)

	// Convert the string to an integer
	intValue, err := strconv.Atoi(stringValue)
	if err != nil {
		return err
	}

	*a = ASN(intValue)
	return nil
}

// Int returns the int value of the ASN
func (a ASN) Int() int {
	return int(a)
}

// MarshalJSON implements custom marshaling for ASN
func (a ASN) MarshalJSON() ([]byte, error) {
	return json.Marshal(int(a))
}

// RipeTime is a custom time type that handles the RIPE API time format
type RipeTime time.Time

// UnmarshalJSON implements custom unmarshaling for time values from RIPE Stat API
// RIPE API may return times in various formats, with or without timezone information
func (rt *RipeTime) UnmarshalJSON(data []byte) error {
	// Remove the quotes from the JSON string
	s := strings.Trim(string(data), "\"")
	if s == "" || s == "null" {
		*rt = RipeTime(time.Time{})
		return nil
	}

	// Try to parse with timezone first
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		*rt = RipeTime(t)
		return nil
	}

	// Try to parse without timezone - using multiple formats
	formats := []string{
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05.999999",
	}

	for _, format := range formats {
		t, err := time.Parse(format, s)
		if err == nil {
			*rt = RipeTime(t)
			return nil
		}
	}

	// Return original error if none of the formats match
	return err
}

// Time returns the time.Time value
func (rt RipeTime) Time() time.Time {
	return time.Time(rt)
}

// MarshalJSON implements custom marshaling for RipeTime
func (rt RipeTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Time(rt).Format(time.RFC3339))
}

// Response represents the standard response format from the RIPE Stat API
type Response struct {
	Status       string   `json:"status"`
	StatusCode   int      `json:"status_code"`
	Version      string   `json:"version"`
	ServerID     string   `json:"server_id"`
	Method       string   `json:"method"`
	ClientID     string   `json:"client_id"`
	APIKey       string   `json:"api_key"`
	Time         RipeTime `json:"time"` // Using custom RipeTime type
	ProcessTime  int      `json:"query_time"`
	ResultTime   int      `json:"result_time"`
	SeeAlso      []string `json:"see_also"`
	Parameters   struct{} `json:"parameters"`
	QueryID      string   `json:"query_id"`
	DataCallName string   `json:"data_call_name"`
	DataCall     string   `json:"data_call"`
	// Cached is a boolean that indicates if the data was cached
	Cached bool `json:"cached"`
}

// IsCached returns whether the response was served from cache
func (r Response) IsCached() bool {
	return r.Cached
}

// AbuseContactResponse represents the response from abuse-contact-finder endpoint
type AbuseContactResponse struct {
	Response
	Data struct {
		AbuseContacts    []string `json:"abuse_contacts"`
		AuthoritativeRIR string   `json:"authoritative_rir"`
		IPOrPrefix       string   `json:"ip_or_prefix"`
		// Time fields mentioned in documentation
		EarliestTime RipeTime `json:"earliest_time,omitempty"`
		LatestTime   RipeTime `json:"latest_time,omitempty"`
		// Parameters section in documentation
		Parameters struct {
			Resource string `json:"resource"`
		} `json:"parameters,omitempty"`
	} `json:"data"`
}

// NetworkInfoResponse represents the response from network-info endpoint
type NetworkInfoResponse struct {
	Response
	Data struct {
		Prefix      string `json:"prefix"`
		ASNs        []ASN  `json:"asns"`
		Holder      string `json:"holder"`
		Announced   bool   `json:"announced"`
		RelatedPfxs []struct {
			Prefix string `json:"prefix"`
			Name   string `json:"name"`
		} `json:"related_prefixes"`
	} `json:"data"`
}

// ASOverviewResponse represents the response from as-overview endpoint
type ASOverviewResponse struct {
	Response
	Data struct {
		Holder     string `json:"holder"`
		ASNumber   ASN    `json:"asn"`
		Announced  bool   `json:"announced"`
		BlockList  []string
		QueryTime  RipeTime `json:"query_time"`
		ResourcesT struct {
			IPv4 []string `json:"ipv4"`
			IPv6 []string `json:"ipv6"`
		} `json:"resources"`
	} `json:"data"`
}

// NetworkInfo contains simplified network information
type NetworkInfo struct {
	Prefix string
	ASNs   []ASN
	Holder string
}

// ASOverview contains simplified AS overview information
type ASOverview struct {
	Holder   string
	ASNumber ASN
}

// GeolocationResponse represents the response from maxmind-geo-lite endpoint
type GeolocationResponse struct {
	Response
	Data struct {
		Located     []LocatedPrefix `json:"located_resources"`
		Resource    string          `json:"resource"`
		LocationFor string          `json:"location_for"`
	} `json:"data"`
}

// LocatedPrefix represents geolocation information for a prefix
type LocatedPrefix struct {
	Locations []GeoLocation `json:"locations"`
	Prefix    string        `json:"resource"`
}

// GeoLocation contains detailed geographical location information
type GeoLocation struct {
	CountryCode string  `json:"country"`
	City        string  `json:"city"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	CountryName string  `json:"country_name"`
	Unknown     bool    `json:"covered_percentage"`
}

// MaxmindGeoLite is a simplified representation of geolocation data
type MaxmindGeoLite struct {
	City        string
	CountryCode string
}
