package enricher

/*
* https://www.DIVD.nl
* written by Pepijn van der Stap
 */

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"nuclei-parse-enrich/pkg/types"

	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
)

var (
	whoisRegexp = regexp.MustCompile("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
)

const (
	ripeStatSourceApp = "AS50559-DIVD_NL"
)

type Enricher struct {
	types.EnrichInfo
}

func NewEnricher(ip string) *Enricher {
	return &Enricher{
		EnrichInfo: types.EnrichInfo{
			Ip: ip,
		},
	}
}

func (e *Enricher) Enrich() *types.EnrichInfo {
	return e.EnrichIP(e.Ip)
}

func (e *Enricher) EnrichIP(ipAddr string) *types.EnrichInfo {
	e.EnrichInfo = types.EnrichInfo{
		Ip: ipAddr,
	}

	e.EnrichInfo.Abuse, e.EnrichInfo.Abuse_source = e.enrichAbuseFromIP(ipAddr)
	e.EnrichInfo.Prefix, e.EnrichInfo.Asn = e.enrichPrefixAndASNFromIP(ipAddr)
	e.EnrichInfo.Holder = e.enrichHolderFromASN(e.EnrichInfo.Asn)
	e.EnrichInfo.City, e.EnrichInfo.Country = e.enrichCityAndCountryFromPrefix(e.EnrichInfo.Prefix)

	return &e.EnrichInfo
}

func (e *Enricher) enrichAbuseFromIP(ipAddr string) (string, string) {
	abuse := "unknown"
	abuseSource := ""

	// Get abuse info - https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>
	ripestat_abuse_reply, err := e.queryRipeStat("abuse-contact-finder", ipAddr)
	if err != nil {
		return abuse, abuseSource
	}

	abuse_contacts_ripeStat := []string{}

	if ripestat_abuse_reply != nil {
		abuse_reply_data := ripestat_abuse_reply["data"].(map[string]interface{})
		if abuse_reply_data != nil {
			abuse_reply_data_abuse_contacts := abuse_reply_data["abuse_contacts"].([]interface{})

			for _, abuse_contact := range abuse_reply_data_abuse_contacts {
				abuse_contacts_ripeStat = append(abuse_contacts_ripeStat, abuse_contact.(string))
			}
		}
	}

	if len(abuse_contacts_ripeStat) > 0 {
		return strings.Join(abuse_contacts_ripeStat, ";"), "ripeSTAT"
	}

	// Fallback to whois
	contacts_from_whois := e.whoisEnrichment()
	if len(contacts_from_whois) > 0 {
		return strings.Join(contacts_from_whois, ";"), "whois"
	}

	return abuse, abuseSource
}

func (e *Enricher) enrichPrefixAndASNFromIP(ipAddr string) (string, string) {
	prefix := "unknown"
	asn := "unknown"

	// Get ASN - https://stat.ripe.net/data/network-info/data.json?resource=
	asn_reply, err := e.queryRipeStat("network-info", ipAddr)
	if err != nil {
		return prefix, asn
	}

	asn_reply_data := asn_reply["data"].(map[string]interface{})

	if replyPrefix, ok := asn_reply_data["prefix"]; ok {
		prefix = replyPrefix.(string)
	}

	if asns, ok := asn_reply_data["asns"]; ok {
		asn_reply_data_asn := asns.([]interface{})
		if len(asn_reply_data_asn) > 0 {
			asn = asn_reply_data_asn[0].(string)
		}
	}

	return prefix, asn
}

func (e *Enricher) enrichHolderFromASN(asn string) string {
	holder := "unknown"

	// Get ASN info from ripeStat - https://stat.ripe.net/data/as-overview/data.json?resource=
	if asn == "unknown" {
		return holder
	}

	asn_data, err := e.queryRipeStat("as-overview", asn)
	if err != nil {
		return holder
	}

	if asn_data["data"] != nil {
		asn_datablock := asn_data["data"].(map[string]interface{})
		if asn_datablock["holder"] != nil {
			holder = asn_datablock["holder"].(string)
		}
	}

	return holder
}

func (e *Enricher) enrichCityAndCountryFromPrefix(prefix string) (string, string) {
	city := "unknown"
	country := "unknown"

	if prefix == "unknown" {
		return city, country
	}

	location_data, err := e.queryRipeStat("maxmind-geo-lite", prefix)
	if err != nil {
		return city, country
	}

	if location_data["data"] != nil {
		location_data_located_resources := location_data["data"].(map[string]interface{})["located_resources"].([]interface{})
		if len(location_data_located_resources) > 0 {
			location_data_located_resources_locations := location_data_located_resources[0].(map[string]interface{})["locations"].([]interface{})
			if len(location_data_located_resources_locations) > 0 {
				location_data_located_resources_location := location_data_located_resources_locations[0].(map[string]interface{})
				city = location_data_located_resources_location["city"].(string)
				country = location_data_located_resources_location["country"].(string)
			}
		}
	}

	return city, country
}

func (e *Enricher) whoisEnrichment() []string {
	return e.whoisEnrichmentIP(e.Ip)
}

func (e *Enricher) whoisEnrichmentIP(ipAddr string) []string {
	logrus.Debug("enricher: ripestat has no abuse mails for us, executing whoisEnrichment on IP address: ", ipAddr)

	whoisInfo, err := whois.Whois(ipAddr)
	if err != nil || whoisInfo == "" {
		logrus.Debug("enricher: whoisEnrichment - could not get whois info for ", ipAddr)
		return []string{}
	}

	foundMailAddresses := whoisRegexp.FindAllString(whoisInfo, -1)
	switch len(foundMailAddresses) {
	case 0:
		logrus.Debug("enricher: whoisEnrichment - could not find any abuse emails for ", ipAddr)
		return []string{}
	case 1:
		// Spare some allocations and a sort if there's only one address found
		return []string{strings.ToLower(foundMailAddresses[0])}
	}

	// lower and sort unique
	m := make(map[string]struct{}, len(foundMailAddresses))
	for _, v := range foundMailAddresses {
		m[strings.ToLower(v)] = struct{}{}
	}

	abusemails := make([]string, 0, len(m))
	for k := range m {
		abusemails = append(abusemails, k)
	}
	sort.Strings(abusemails)

	return abusemails
}

func (e *Enricher) queryRipeStat(resource string, query string) (map[string]interface{}, error) {
	if query == "" {
		return nil, fmt.Errorf("empty query for resource %v", resource)
	}
	url := fmt.Sprintf("https://stat.ripe.net/data/%s/data.json?resource=%s&sourceapp=%s", resource, query, ripeStatSourceApp)

	resp, err := http.Get(url)
	if err != nil {
		logrus.Debug("enricher: queryRipeStat - could not get data from ", url)
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Debug("enricher: queryRipeStat - could not read response body from ", url)
		return nil, err
	}

	var data map[string]interface{}

	err = json.Unmarshal(body, &data)
	if err != nil {
		logrus.Debug("enricher: queryRipeStat - could not unmarshal response body from ", url)
		return nil, err
	}
	if data == nil {
		return data, errors.New("enricher: ripestat is down " + url)
	}
	return data, nil
}
