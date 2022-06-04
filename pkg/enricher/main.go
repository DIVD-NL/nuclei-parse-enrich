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

type Enricher struct {
	types.EnrichInfo
	ripeStatSourceApp string
}

func NewEnricher(ip string) *Enricher {
	return &Enricher{
		EnrichInfo: types.EnrichInfo{
			Ip: ip,
		},
		ripeStatSourceApp: "AS50559-DIVD_NL",
	}
}

func (e *Enricher) Enrich() *types.EnrichInfo {
	e.EnrichInfo = types.EnrichInfo{
		Ip:           e.Ip,
		Abuse_source: "",
		Abuse:        "unknown",
		Country:      "unknown",
		City:         "unknown",
		Holder:       "unknown",
	}

	// Get abuse info - https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>
	ripestat_abuse_reply, err := e.queryRipeStat("abuse-contact-finder", e.Ip)
	if err == nil {
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
			e.EnrichInfo.Abuse = strings.Join(abuse_contacts_ripeStat, ";")
			e.EnrichInfo.Abuse_source = "ripeSTAT"
		} else {
			contacts_from_whois := e.whoisEnrichment()
			if len(contacts_from_whois) > 0 {
				e.EnrichInfo.Abuse = strings.Join(contacts_from_whois, ";")
				e.EnrichInfo.Abuse_source = "whois"
			}
		}

		// Get ASN - https://stat.ripe.net/data/network-info/data.json?resource=
		asn_reply, err := e.queryRipeStat("network-info", e.Ip)
		if err == nil {
			asn_reply_data := asn_reply["data"].(map[string]interface{})

			if asn_reply_data["prefix"] != nil {
				e.EnrichInfo.Prefix = asn_reply_data["prefix"].(string)
			}

			if asn_reply_data["asns"] != nil {
				asn_reply_data_asn := asn_reply_data["asns"].([]interface{})
				if len(asn_reply_data_asn) > 0 {
					e.EnrichInfo.Asn = asn_reply_data_asn[0].(string)
				}
			}
		}

		// Get ASN info from ripeStat - https://stat.ripe.net/data/as-overview/data.json?resource=
		if e.EnrichInfo.Asn != "unknown" {
			asn_data, err := e.queryRipeStat("as-overview", e.EnrichInfo.Asn)
			if err == nil {
				if asn_data["data"] != nil {
					asn_datablock := asn_data["data"].(map[string]interface{})
					if asn_datablock["holder"] != nil {
						e.EnrichInfo.Holder = asn_datablock["holder"].(string)
					}
				}
			}

			// Get geolocation from RipeStat - https://stat.ripe.net/data/geoloc/data.json?resource=
			if e.EnrichInfo.Prefix != "unknown" {
				location_data, err := e.queryRipeStat("maxmind-geo-lite", e.EnrichInfo.Prefix)
				if err == nil {
					if location_data["data"] != nil {
						location_data_located_resources := location_data["data"].(map[string]interface{})["located_resources"].([]interface{})
						if len(location_data_located_resources) > 0 {
							location_data_located_resources_locations := location_data_located_resources[0].(map[string]interface{})["locations"].([]interface{})
							if len(location_data_located_resources_locations) > 0 {
								location_data_located_resources_location := location_data_located_resources_locations[0].(map[string]interface{})
								e.EnrichInfo.City = location_data_located_resources_location["city"].(string)
								e.EnrichInfo.Country = location_data_located_resources_location["country"].(string)
							}
						}
					}
				}
			}
		}
	}
	return &e.EnrichInfo
}

func (e *Enricher) whoisEnrichment() []string {
	logrus.Debug("enricher: ripestat has no abuse mails for us, executing whoisEnrichment on e.Ip: ", e.Ip)

	re := regexp.MustCompile("[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*")
	abusemails := []string{}

	whois, err := whois.Whois(e.Ip)

	if err != nil || whois == "" {
		logrus.Debug("enricher: whoisEnrichment - could not get whois info for ", e.Ip)
		return []string{}
	}

	abusemails = append(abusemails, re.FindAllString(whois, -1)...)

	if len(abusemails) == 0 {
		logrus.Debug("enricher: whoisEnrichment - could not find any abuse emails for ", e.Ip)
	}

	// lower and sort unique
	func() {
		m := make(map[string]bool)
		for _, v := range abusemails {
			m[strings.ToLower(v)] = true
		}
		abusemails = make([]string, 0, len(m))
		for k := range m {
			abusemails = append(abusemails, k)
		}
		sort.Strings(abusemails)
	}()

	return abusemails
}

func (e *Enricher) queryRipeStat(resource string, query string) (map[string]interface{}, error) {
	url := fmt.Sprintf("https://stat.ripe.net/data/%s/data.json?resource=%s&sourceapp=%s", resource, query, e.ripeStatSourceApp)

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
