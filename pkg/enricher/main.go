package enricher

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"net/mail"
	"regexp"
	"strings"

	"nuclei-parse-enrich/pkg/ipinfo"
	"nuclei-parse-enrich/pkg/ripestat"
	"nuclei-parse-enrich/pkg/types"

	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
)

var whoisRegexp = regexp.MustCompile("[a-zA-Z\\d.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?(?:\\.[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?)*\\.?[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?(?:\\.[a-zA-Z\\d](?:[a-zA-Z\\d-]{0,61}[a-zA-Z\\d])?)*")

const (
	RipeStatSourceApp = "AS50559-DIVD_NL"
)

type Enricher struct {
	rs *ripestat.Client
	is *ipinfo.Client
}

func NewEnricher() *Enricher {
	return &Enricher{
		rs: ripestat.NewRipeStatClient(RipeStatSourceApp, 10),
		is: ipinfo.NewIpInfoClient(3),
	}
}

func (e *Enricher) EnrichIP(ipAddr string) types.EnrichInfo {
	ret := types.EnrichInfo{
		Ip: ipAddr,
	}

	ret.Abuse, ret.AbuseSource = e.enrichAbuseFromIP(ipAddr)
	ret.Prefix, ret.Asn = e.enrichPrefixAndASNFromIP(ipAddr)
	ret.Holder = e.enrichHolderFromASN(ret.Asn)
	ret.City, ret.Country = e.enrichCityAndCountryFromPrefix(ret.Prefix)

	return ret
}

func (e *Enricher) enrichAbuseFromIP(ipAddr string) (foundMailAddresses string, abuseSource string) {
	foundMailAddresses = "unknown"
	abuseSource = "RipeSTAT"

	rsEmailAddresses, err := e.rs.GetAbuseContacts(ipAddr)
	if err != nil {
		logrus.Warnf("abuse rsEmailAddresses err: %v", err)
		return foundMailAddresses, abuseSource
	}

	if len(rsEmailAddresses) == 1 {
		mailAddress, err := mail.ParseAddress(rsEmailAddresses[0])
		if err != nil {
			logrus.Warnf("abuse foundMailAddresses err: %v", err)
		}

		return mailAddress.Address, abuseSource
	}

	if len(rsEmailAddresses) > 1 {
		var cleanMailAddresses []string

		for _, mailAddress := range rsEmailAddresses {
			mailAddress, err := mail.ParseAddress(mailAddress)
			if err != nil {
				logrus.Warnf("abuse foundMailAddresses err: %v", err)
			}
			cleanMailAddresses = append(cleanMailAddresses, mailAddress.Address)
		}

		return strings.Join(cleanMailAddresses, ";"), abuseSource
	}

	// Fallback to whois
	contactsFromWhois := e.whoisEnrichmentIP(ipAddr)
	if len(contactsFromWhois) > 0 {
		return strings.Join(contactsFromWhois, ";"), "whois"
	}

	return foundMailAddresses, abuseSource
}

func (e *Enricher) enrichPrefixAndASNFromIP(ipAddr string) (string, string) {
	prefix := "unknown"
	asn := "unknown"

	netInfo, err := e.rs.GetNetworkInfo(ipAddr)
	if err != nil {
		logrus.Warnf("network info err: %v", err)
		return prefix, asn
	}

	if len(netInfo.ASNs) == 0 {
		return netInfo.Prefix, asn
	}

	return netInfo.Prefix, netInfo.ASNs[0]
}

func (e *Enricher) enrichHolderFromASN(asn string) string {
	holder := "unknown"

	if asn == "unknown" {
		return holder
	}

	asOverview, err := e.rs.GetASOverview(asn)
	if err != nil {
		logrus.Warnf("holder err: %v", err)
		return holder
	}

	return asOverview.Holder
}

func (e *Enricher) enrichCityAndCountryFromPrefix(prefix string) (string, string) {
	city := "unknown"
	country := "unknown"

	if prefix == "unknown" {
		return city, country
	}

	geolocation, err := e.rs.GetGeolocationData(prefix)
	if err != nil {
		logrus.Warnf("geolocation err: %v", err)
		return city, country
	}

	if len(geolocation.LocatedResources) == 0 {
		return city, country
	}

	if len(geolocation.LocatedResources[0].Locations) == 0 {
		return city, country
	}

	return geolocation.LocatedResources[0].Locations[0].City, geolocation.LocatedResources[0].Locations[0].Country
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
		// TODO: fall back to ipinfo. Whois is not always available
		return []string{}
	case 1:
		// Spare some allocations and a sort if there's only one address found
		email, err := mail.ParseAddress(foundMailAddresses[0])
		if err != nil {
			logrus.Debug("enricher: whoisEnrichment - could not parse email address for ", ipAddr)
			return []string{}
		}

		return []string{strings.ToLower(email.Address)}
	}

	// lower and sort unique
	var uniqueMailAddresses = make(map[string]struct{}, len(foundMailAddresses))
	for _, v := range foundMailAddresses {
		email, err := mail.ParseAddress(v)

		if err != nil {
			logrus.Debug("enricher: whoisEnrichment - could not parse email address for ", ipAddr)
			continue
		}

		uniqueMailAddresses[strings.ToLower(email.Address)] = struct{}{}
	}

	abuseEmails := make([]string, 0, len(uniqueMailAddresses))

	for k := range uniqueMailAddresses {
		abuseEmails = append(abuseEmails, k)
	}

	return abuseEmails
}
