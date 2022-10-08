package enricher

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"errors"
	"net/mail"
	"os"
	"strings"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ipinfo"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ripestat"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/types"

	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
)

func NewEnricher() *Enricher {
	ipInfoToken := os.Getenv("IPINFO_TOKEN")

	if ipInfoToken != "" {
		return &Enricher{
			rs: ripestat.NewRipeStatClient(RipeStatSourceApp, 10),
			io: ipinfo.NewIpInfoClient(3, ipInfoToken),
		}
	}

	return &Enricher{
		rs: ripestat.NewRipeStatClient(RipeStatSourceApp, 10),
		io: nil,
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
			return foundMailAddresses, abuseSource
		}

		return mailAddress.Address, abuseSource
	}

	if len(rsEmailAddresses) > 1 {
		var cleanMailAddresses []string

		for _, mailAddress := range rsEmailAddresses {
			mailAddress, err := mail.ParseAddress(mailAddress)
			if err != nil {
				logrus.Warnf("abuse foundMailAddresses err: %v", err)
				continue
			}
			cleanMailAddresses = append(cleanMailAddresses, mailAddress.Address)
		}

		return strings.Join(cleanMailAddresses, ";"), abuseSource
	}

	// Fallback to whois if no abuse contact was found in whois..
	contactsFromWhois, err := e.whoisEnrichmentIP(ipAddr)
	if err != nil {
		logrus.Warnf("abuse contactsFromWhois err: %v", err)
		return foundMailAddresses, abuseSource
	}

	if len(contactsFromWhois) > 0 {
		return strings.Join(contactsFromWhois, ";"), "whois"
	}

	//// Fallback to ipinfo if no abuse contact was found in whois either
	//abuseContact, err := e.io.GetAbuseContact(ipAddr)
	//if err != nil {
	//	logrus.Debugf("abuse contactsFromIpinfo err: %v", err)
	//	return foundMailAddresses, abuseSource
	//}
	//
	//if abuseContact != "" {
	//	return abuseContact, "ipinfo"
	//} //@TODO: re-enable

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

func (e *Enricher) whoisEnrichmentIP(ipAddr string) ([]string, error) {
	logrus.Debug("enricher: ripestat has no abuse mails for us, executing whoisEnrichment on IP address: ", ipAddr)

	whoisInfo, err := whois.Whois(ipAddr)
	if err != nil {
		logrus.Debug("enricher: whoisEnrichment - could not get whois info for ", ipAddr)
		return nil, err
	}

	if whoisInfo == "" {
		err := errors.New("enricher: whoisEnrichment - whois info is empty for " + ipAddr)
		return nil, err
	}

	foundMailAddresses := whoisRegexp.FindAllString(whoisInfo, -1)

	switch len(foundMailAddresses) {
	case 0:
		err := errors.New("enricher: whoisEnrichment - could not find any abuse emails for " + ipAddr)
		return nil, err
	case 1:
		// Spare some allocations and a sort if there's only one address found
		email, err := mail.ParseAddress(foundMailAddresses[0])
		if err != nil {
			err := errors.New("enricher: whoisEnrichment - could not parse email address for " + ipAddr)
			return nil, err
		}

		return []string{strings.ToLower(email.Address)}, nil
	}

	// lower and sort unique
	var uniqueMailAddresses = make(map[string]struct{}, len(foundMailAddresses))
	for i, v := range foundMailAddresses {
		email, err := mail.ParseAddress(v)

		if err != nil {
			logrus.Debugf("enricher: whoisEnrichment - could not parse email address %d for %s", i, ipAddr)
			continue
		}

		uniqueMailAddresses[strings.ToLower(email.Address)] = struct{}{}
	}

	abuseEmails := make([]string, 0, len(uniqueMailAddresses))

	for k := range uniqueMailAddresses {
		abuseEmails = append(abuseEmails, k)
	}

	return abuseEmails, nil
}
