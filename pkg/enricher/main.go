package enricher

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"fmt"
	"maps"
	"net/mail"
	"os"
	"regexp"
	"strings"

	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ipinfo"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/ripestat"
	"github.com/DIVD-NL/nuclei-parse-enrich/pkg/types"

	"github.com/likexian/whois"
	"github.com/sirupsen/logrus"
)

// Constants for error and log messages
const (
	errWhoisEmpty      = "enricher: whoisEnrichment - whois info is empty for %s"
	errNoAbuseEmails   = "enricher: whoisEnrichment - could not find any abuse emails for %s"
	errInvalidEmail    = "enricher: whoisEnrichment - could not parse email address for %s"
	logWhoisNoInfo     = "enricher: whoisEnrichment - could not get whois info for %s"
	logRipeStatNoAbuse = "enricher: ripestat has no abuse mails for us, executing whoisEnrichment on IP address: %s"
	logEmailParseErr   = "enricher: whoisEnrichment - could not parse email address %d for %s"
)

// NewEnricher creates a new Enricher instance.
// It initializes the RipeStat client and optionally the IPInfo client if an API token is available.
func NewEnricher() *Enricher {
	ipInfoToken := os.Getenv("IPINFO_TOKEN")
	ripeClient := ripestat.NewRipeStatClient(RipeStatSourceApp)

	if ipInfoToken != "" {
		return &Enricher{
			ripeClient:   ripeClient,
			ipinfoClient: ipinfo.NewIpInfoClient(3, ipInfoToken),
		}
	}

	return &Enricher{
		ripeClient:   ripeClient,
		ipinfoClient: nil,
	}
}

// EnrichIP gathers enrichment information for the provided IP address.
// It collects abuse contact, network information, ASN holder, and geolocation data.
func (e *Enricher) EnrichIP(ipAddr string) types.EnrichInfo {
	enrichInfo := types.EnrichInfo{
		Ip: ipAddr,
	}

	enrichInfo.Abuse, enrichInfo.AbuseSource = e.enrichAbuseFromIP(ipAddr)
	enrichInfo.Prefix, enrichInfo.Asn = e.enrichPrefixAndASNFromIP(ipAddr)
	enrichInfo.Holder = e.enrichHolderFromASN(enrichInfo.Asn)
	enrichInfo.City, enrichInfo.Country = e.enrichCityAndCountryFromPrefix(enrichInfo.Prefix)

	return enrichInfo
}

// enrichAbuseFromIP attempts to find abuse contact information for an IP address.
// It first tries RipeStat, then falls back to Whois, and finally IPInfo if available.
func (e *Enricher) enrichAbuseFromIP(ipAddr string) (abuseEmails string, abuseSource string) {
	const defaultEmail = "unknown"
	const sourceRipeStat = "RipeSTAT"

	// Try RipeStat first
	rsEmailAddresses, err := e.ripeClient.GetAbuseContacts(ipAddr)
	if err != nil {
		logrus.Warnf("abuse rsEmailAddresses err: %v", err)
		return defaultEmail, sourceRipeStat
	}

	if len(rsEmailAddresses) == 1 {
		mailAddress, err := mail.ParseAddress(rsEmailAddresses[0])
		if err != nil {
			logrus.Warnf("abuse foundMailAddresses err: %v", err)
			return defaultEmail, sourceRipeStat
		}

		return sanitizeEmail(mailAddress.Address), sourceRipeStat
	}

	if len(rsEmailAddresses) > 1 {
		cleanMailAddresses := make([]string, 0, len(rsEmailAddresses))

		for _, mailAddress := range rsEmailAddresses {
			parsedAddr, err := mail.ParseAddress(mailAddress)
			if err != nil {
				logrus.Warnf("abuse foundMailAddresses err: %v", err)
				continue
			}
			cleanMailAddresses = append(cleanMailAddresses, sanitizeEmail(parsedAddr.Address))
		}

		return strings.Join(cleanMailAddresses, ";"), sourceRipeStat
	}

	// Fallback to whois if no abuse contact was found in RipeStat
	contactsFromWhois, err := e.whoisEnrichmentIP(ipAddr)
	if err != nil {
		logrus.Warnf("abuse contactsFromWhois err: %v", err)
		return defaultEmail, sourceRipeStat
	}

	if len(contactsFromWhois) > 0 {
		return strings.Join(contactsFromWhois, ";"), "whois"
	}

	// Fallback to ipinfo if no abuse contact was found in whois either
	if e.ipinfoClient != nil {
		abuseContact, err := e.ipinfoClient.GetAbuseContact(ipAddr)
		if err != nil {
			logrus.Debugf("abuse contactsFromIpinfo err: %v", err)
			return defaultEmail, sourceRipeStat
		}

		if abuseContact != "" {
			return sanitizeEmail(abuseContact), "ipinfo"
		}
	}

	return defaultEmail, sourceRipeStat
}

// enrichPrefixAndASNFromIP retrieves the network prefix and ASN for an IP address.
func (e *Enricher) enrichPrefixAndASNFromIP(ipAddr string) (string, string) {
	const unknown = "unknown"

	netInfo, err := e.ripeClient.GetNetworkInfo(ipAddr)
	if err != nil {
		// Try direct API call as fallback
		prefix, asn, directErr := e.ripeClient.NetworkInfo(ipAddr)
		if directErr != nil {
			logrus.Warnf("network info err (both methods): %v, %v", err, directErr)
			return unknown, unknown
		}
		return prefix, asn
	}

	if len(netInfo.ASNs) == 0 {
		return netInfo.Prefix, unknown
	}

	return netInfo.Prefix, fmt.Sprintf("%d", netInfo.ASNs[0].Int())
}

// enrichHolderFromASN retrieves the organization name for the given ASN.
func (e *Enricher) enrichHolderFromASN(asn string) string {
	const unknown = "unknown"

	if asn == unknown {
		return unknown
	}

	// First try direct method
	holder, err := e.ripeClient.ASNHolder(asn)
	if err == nil && holder != "" {
		return holder
	}

	// Convert string ASN to int for the structured method
	var asnInt int
	_, err = fmt.Sscanf(asn, "%d", &asnInt)
	if err != nil {
		logrus.Warnf("failed to parse ASN: %v", err)
		return unknown
	}

	asOverview, err := e.ripeClient.GetASOverview(asnInt)
	if err != nil {
		logrus.Warnf("holder err: %v", err)
		return unknown
	}

	return asOverview.Holder
}

// enrichCityAndCountryFromPrefix retrieves geolocation information for a network prefix.
func (e *Enricher) enrichCityAndCountryFromPrefix(prefix string) (string, string) {
	const unknown = "unknown"

	if prefix == unknown {
		return unknown, unknown
	}

	// Try with the prefix first
	geoData, err := e.ripeClient.GetGeolocationData(prefix)
	if err == nil {
		// Successfully got geolocation data
		city := geoData.City
		// Only convert empty city to "unknown", leave country as is
		if city == "" {
			city = unknown
		}
		return city, geoData.CountryCode
	}

	// If that fails, try with just first IP in the prefix
	// This handles cases where prefix is in the format "x.x.x.0/24"
	ipParts := strings.Split(prefix, "/")
	if len(ipParts) > 0 {
		baseIP := ipParts[0]
		geoData, err := e.ripeClient.GetGeolocationData(baseIP)
		if err == nil {
			city := geoData.City
			// Only convert empty city to "unknown", leave country as is
			if city == "" {
				city = unknown
			}
			return city, geoData.CountryCode
		}
	}

	logrus.Warnf("geolocation err for prefix %s: %v", prefix, err)
	return unknown, unknown
}

// whoisEnrichmentIP queries WHOIS for email addresses associated with an IP address.
func (e *Enricher) whoisEnrichmentIP(ipAddr string) ([]string, error) {
	logrus.Debugf(logRipeStatNoAbuse, ipAddr)

	whoisInfo, err := whois.Whois(ipAddr)
	if err != nil {
		logrus.Debugf(logWhoisNoInfo, ipAddr)
		return nil, err
	}

	if whoisInfo == "" {
		return nil, fmt.Errorf(errWhoisEmpty, ipAddr)
	}

	foundMailAddresses := whoisRegexp.FindAllString(whoisInfo, -1)

	switch len(foundMailAddresses) {
	case 0:
		return nil, fmt.Errorf(errNoAbuseEmails, ipAddr)
	case 1:
		// Spare some allocations and a sort if there's only one address found
		email, err := mail.ParseAddress(foundMailAddresses[0])
		if err != nil {
			return nil, fmt.Errorf(errInvalidEmail, ipAddr)
		}

		return []string{strings.ToLower(email.Address)}, nil
	}

	// Store unique, lowercase email addresses
	uniqueMailAddresses := make(map[string]struct{}, len(foundMailAddresses))
	for i, mailAddr := range foundMailAddresses {
		email, err := mail.ParseAddress(mailAddr)
		if err != nil {
			logrus.Debugf(logEmailParseErr, i, ipAddr)
			continue
		}

		uniqueMailAddresses[strings.ToLower(email.Address)] = struct{}{}
	}

	emails := make([]string, 0, len(uniqueMailAddresses))
	for email := range maps.Keys(uniqueMailAddresses) {
		emails = append(emails, email)
	}
	return emails, nil
}

// sanitizeEmail cleans up email addresses by removing unwanted characters
// while preserving the valid structure and characters allowed in email addresses.
func sanitizeEmail(email string) string {
	const (
		maxEmailLength = 254 // RFC 5321 limits (+
		emptyResult    = ""
	)

	// Check if email exceeds RFC length limit
	if len(email) > maxEmailLength {
		logrus.Warnf("enricher: sanitizeEmail - email exceeds RFC 5321 limit: %s (%d chars)",
			email, len(email))
		return emptyResult
	}

	// Basic cleanup
	email = strings.ToLower(
		strings.TrimSpace(email),
	)

	// Simple email validation pattern - just check format, not character restrictions
	basicEmailPattern := regexp.MustCompile(`^.+@.+\..+$`)
	if !basicEmailPattern.MatchString(email) {
		logrus.Warnf("enricher: sanitizeEmail - email lacks basic structure: %s", email)
		return emptyResult
	}

	// Allow a broader range of characters commonly found in abuse email addresses
	var validChars strings.Builder
	validChars.Grow(len(email)) // Pre-allocate capacity

	for _, c := range email {
		// Allow alphanumeric
		if isValidEmailChar(c) {
			validChars.WriteRune(c)
		}
	}

	filtered := validChars.String()

	// Final safety check - must have @ and . to be a valid email
	parts := strings.Split(filtered, "@")
	if len(parts) != 2 || !strings.Contains(parts[1], ".") {
		logrus.Warnf("enricher: sanitizeEmail - filtered result invalid: %s -> %s",
			email, filtered)
		return emptyResult
	}

	return filtered
}

// isValidEmailChar returns true if the character is valid in an email address.
func isValidEmailChar(c rune) bool {
	// Alphanumeric characters
	if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
		return true
	}

	// Common special chars in email local part
	switch c {
	case '@', '.', '-', '_', '%', '+', '&', '\'', '*', '=', '!', '#',
		'$', '/', '?', '^', '`', '{', '}', '|', '~':
		return true
	default:
		return false
	}
}
