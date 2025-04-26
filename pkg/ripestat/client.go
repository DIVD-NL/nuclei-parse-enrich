package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/time/rate"
)

// Client represents a RIPE Stat API client
type Client struct {
	// BaseURL is the base URL of the RIPE Stat API
	BaseURL string
	// HTTPClient is the HTTP client used for API requests
	HTTPClient *http.Client
	// SourceApp is the name of the application to identify to RIPE
	SourceApp string
	limiter   *rate.Limiter
}

// NewRipeStatClient creates a new RIPE Stat API client with the given source application name
// If sourceApp is empty, DefaultSourceApp will be used
func NewRipeStatClient(sourceApp string) *Client {
	if sourceApp == "" {
		sourceApp = DefaultSourceApp
	}

	return &Client{
		BaseURL:    DefaultBaseURL,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
		SourceApp:  sourceApp,
		limiter:    rate.NewLimiter(DefaultRateLimit, DefaultBurst),
	}
}

// GetAbuseContacts retrieves abuse contact information for the given IP address
func (c *Client) GetAbuseContacts(ip string) ([]string, error) {
	endpoint := "abuse-contact-finder"
	params := map[string]string{"resource": ip}

	var response AbuseContactResponse
	if err := c.send(endpoint, params, &response); err != nil {
		return nil, fmt.Errorf(ErrFailedGetAbuse, ip, err)
	}

	return response.Data.AbuseContacts, nil
}

// GetNetworkInfo retrieves network information for the given IP address
func (c *Client) GetNetworkInfo(ip string) (*NetworkInfo, error) {
	endpoint := "network-info"
	params := map[string]string{"resource": ip}

	var response struct {
		Status string `json:"status"`
		Data   struct {
			Prefix    string        `json:"prefix"`
			ASNs      []interface{} `json:"asns"`
			Holder    string        `json:"holder"`
			Announced bool          `json:"announced"`
		} `json:"data"`
	}

	if err := c.send(endpoint, params, &response); err != nil {
		return nil, fmt.Errorf(ErrFailedGetNetInfo, ip, err)
	}

	if response.Status != "ok" {
		return nil, fmt.Errorf(ErrNonOkStatus)
	}

	// If announced is false, just return the prefix info (not announced doesn't mean it's not valid data)
	// We won't check 'announced' flag anymore

	// Convert ASNs to our internal type
	asns := make([]ASN, 0, len(response.Data.ASNs))
	for _, rawASN := range response.Data.ASNs {
		// Try as string first
		if asnStr, ok := rawASN.(string); ok {
			asnVal, err := strconv.Atoi(strings.TrimPrefix(asnStr, "AS"))
			if err != nil {
				continue
			}
			asns = append(asns, ASN(asnVal))
		} else if asnNum, ok := rawASN.(float64); ok {
			// JSON numbers come as float64
			asns = append(asns, ASN(int(asnNum)))
		}
	}

	return &NetworkInfo{
		Prefix: response.Data.Prefix,
		ASNs:   asns,
		Holder: response.Data.Holder,
	}, nil
}

// GetASOverview retrieves AS overview information for the given AS number
func (c *Client) GetASOverview(asn int) (*ASOverview, error) {
	endpoint := "as-overview"
	params := map[string]string{"resource": fmt.Sprintf("AS%d", asn)}

	var response struct {
		Status string `json:"status"`
		Data   struct {
			Holder    string      `json:"holder"`
			Resource  string      `json:"resource"`
			ASNumber  interface{} `json:"asn"`
			Announced bool        `json:"announced"`
		} `json:"data"`
	}

	if err := c.send(endpoint, params, &response); err != nil {
		return nil, fmt.Errorf(ErrFailedGetASInfo, asn, err)
	}

	if response.Status != "ok" {
		return nil, fmt.Errorf(ErrNonOkStatus)
	}

	// We won't check announced flag anymore

	// Try to get ASN from different fields
	var asnValue ASN

	// First try ASNumber field if present
	if response.Data.ASNumber != nil {
		// Try as string first
		if asnStr, ok := response.Data.ASNumber.(string); ok {
			asnVal, err := strconv.Atoi(strings.TrimPrefix(asnStr, "AS"))
			if err == nil {
				asnValue = ASN(asnVal)
			}
		} else if asnNum, ok := response.Data.ASNumber.(float64); ok {
			// JSON numbers come as float64
			asnValue = ASN(int(asnNum))
		}
	}
	// If still not set, try to get from Resource field
	if asnValue == 0 && response.Data.Resource != "" {
		asnStr := strings.TrimPrefix(response.Data.Resource, "AS")
		asnVal, err := strconv.Atoi(asnStr)
		if err == nil {
			asnValue = ASN(asnVal)
		}
	}
	// If still not set, use the input ASN
	if asnValue == 0 {
		asnValue = ASN(asn)
	}

	return &ASOverview{
		Holder:   response.Data.Holder,
		ASNumber: asnValue,
	}, nil
}

// GetGeolocationData retrieves geolocation data for the given IP address
func (c *Client) GetGeolocationData(ip string) (*MaxmindGeoLite, error) {
	endpoint := "maxmind-geo-lite"
	params := map[string]string{"resource": ip}

	var response struct {
		Status string `json:"status"`
		Data   struct {
			LocatedResources []struct {
				Locations []struct {
					Country string `json:"country"`
					City    string `json:"city"`
				} `json:"locations"`
			} `json:"located_resources"`
		} `json:"data"`
	}

	if err := c.send(endpoint, params, &response); err != nil {
		return nil, fmt.Errorf(ErrFailedGeoData, ip, err)
	}

	if response.Status != "ok" {
		return nil, fmt.Errorf(ErrNonOkStatus)
	}

	if len(response.Data.LocatedResources) == 0 || len(response.Data.LocatedResources[0].Locations) == 0 {
		return nil, fmt.Errorf(ErrNoGeoData, ip)
	}

	location := response.Data.LocatedResources[0].Locations[0]

	// Return empty strings for missing values rather than nil
	// The enricher will convert empty strings to "unknown"
	city := location.City
	countryCode := location.Country

	return &MaxmindGeoLite{
		City:        city,
		CountryCode: countryCode,
	}, nil
}

// send makes a request to the RIPE Stat API with exponential backoff retry logic
func (c *Client) send(endpoint string, params map[string]string, response interface{}) error {
	var lastErr error

	for attempt := 0; attempt <= MaxRetries; attempt++ {
		// Calculate backoff duration
		backoffDuration := c.calculateBackoff(attempt)
		if attempt > 0 {
			time.Sleep(backoffDuration)
		}

		// Make the request
		respData, err := c.sendRequest(endpoint, params)
		if err == nil {
			// Parse the response
			return parseResponse(respData, response)
		}

		// Store the error and retry if this wasn't the last attempt
		lastErr = err

		// If the error is not retriable, don't retry
		if !isRetriableError(err) {
			return err
		}
	}

	return fmt.Errorf(ErrMaxRetriesExceeded2, lastErr)
}

// calculateBackoff calculates the backoff duration with jitter
func (c *Client) calculateBackoff(attempt int) time.Duration {
	if attempt == 0 {
		return 0
	}

	// Calculate base backoff (exponential)
	baseBackoff := float64(100*time.Millisecond) * math.Pow(2, float64(attempt))

	// Add jitter (±20%)
	jitter := (rand.Float64() * 0.4) - 0.2 // -0.2 to +0.2
	backoff := baseBackoff * (1 + jitter)

	// Cap at 10 seconds
	maxBackoff := float64(10 * time.Second)
	if backoff > maxBackoff {
		backoff = maxBackoff
	}

	return time.Duration(backoff)
}

// isRetriableError determines if an error is retriable
func isRetriableError(err error) bool {
	// Check for network errors, timeouts, and specific HTTP status codes
	if strings.Contains(err.Error(), "timeout") ||
		strings.Contains(err.Error(), "connection refused") ||
		strings.Contains(err.Error(), "status code 429") || // Too Many Requests
		strings.Contains(err.Error(), "status code 500") || // Internal Server Error
		strings.Contains(err.Error(), "status code 502") || // Bad Gateway
		strings.Contains(err.Error(), "status code 503") || // Service Unavailable
		strings.Contains(err.Error(), "status code 504") { // Gateway Timeout
		return true
	}
	return false
}

// sendRequest sends a request to the RIPE Stat API and returns the response body
func (c *Client) sendRequest(endpoint string, params map[string]string) ([]byte, error) {
	// Rate limit requests
	if err := c.limiter.Wait(context.TODO()); err != nil {
		return nil, fmt.Errorf(ErrRateLimit, err)
	}

	// Build the URL with properly encoded parameters
	urlValues := url.Values{}
	for k, v := range params {
		urlValues.Add(k, v)
	}
	urlValues.Add("sourceapp", c.SourceApp)

	requestURL := fmt.Sprintf("%s/%s/%s?%s", c.BaseURL, endpoint, "data.json", urlValues.Encode())

	// Create and send the request
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	if err != nil {
		return nil, fmt.Errorf(ErrCreateRequest, err)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf(ErrRequestFailed, err)
	}
	defer func() {
		// Drain and close the body to ensure connection reuse
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	// Check for HTTP errors
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf(ErrHTTPStatusCode, resp.StatusCode)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf(ErrReadResponse, err)
	}

	return body, nil
}

// parseResponse unmarshals raw JSON data into the specified response type
func parseResponse(data []byte, response interface{}) error {
	if err := json.Unmarshal(data, response); err != nil {
		return fmt.Errorf(ErrParseResponse, err)
	}

	// Check if the response came from cache (useful for logging or diagnostics)
	if resp, ok := response.(interface{ IsCached() bool }); ok && resp.IsCached() {
		// We could log cache hits here if needed
		// fmt.Printf("Response from cache: %v\n", resp)
	}

	return nil
}

// AbuseContactFinder is an interface for finding abuse contacts for IPs
// This interface is used for dependency injection and testing
type AbuseContactFinder interface {
	FindAbuseContact(ip string) ([]string, error)
}

// FindAbuseContact finds the abuse contact for an IP address
func (c *Client) FindAbuseContact(ip string) ([]string, error) {
	params := map[string]string{
		"resource": ip,
	}

	body, err := c.sendRequest("abuse-contact-finder", params)
	if err != nil {
		return nil, err
	}

	contacts, err := ConvertAbuseContactsData(body)
	if err != nil {
		// Fallback to manual parsing
		var response struct {
			Data struct {
				AbuseContacts []string `json:"abuse_contacts"`
			} `json:"data"`
			Status string `json:"status"`
		}

		if jsonErr := json.Unmarshal(body, &response); jsonErr != nil {
			return nil, jsonErr
		}

		if response.Status != "ok" {
			return nil, errors.New(ErrNonOkStatus)
		}

		// Return empty list if no contacts found (will be converted to "unknown" by enricher)
		if len(response.Data.AbuseContacts) == 0 {
			return []string{}, nil
		}

		return response.Data.AbuseContacts, nil
	}

	// Return empty list if no contacts found (will be converted to "unknown" by enricher)
	if len(contacts) == 0 {
		return []string{}, nil
	}

	return contacts, nil
}

// ASNHolder returns information about an ASN holder
func (c *Client) ASNHolder(asn string) (string, error) {
	params := map[string]string{
		"resource": asn,
	}

	body, err := c.sendRequest("as-overview", params)
	if err != nil {
		return "", err
	}

	asData, err := ConvertASOverviewData(body)
	if err != nil {
		// Fallback to manual parsing
		var response struct {
			Data struct {
				Holder string `json:"holder"`
			} `json:"data"`
			Status string `json:"status"`
		}

		if jsonErr := json.Unmarshal(body, &response); jsonErr != nil {
			return "", jsonErr
		}

		if response.Status != "ok" {
			return "", errors.New(ErrNonOkStatus)
		}

		// No need to convert empty to unknown here, the enricher will handle it
		return response.Data.Holder, nil
	}

	return asData.Holder, nil
}

// NetworkInfo returns network information for an IP
func (c *Client) NetworkInfo(ip string) (string, string, error) {
	params := map[string]string{
		"resource": ip,
	}

	body, err := c.sendRequest("network-info", params)
	if err != nil {
		return "", "", err
	}

	netInfo, err := ConvertNetworkInfoData(body)
	if err != nil {
		// Fallback to manual parsing
		var response struct {
			Data struct {
				Prefix string   `json:"prefix"`
				ASNs   []string `json:"asns"`
			} `json:"data"`
			Status string `json:"status"`
		}

		if jsonErr := json.Unmarshal(body, &response); jsonErr != nil {
			return "", "", jsonErr
		}

		if response.Status != "ok" {
			return "", "", errors.New(ErrNonOkStatus)
		}

		// Check if prefix is empty, use empty string which will be converted to "unknown" by enricher
		prefix := response.Data.Prefix

		// Check if there is at least one ASN
		if len(response.Data.ASNs) == 0 {
			return prefix, "", nil
		}

		return prefix, response.Data.ASNs[0], nil
	}

	// Check if prefix is empty, use empty string which will be converted to "unknown" by enricher
	prefix := netInfo.Prefix

	// Check if there is at least one ASN
	if len(netInfo.ASNs) == 0 {
		return prefix, "", nil
	}

	return prefix, fmt.Sprintf("%d", netInfo.ASNs[0].Int()), nil
}
