package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

const (
	// DefaultBaseURL is the default base URL for the RIPE Stat API
	DefaultBaseURL = "https://stat.ripe.net/data"
	// DefaultSourceApp is the name of this application to identify to RIPE
	DefaultSourceApp = "nuclei-parser-enricher"
	// MaxRetries is the maximum number of retry attempts for failed requests
	MaxRetries = 3
	// DefaultRateLimit defines the number of requests per second
	DefaultRateLimit = 10
	// DefaultBurst defines the maximum burst size for rate limiting
	DefaultBurst = 1

	// Error messages
	ErrInvalidRetries     = "invalid MaxRetries, expected positive integer"
	ErrMaxRetriesExceeded = "MaxRetries (%d) exceeded for endpoint %q and resource %q"
	ErrHTTPRequest        = "error making http get request to: %s: %v"
	ErrReadResponse       = "error reading response body: %v"

	// New error constants
	ErrFailedGetAbuse      = "failed to get abuse contacts for %s: %w"
	ErrFailedGetNetInfo    = "failed to get network info for %s: %w"
	ErrIPNotAnnounced      = "IP %s is not announced"
	ErrFailedGetASInfo     = "failed to get AS overview for AS%d: %w"
	ErrASNotAnnounced      = "AS%d is not announced"
	ErrFailedGeoData       = "failed to get geolocation data for %s: %w"
	ErrNoGeoData           = "no geolocation data found for %s"
	ErrMaxRetriesExceeded2 = "maximum retries exceeded: %w"
	ErrRateLimit           = "rate limit error: %w"
	ErrCreateRequest       = "failed to create request: %w"
	ErrRequestFailed       = "request failed: %w"
	ErrHTTPStatusCode      = "HTTP request failed with status code %d"
	ErrParseResponse       = "failed to parse API response: %w"
	ErrNonOkStatus         = "received non-ok status from RIPE Stat API"
)
