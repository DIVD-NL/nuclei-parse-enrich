package ipinfo

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"errors"
	"math/rand"
	"net"
	"time"

	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/sirupsen/logrus"
)

// Error messages
const (
	errNoAbuseEmail = "ipinfo abuse email not found"
)

// Client wraps the IPInfo API client with additional functionality
type Client struct {
	*ipinfo.Client
	MaxRetries  int
	IpInfoToken string
}

// NewIpInfoClient creates a new IPInfo client with the specified token and retry settings
func NewIpInfoClient(maxRetries int, ipInfoToken string) *Client {
	client := &Client{
		IpInfoToken: ipInfoToken,
		MaxRetries:  maxRetries,
	}

	client.Client = ipinfo.NewClient(nil, nil, client.IpInfoToken)

	return client
}

// GetAbuseContact retrieves the abuse contact email for the given IP address
// It retries up to MaxRetries times with exponential backoff
func (c *Client) GetAbuseContact(ipAddr string) (string, error) {
	// Validate IP address
	parsedIP := net.ParseIP(ipAddr)
	if parsedIP == nil {
		return "", errors.New("invalid IP address format")
	}

	var lastErr error
	waitTime := 500 * time.Millisecond

	for i := 0; i < c.MaxRetries; i++ {
		if i > 0 {
			// Add jitter to prevent thundering herd
			jitter := time.Duration(rand.Intn(200)) * time.Millisecond
			time.Sleep(waitTime + jitter)
			waitTime *= 2 // Exponential backoff
		}

		info, err := c.Client.GetIPInfo(parsedIP)
		if err == nil {
			logrus.Debugf("[ipinfo] Found info for %s: %+v", ipAddr, info)
			if info.Abuse != nil && info.Abuse.Email != "" {
				return info.Abuse.Email, nil
			}
			lastErr = errors.New(errNoAbuseEmail)
		} else {
			logrus.Warnf("[ipinfo] Failed to get abuse contact for %s: %s", ipAddr, err)
			lastErr = err
		}
	}

	if c.MaxRetries > 0 {
		logrus.Warnf("[ipinfo] Failed to get abuse contact after %d retries", c.MaxRetries)
	}
	return "", lastErr
}
