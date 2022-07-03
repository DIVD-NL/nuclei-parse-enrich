package ripestat

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

const (
	DataUrl = "https://stat.ripe.net/data/"
)

type Client struct {
	SourceApp  string
	MaxRetries int
}

func NewRipeStatClient(sourceApp string, maxRetries int) *Client {
	return &Client{
		SourceApp:  sourceApp,
		MaxRetries: maxRetries,
	}
}

func (c *Client) GetAbuseContacts(ipAddr string) ([]string, error) {
	data, err := c.send("abuse-contact-finder", ipAddr)
	if err != nil {
		return nil, err
	}
	return ConvertAbuseContactsData(data)
}

func (c *Client) GetNetworkInfo(ipAddr string) (NetworkInfo, error) {
	data, err := c.send("network-info", ipAddr)
	if err != nil {
		return NetworkInfo{}, err
	}
	return ConvertNetworkInfoData(data)
}

func (c *Client) GetASOverview(asn string) (ASOverview, error) {
	data, err := c.send("as-overview", asn)
	if err != nil {
		return ASOverview{}, err
	}
	return ConvertASOverviewData(data)
}

func (c *Client) GetGeolocationData(prefix string) (MaxmindGeoLite, error) {
	data, err := c.send("maxmind-geo-lite", prefix)
	if err != nil {
		return MaxmindGeoLite{}, err
	}
	return ConvertGeolocationData(data)
}

func (c *Client) send(endpoint, resource string) ([]byte, error) {

	if c.MaxRetries == 0 {
		return c.sendRequest(endpoint, resource)
	}

	if c.MaxRetries < 0 {
		return nil, fmt.Errorf("invalid MaxRetries, expected positive integer")
	}

	lastTimeout := 1000 * time.Millisecond

	for retries := 0; retries < c.MaxRetries; retries++ {
		result, err := c.sendRequest(endpoint, resource)
		if err == nil {
			return result, err
		}
		logrus.Debugf("got error %v, sleeping %v", err, lastTimeout)
		time.Sleep(lastTimeout)
		jitter := time.Duration(rand.Intn(2000)) * time.Millisecond
		lastTimeout += lastTimeout + jitter
	}

	return nil, fmt.Errorf("MaxRetries (%d) exceeded for endpoint %q and resource %q", c.MaxRetries, endpoint, resource)
}

func (c *Client) sendRequest(endpoint, resource string) ([]byte, error) {
	endpoint = url.QueryEscape(endpoint)
	resource = url.QueryEscape(resource)

	var requestUriRipeSTAT = fmt.Sprintf("%s%s/data.json?resource=%s&sourceapp=%s", DataUrl, endpoint, resource, c.SourceApp)

	resp, err := http.Get(requestUriRipeSTAT)

	if err != nil {
		return nil, fmt.Errorf("error making http get request to: %s: %v", requestUriRipeSTAT, err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logrus.Debugf("error closing body: %v", err)
		}
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}

	return body, nil
}
