package ripestat

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"time"
)

const (
	DATA_URL = "https://stat.ripe.net/data/"
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
	if c.MaxRetries < 0 {
		return nil, fmt.Errorf("invalid MaxRetries, expected positive integer")
	} else if c.MaxRetries == 0 {
		return c.sendRequest(endpoint, resource)
	}

	lastTimeout := 1000 * time.Millisecond
	for i := 0; i < c.MaxRetries; i++ {
		result, err := c.sendRequest(endpoint, resource)
		if err == nil {
			return result, err
		}
		fmt.Printf("got error %v, sleeping %v\n", err, lastTimeout)
		time.Sleep(lastTimeout)
		jitter := time.Duration(rand.Intn(1000)) * time.Millisecond
		lastTimeout += lastTimeout + jitter
	}

	return nil, fmt.Errorf("MaxRetries (%d) exceeded for endpoint %q and resource %q", c.MaxRetries, endpoint, resource)
}

func (c *Client) sendRequest(endpoint, resource string) ([]byte, error) {
	endpoint = url.QueryEscape(endpoint)
	resource = url.QueryEscape(resource)
	url := DATA_URL + endpoint + "/data.json?resource=" + resource + "&sourceapp=" + c.SourceApp

	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
