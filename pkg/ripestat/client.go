package ripestat

import (
	"io"
	"net/http"
	"net/url"
)

const (
	DATA_URL = "https://stat.ripe.net/data/"
)

type Client struct {
	SourceApp string
}

func NewRipeStatClient(sourceApp string) *Client {
	return &Client{
		SourceApp: sourceApp,
	}
}

func (c *Client) GetAbuseContacts(ipAddr string) ([]string, error) {
	data, err := c.sendRequest("abuse-contact-finder", ipAddr)
	if err != nil {
		return nil, err
	}
	return ConvertAbuseContactsData(data)
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