package ipinfo

/*
* https://www.DIVD.nl
* released under the Apache 2.0 license
* https://www.apache.org/licenses/LICENSE-2.0
 */

import (
	"errors"
	"github.com/ipinfo/go/v2/ipinfo"
	"github.com/sirupsen/logrus"
	"net"
)

type Client struct {
	*ipinfo.Client
	MaxRetries  int
	IpInfoToken string
}

func NewIpInfoClient(maxRetries int, ipInfoToken string) *Client {
	client := &Client{
		IpInfoToken: ipInfoToken,
		MaxRetries:  maxRetries, // @TODO: implement when we have use for the client
	}

	client.Client = ipinfo.NewClient(nil, nil, client.IpInfoToken)

	return client
}

// GetAbuseContact returns the abuse contacts emails for the given IP address
func (c *Client) GetAbuseContact(ipAddr string) (abuseContact string, err error) {

	for i := 0; i < c.MaxRetries; i++ {
		info, err := c.Client.GetIPInfo(net.ParseIP(ipAddr))
		if err == nil {
			logrus.Debugf("Found the following info: %+v", info)
			if info.Abuse != nil && info.Abuse.Email != "" {
				abuseContact = info.Abuse.Email
				break
			}
		}
		logrus.Warnf("[ipinfo] - Failed to get abuse contact for %s: %s", ipAddr, err)
	}

	return abuseContact, errors.New("ipinfo abuse email not found")
}
